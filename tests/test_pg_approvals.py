"""Postgres approval store (#169, #174): shared, persistent, once-only.

Needs TEST_SESSION_DB_URL; skipped otherwise. The whole approval flow also runs
on this store when the suite is run with TEST_SESSION_BACKEND=postgres.
"""

import json
import threading

import psycopg
import pytest

from router.approvals import ApprovalError, calls_hash
from router.pg_approvals import PostgresApprovalStore
from router.pg_session import APPROVALS_TABLE as TABLE
from router.session import SessionStoreUnavailable

SECRET_ARGUMENT = "remit-4410-2291-07@evil.example"


def _calls(to=SECRET_ARGUMENT):
    return [
        {
            "id": "call-1",
            "type": "function",
            "function": {"name": "send_email", "arguments": json.dumps({"to": to, "body": "paid"})},
        }
    ]


@pytest.fixture()
def replica(pg_store_factory, clock):
    """Build approval stores that share one database, like proxy replicas."""

    def make(ttl=900, secret=None):
        sessions = pg_store_factory()
        return PostgresApprovalStore(
            sessions.database, secret or sessions.secret, ttl=ttl, clock=clock
        )

    return make


def _create(store, **kw):
    values = {
        "session_key": "session-a",
        "session_ref": "ref-a",
        "owner": "key-a",
        "agent": "demo-assistant",
        "calls": _calls(),
        "content": "Sending the confirmation.",
        "summary": {"tools": ["send_email"], "unlisted_destinations": ["@evil.example"]},
    }
    values.update(kw)
    return store.create(**values)


def _sql(pg_url, statement, params=()):
    with psycopg.connect(pg_url) as conn:
        cursor = conn.execute(statement, params)
        return cursor.fetchall() if cursor.description else None


def _claim(store, raw, session_key="session-a", owner="key-a"):
    return store.claim(raw, session_key=session_key, owner=owner)


# -- shared and persistent ------------------------------------------------------


def test_a_decision_on_one_replica_is_used_on_another_after_a_restart(replica):
    first = replica()
    raw, record = _create(first)
    assert _claim(first, raw).status == "pending"

    admin = replica()  # the approver's request lands on another replica
    listed = admin.pending()
    assert [a.ref for a in listed] == [record.ref]
    assert listed[0].public(with_arguments=True)["tool_calls"][0]["name"] == "send_email"
    assert admin.decide(record.ref, approve=True, approver="admin").status == "approved"

    retry = replica()  # and the agent's retry on a third, after the first restarted
    claim = _claim(retry, raw)
    assert claim.ok and claim.calls == _calls() and claim.content == "Sending the confirmation."
    assert retry.verify_replay(claim.ref, claim.calls) is True
    assert _claim(first, raw).status == "used"
    assert first.verify_replay(claim.ref, claim.calls) is False  # checked once


def test_concurrent_retries_on_many_replicas_replay_once(replica):
    stores = [replica() for _ in range(6)]
    raw, record = _create(stores[0])
    stores[1].decide(record.ref, approve=True, approver="admin")
    results, errors = [], []
    start = threading.Barrier(len(stores))

    def retry(store):
        try:
            start.wait()
            results.append(_claim(store, raw))
        except Exception as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=retry, args=(store,)) for store in stores]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert sorted(c.status for c in results) == ["used"] * 6
    assert sum(c.ok for c in results) == 1  # one replay; the rest were told "used"


def test_two_admins_cannot_both_decide(replica):
    one, two = replica(), replica()
    _, record = _create(one)
    one.decide(record.ref, approve=False, approver="admin-1")
    with pytest.raises(ApprovalError) as exc:
        two.decide(record.ref, approve=True, approver="admin-2")
    assert exc.value.status == 409 and "denied" in str(exc.value)


def test_binding_to_session_and_key_holds_across_replicas(replica):
    one, two = replica(), replica()
    raw, record = _create(one)
    one.decide(record.ref, approve=True, approver="admin")
    assert _claim(two, raw, session_key="session-b").status == "mismatch"
    assert _claim(two, raw, owner="key-b").status == "mismatch"
    assert _claim(two, "not-an-id").status == "unknown"
    assert _claim(two, raw).ok  # the mismatches did not use it up


def test_an_expiry_is_reported_once_across_replicas(replica, clock):
    one, two = replica(ttl=60), replica(ttl=60)
    raw, record = _create(one)
    one.decide(record.ref, approve=True, approver="admin")
    clock.advance(61)
    assert _claim(two, raw).status == "expired"  # before any sweep has run
    assert one.pending() == []
    reported = [a.ref for a in one.sweep()] + [a.ref for a in two.sweep()]
    assert reported == [record.ref]
    with pytest.raises(ApprovalError) as exc:
        two.decide(record.ref, approve=True, approver="admin")
    assert exc.value.status == 409


def test_the_per_request_expiry_check_asks_the_database_at_most_once_per_window(replica, clock):
    store = replica(ttl=60)
    raw, record = _create(store)
    store.decide(record.ref, approve=True, approver="admin")
    assert store.due_expiries() == []  # the first check of this process sweeps

    class _Counting:
        def __init__(self, database):
            self.database, self.calls = database, 0

        def run(self, work, **kw):
            self.calls += 1
            return self.database.run(work, **kw)

    store._db = counting = _Counting(store._db)
    for _ in range(50):  # fifty requests inside the window
        assert store.due_expiries() == []
    assert counting.calls == 0

    clock.advance(61)  # overdue, and still inside nobody's sweep
    assert _claim(store, raw).status == "expired"  # expiry never waits for the sweep
    assert [a.ref for a in store.due_expiries()] == [record.ref]
    assert store.due_expiries() == []


def test_unknown_and_malformed_refs_are_not_found(replica):
    store = replica()
    _create(store)
    for ref in ("0" * 16, "%" * 16, "short", "g" * 16, None):
        with pytest.raises(ApprovalError) as exc:
            store.decide(ref, approve=True, approver="admin")
        assert exc.value.status == 404


# -- what the database holds -------------------------------------------------------


def test_arguments_are_unreadable_in_the_database_and_then_deleted(replica, pg_url):
    store = replica()
    raw, record = _create(store)
    dump = str(_sql(pg_url, f"SELECT * FROM {TABLE}"))
    assert raw not in dump
    assert SECRET_ARGUMENT not in dump and "paid" not in dump
    assert "Sending the confirmation" not in dump
    assert "send_email" in dump  # the summary an approver sees is stored in the clear

    def payload():
        return _sql(pg_url, f"SELECT payload FROM {TABLE}")[0][0]

    assert payload() is not None
    store.decide(record.ref, approve=True, approver="admin")
    claim = _claim(store, raw)
    assert payload() is not None  # kept only until the replay has been compared
    store.verify_replay(claim.ref, claim.calls)
    assert payload() is None


@pytest.mark.parametrize("ending", ["deny", "expire"])
def test_arguments_are_deleted_when_an_approval_ends_unused(replica, pg_url, clock, ending):
    store = replica(ttl=60)
    _, record = _create(store)
    if ending == "deny":
        store.decide(record.ref, approve=False, approver="admin")
    else:
        clock.advance(61)
        store.sweep()
    assert _sql(pg_url, f"SELECT payload, status FROM {TABLE}") == [
        (None, "denied" if ending == "deny" else "expired")
    ]


# -- integrity ------------------------------------------------------------------------


def test_a_row_flipped_to_approved_in_the_database_replays_nothing(replica, pg_url):
    store = replica()
    raw, record = _create(store)
    _sql(pg_url, f"UPDATE {TABLE} SET status = 'approved', decided_by = 'admin'")
    claim = _claim(store, raw)
    assert (claim.ok, claim.status, claim.calls) == (False, "tampered", [])
    assert store.pending() == []  # and an approver is not shown it


@pytest.mark.parametrize(
    "tamper",
    [
        'summary = \'{"tools": ["read_file"]}\'::jsonb',
        "expires_at = expires_at + 100000",
        "owner = 'key-b'",
        "agent = 'someone-else'",
        "mac = ''",
    ],
)
def test_a_changed_pending_row_cannot_be_approved(replica, pg_url, tamper):
    store = replica()
    _, record = _create(store)
    _sql(pg_url, f"UPDATE {TABLE} SET {tamper}")
    assert store.pending() == []
    with pytest.raises(ApprovalError, match="integrity check"):
        store.decide(record.ref, approve=True, approver="admin")


def test_swapped_or_altered_arguments_are_not_replayed(replica, pg_url):
    store = replica()
    raw, record = _create(store)
    _, other = _create(store, calls=_calls("attacker@evil.example"))
    store.decide(record.ref, approve=True, approver="admin")
    # Put the other approval's (validly encrypted) arguments under the approved one.
    _sql(
        pg_url,
        f"UPDATE {TABLE} SET payload = (SELECT payload FROM {TABLE} WHERE approval_key LIKE %s) "
        "WHERE approval_key LIKE %s",
        (other.ref + "%", record.ref + "%"),
    )
    claim = _claim(store, raw)
    assert (claim.ok, claim.status) == (False, "tampered")


def test_a_replica_with_another_secret_trusts_nothing(replica):
    store = replica()
    raw, record = _create(store)
    store.decide(record.ref, approve=True, approver="admin")
    stranger = replica(secret=b"x" * 40)
    assert _claim(stranger, raw).status == "tampered"
    assert stranger.pending() == []


def test_a_wrong_replay_is_refused_and_the_arguments_dropped(replica, pg_url):
    store = replica()
    raw, record = _create(store)
    store.decide(record.ref, approve=True, approver="admin")
    claim = _claim(store, raw)
    assert calls_hash(claim.calls) == record.calls_hash
    assert store.verify_replay(claim.ref, _calls("other@evil.example")) is False
    assert _sql(pg_url, f"SELECT payload FROM {TABLE}") == [(None,)]


# -- failing closed ----------------------------------------------------------------------


def test_an_unreachable_database_fails_closed(clock):
    from router.pg_session import PostgresSessionStore
    from tests.conftest import TEST_SESSION_HMAC_KEY

    sessions = PostgresSessionStore(
        "postgresql://nobody:x@127.0.0.1:1/none",
        TEST_SESSION_HMAC_KEY,
        idle_ttl=1800,
        tombstone_ttl=86400,
        timeout_ms=1000,
    )
    store = PostgresApprovalStore(sessions.database, sessions.secret, clock=clock)
    for call in (
        lambda: _create(store),
        lambda: _claim(store, "id"),
        lambda: store.decide("0" * 16, approve=True, approver="admin"),
        lambda: store.verify_replay("0" * 16, _calls()),
        store.pending,
        store.sweep,
    ):
        with pytest.raises(SessionStoreUnavailable):
            call()
