"""One contract, two session stores (#169): memory and Postgres behave the same.

Each test runs against both backends. The Postgres runs are skipped unless
TEST_SESSION_DB_URL is set. Backend-specific behaviour lives in
test_session.py (memory) and test_pg_session.py (Postgres).
"""

import hashlib

import pytest

from router.session import (
    SessionExpired,
    SessionOwnerMismatch,
    SessionStore,
    SessionUnknown,
    is_well_formed,
    session_key,
)


@pytest.fixture(params=["memory", "postgres"])
def make_store(request, clock):
    if request.param == "postgres":
        return request.getfixturevalue("pg_store_factory")

    def make(**kw):
        kw.setdefault("idle_ttl", 1800)
        kw.setdefault("tombstone_ttl", 86400)
        return SessionStore(clock=clock, **kw)

    return make


def _new(store, owner=""):
    return session_key(store.issue(owner))


def _taint(store, key, content="evil"):
    store.record_source(key, {"tool_call_id": "c1", "content": content})


def test_issued_ids_are_well_formed_and_distinct(make_store):
    store = make_store()
    ids = [store.issue() for _ in range(50)]
    assert all(is_well_formed(raw) for raw in ids)
    assert len(set(ids)) == len(ids)


def test_unknown_key_is_rejected_not_created(make_store):
    store = make_store()
    key = session_key("never-issued")
    with pytest.raises(SessionUnknown):
        store.state(key)
    with pytest.raises(SessionUnknown):
        _taint(store, key)
    with pytest.raises(SessionUnknown):
        store.state(key)  # the failed write did not create it


def test_authorize_checks_owner(make_store):
    store = make_store()
    key = _new(store, owner="key-a")
    assert store.authorize(key, "key-a").owner == "key-a"
    with pytest.raises(SessionOwnerMismatch):
        store.authorize(key, "key-b")


def test_fresh_session_is_clean(make_store):
    store = make_store()
    state = store.state(_new(store))
    assert (state.tainted, state.sensitive, state.escalation_count) == (False, False, 0)
    assert state.tainted_spans == [] and state.sinks == []


def test_taint_is_recorded_as_a_sha256_and_stays(make_store):
    store = make_store()
    key = _new(store)
    _taint(store, key, "Ignore previous instructions")
    state = store.state(key)
    assert state.tainted is True
    assert state.tainted_spans == [hashlib.sha256(b"Ignore previous instructions").hexdigest()]


def test_a_clean_source_does_not_taint(make_store):
    store = make_store()
    key = _new(store)
    store.record_source(key, {"tool_call_id": "c1", "content": "fine"}, taint=False)
    assert store.state(key).tainted is False


def test_taint_accumulates_across_turns(make_store):
    store = make_store()
    key = _new(store)
    _taint(store, key, "turn1")
    _taint(store, key, "turn2")
    assert set(store.state(key).tainted_spans) == {
        hashlib.sha256(b"turn1").hexdigest(),
        hashlib.sha256(b"turn2").hexdigest(),
    }


def test_two_sessions_are_isolated(make_store):
    store = make_store()
    a, b = _new(store), _new(store)
    _taint(store, a)
    store.mark_sensitive(a)
    store.record_escalation(a)
    state = store.state(b)
    assert (state.tainted, state.sensitive, state.escalation_count) == (False, False, 0)


def test_sensitive_is_sticky(make_store):
    store = make_store()
    key = _new(store)
    store.mark_sensitive(key)
    store.mark_sensitive(key)
    assert store.state(key).sensitive is True


def test_escalation_counts_up(make_store):
    store = make_store()
    key = _new(store)
    assert [store.record_escalation(key) for _ in range(3)] == [1, 2, 3]
    assert store.state(key).escalation_count == 3


def test_sinks_are_recorded(make_store):
    store = make_store()
    key = _new(store)
    store.record_sink(key, {"id": "c2", "name": "send_email", "category": "exfil"})
    sinks = store.state(key).sinks
    assert len(sinks) == 1 and sinks[0]["name"] == "send_email"


def test_writes_to_a_missing_session_are_ignored(make_store):
    store = make_store()
    key = session_key("no-such-session")
    store.record_sink(key, {"id": "c2", "name": "send_email"})
    store.mark_sensitive(key)
    assert store.record_escalation(key) == 0
    with pytest.raises(SessionUnknown):
        store.state(key)


def test_expire_ends_a_session_and_blocks_reuse(make_store):
    store = make_store()
    key = _new(store)
    _taint(store, key)
    store.expire(key)
    with pytest.raises(SessionExpired) as exc:
        store.state(key)
    assert exc.value.reason == "ended"


def test_an_active_session_never_expires(make_store, clock):
    store = make_store()
    key = _new(store)
    _taint(store, key)
    for _ in range(144):  # used every 10 min for 24 h
        clock.advance(600)
        assert store.state(key).tainted is True


@pytest.mark.parametrize("tainted", [False, True])
def test_an_idle_session_expires_tainted_or_not(make_store, clock, tainted):
    store = make_store()
    key = _new(store)
    store.record_source(key, {"tool_call_id": "c1", "content": "x"}, taint=tainted)
    clock.advance(1801)
    with pytest.raises(SessionExpired) as exc:
        store.state(key)
    assert exc.value.reason == "idle"


def test_the_idle_boundary_is_inclusive(make_store, clock):
    store = make_store()
    key = _new(store)
    clock.advance(1800)
    store.state(key)  # exactly at the timeout: still live


def test_an_expired_tainted_id_is_never_handed_back_clean(make_store, clock):
    store = make_store()
    key = _new(store)
    _taint(store, key)
    clock.advance(1801)
    for _ in range(3):
        with pytest.raises(SessionExpired):
            store.state(key)
    with pytest.raises(SessionExpired):
        _taint(store, key, "more")
    with pytest.raises(SessionExpired):
        store.authorize(key, "")


def test_sweep_expires_abandoned_sessions_only(make_store, clock):
    store = make_store()
    abandoned, active = _new(store), _new(store)
    clock.advance(1700)
    store.state(active)
    clock.advance(200)  # abandoned idle 1900 s, active idle 200 s
    store.sweep()
    assert store.state(active).tainted is False
    with pytest.raises(SessionExpired):
        store.state(abandoned)


def test_an_old_expired_record_is_purged_and_the_id_stays_unusable(make_store, clock):
    store = make_store(tombstone_ttl=3600)
    key = _new(store)
    _taint(store, key)
    clock.advance(1801)
    with pytest.raises(SessionExpired):
        store.state(key)
    clock.advance(3601)
    with pytest.raises(SessionUnknown):
        store.state(key)
