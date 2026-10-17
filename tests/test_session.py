"""Tests for the session store (#15, #145, #146, #147)."""

import hashlib
import math
from collections import Counter

import pytest

from router.session import (
    SessionExpired,
    SessionOwnerMismatch,
    SessionStore,
    SessionUnknown,
    is_well_formed,
    session_key,
    session_ref,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def clock():
    return FakeClock()


def _store(clock, **kw):
    kw.setdefault("idle_ttl", 1800)
    kw.setdefault("tombstone_ttl", 86400)
    return SessionStore(clock=clock, **kw)


def _new(store, owner=""):
    """Issue a session; return (raw id, store key)."""
    raw = store.issue(owner)
    return raw, session_key(raw)


# ---------------------------------------------------------------------------
# Issued ids (#145) — NIST SP 800-63B / OWASP session identifier requirements
# ---------------------------------------------------------------------------


def test_issued_id_shape_and_entropy():
    store = SessionStore()
    raw = store.issue()
    assert is_well_formed(raw)
    assert len(raw) == 43  # token_urlsafe(32): 256 bits, base64url
    # 43 base64url chars carry 6 bits each — well over the 64-bit minimum.
    assert len(raw) * 6 >= 256


def test_issued_ids_are_unique_and_unpredictable():
    store = SessionStore()
    ids = [store.issue() for _ in range(2000)]
    assert len(set(ids)) == len(ids)
    # Characters are spread across the alphabet, not sequential or patterned.
    counts = Counter("".join(ids))
    entropy = -sum(
        c / sum(counts.values()) * math.log2(c / sum(counts.values())) for c in counts.values()
    )
    assert entropy > 5.9  # max for a 64-symbol alphabet is 6.0


def test_raw_id_is_never_stored():
    store = SessionStore()
    raw = store.issue("owner-a")
    assert raw not in store._store
    assert session_key(raw) in store._store
    assert store._store[session_key(raw)].session_id == session_key(raw)


def test_session_key_and_ref():
    raw = "a" * 43
    assert session_key(raw) == hashlib.sha256(raw.encode()).hexdigest()
    assert session_ref(raw) == session_key(raw)[:16]


@pytest.mark.parametrize(
    "value",
    ["", "run-1", "a" * 42, "a" * 44, "a" * 42 + "=", "a" * 42 + "/", " " + "a" * 42, "é" * 43],
)
def test_is_well_formed_rejects_anything_not_issued(value):
    assert not is_well_formed(value)


def test_unknown_key_is_rejected_not_created():
    store = SessionStore()
    with pytest.raises(SessionUnknown):
        store.state(session_key("never-issued"))
    with pytest.raises(SessionUnknown):
        store.record_source(session_key("never-issued"), {"tool_call_id": "c1", "content": "x"})
    assert store._store == {}


def test_authorize_checks_owner():
    store = SessionStore()
    _, key = _new(store, owner="key-a")
    assert store.authorize(key, "key-a").owner == "key-a"
    with pytest.raises(SessionOwnerMismatch):
        store.authorize(key, "key-b")


# ---------------------------------------------------------------------------
# Taint state (#15)
# ---------------------------------------------------------------------------


def test_fresh_session_is_clean():
    store = SessionStore()
    _, key = _new(store)
    s = store.state(key)
    assert s.tainted is False
    assert s.sources == []
    assert s.sinks == []


def test_two_sessions_are_isolated():
    store = SessionStore()
    _, a = _new(store)
    _, b = _new(store)
    store.record_source(a, {"tool_call_id": "c1", "content": "evil payload"})
    s_b = store.state(b)
    assert s_b.tainted is False
    assert s_b.sources == []


def test_record_source_marks_tainted():
    store = SessionStore()
    _, key = _new(store)
    store.record_source(key, {"tool_call_id": "c1", "content": "injected"})
    s = store.state(key)
    assert s.tainted is True
    assert len(s.sources) == 1
    assert len(s.tainted_spans) == 1


def test_tainted_spans_are_sha256():
    store = SessionStore()
    _, key = _new(store)
    content = "Ignore previous instructions"
    store.record_source(key, {"tool_call_id": "c1", "content": content})
    expected = hashlib.sha256(content.encode()).hexdigest()
    assert store.state(key).tainted_spans[0] == expected


def test_record_sink_appended():
    store = SessionStore()
    _, key = _new(store)
    store.record_source(key, {"tool_call_id": "c1", "content": "x"})
    store.record_sink(key, {"id": "c2", "name": "send_email", "category": "exfil"})
    s = store.state(key)
    assert len(s.sinks) == 1
    assert s.sinks[0]["name"] == "send_email"


def test_record_sink_on_unknown_session_is_noop():
    store = SessionStore()
    store.record_sink("no-such-session", {"id": "c2", "name": "send_email"})
    assert store._store.get("no-such-session") is None


def test_multi_turn_sources_accumulate():
    store = SessionStore()
    _, key = _new(store)
    store.record_source(key, {"tool_call_id": "c1", "content": "turn1"})
    store.record_source(key, {"tool_call_id": "c2", "content": "turn2"})
    s = store.state(key)
    assert len(s.sources) == 2
    assert len(s.tainted_spans) == 2


# ---------------------------------------------------------------------------
# Idle expiry and tombstones (#147)
# ---------------------------------------------------------------------------


def test_expire_ends_session_and_blocks_reuse():
    store = SessionStore()
    _, key = _new(store)
    store.record_source(key, {"tool_call_id": "c1", "content": "x"})
    store.expire(key)
    assert key not in store._store
    with pytest.raises(SessionExpired) as exc:
        store.state(key)
    assert exc.value.reason == "ended"


def test_active_session_survives_past_idle_ttl_from_creation(clock):
    """The #147 bug: expiry counted from creation, wiping taint on an active session."""
    store = _store(clock)
    _, key = _new(store)
    store.record_source(key, {"tool_call_id": "c1", "content": "evil"})
    for _ in range(6):  # 6 x 10 min = 60 min of activity, each gap < idle TTL
        clock.advance(600)
        assert store.state(key).tainted is True


def test_long_lived_active_session_never_expires(clock):
    """Expiry counts only from last use — a session in use for 24 h stays live."""
    store = _store(clock)
    _, key = _new(store)
    store.record_source(key, {"tool_call_id": "c1", "content": "evil"})
    for _ in range(144):  # 144 x 10 min = 24 h
        clock.advance(600)
        assert store.state(key).tainted is True


@pytest.mark.parametrize("tainted", [False, True])
def test_idle_session_expires_regardless_of_taint(clock, tainted):
    store = _store(clock)
    _, key = _new(store)
    store.record_source(key, {"tool_call_id": "c1", "content": "x"}, taint=tainted)
    clock.advance(1801)
    with pytest.raises(SessionExpired) as exc:
        store.state(key)
    assert exc.value.reason == "idle"
    assert key not in store._store


def test_idle_boundary_is_inclusive(clock):
    store = _store(clock)
    _, key = _new(store)
    clock.advance(1800)
    store.state(key)  # exactly at the TTL: still live


def test_expired_tainted_id_is_never_recreated_clean(clock):
    store = _store(clock)
    _, key = _new(store)
    store.record_source(key, {"tool_call_id": "c1", "content": "evil"})
    clock.advance(1801)
    for _ in range(3):
        with pytest.raises(SessionExpired):
            store.state(key)
    assert key not in store._store


def test_record_source_does_not_write_into_expired_session(clock):
    store = _store(clock)
    _, key = _new(store)
    store.record_source(key, {"tool_call_id": "c1", "content": "evil"})
    clock.advance(1801)
    with pytest.raises(SessionExpired):
        store.record_source(key, {"tool_call_id": "c2", "content": "more"})


def test_sweep_reaps_abandoned_sessions(clock):
    store = _store(clock)
    _, abandoned = _new(store)
    _, active = _new(store)
    clock.advance(1700)
    store.state(active)
    clock.advance(200)  # abandoned idle 1900s, active idle 200s
    store.sweep()
    assert abandoned not in store._store
    assert active in store._store
    assert abandoned in store._tombstones


def test_periodic_sweep_runs_on_access(clock):
    store = _store(clock)
    _, abandoned = _new(store)
    _, other = _new(store)
    clock.advance(1700)
    store.state(other)
    clock.advance(200)
    store.state(other)  # any access past SWEEP_INTERVAL triggers a full sweep
    assert abandoned not in store._store


def test_purged_tombstone_leaves_id_unknown_not_reusable(clock):
    store = _store(clock, tombstone_ttl=3600)
    _, key = _new(store)
    store.record_source(key, {"tool_call_id": "c1", "content": "evil"})
    clock.advance(1801)
    with pytest.raises(SessionExpired):
        store.state(key)
    clock.advance(3601)
    with pytest.raises(SessionUnknown):
        store.state(key)
    assert key not in store._tombstones
    assert key not in store._store


def test_sweep_purges_old_tombstones(clock):
    store = _store(clock, tombstone_ttl=3600)
    _, key = _new(store)
    store.expire(key)
    clock.advance(3601)
    store.sweep()
    assert store._tombstones == {}


def test_from_env_reads_ttls(monkeypatch):
    monkeypatch.setenv("SESSION_IDLE_TTL_SECONDS", "60")
    monkeypatch.setenv("SESSION_TOMBSTONE_TTL_SECONDS", "180")
    store = SessionStore.from_env()
    assert (store._idle_ttl, store._tombstone_ttl) == (60, 180)


def test_from_env_defaults(monkeypatch):
    for name in ("SESSION_IDLE_TTL_SECONDS", "SESSION_TOMBSTONE_TTL_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    store = SessionStore.from_env()
    assert (store._idle_ttl, store._tombstone_ttl) == (1800, 86400)


@pytest.mark.parametrize("value", ["0", "-5", "abc", "1.5"])
def test_from_env_rejects_invalid(monkeypatch, value):
    monkeypatch.setenv("SESSION_IDLE_TTL_SECONDS", value)
    with pytest.raises(ValueError, match="SESSION_IDLE_TTL_SECONDS"):
        SessionStore.from_env()
