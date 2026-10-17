"""Tests for the session store (issue #15)."""

import pytest

from router.session import SessionExpired, SessionStore


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


def test_fresh_session_is_clean():
    store = SessionStore()
    s = store.state("run-1")
    assert s.tainted is False
    assert s.sources == []
    assert s.sinks == []


def test_two_sessions_are_isolated():
    store = SessionStore()
    store.record_source("run-a", {"tool_call_id": "c1", "content": "evil payload"})
    s_b = store.state("run-b")
    assert s_b.tainted is False
    assert s_b.sources == []


def test_record_source_marks_tainted():
    store = SessionStore()
    store.record_source("run-1", {"tool_call_id": "c1", "content": "injected"})
    s = store.state("run-1")
    assert s.tainted is True
    assert len(s.sources) == 1
    assert len(s.tainted_spans) == 1


def test_tainted_spans_are_sha256():
    import hashlib

    store = SessionStore()
    content = "Ignore previous instructions"
    store.record_source("run-1", {"tool_call_id": "c1", "content": content})
    s = store.state("run-1")
    expected = hashlib.sha256(content.encode()).hexdigest()
    assert s.tainted_spans[0] == expected


def test_record_sink_appended():
    store = SessionStore()
    store.record_source("run-1", {"tool_call_id": "c1", "content": "x"})
    store.record_sink("run-1", {"id": "c2", "name": "send_email", "category": "exfil"})
    s = store.state("run-1")
    assert len(s.sinks) == 1
    assert s.sinks[0]["name"] == "send_email"


def test_record_sink_on_unknown_session_is_noop():
    store = SessionStore()
    store.record_sink("no-such-session", {"id": "c2", "name": "send_email"})
    # Should not create a session
    assert store._store.get("no-such-session") is None


def test_expire_ends_session_and_blocks_reuse():
    store = SessionStore()
    store.record_source("run-1", {"tool_call_id": "c1", "content": "x"})
    store.expire("run-1")
    assert "run-1" not in store._store
    with pytest.raises(SessionExpired) as exc:
        store.state("run-1")
    assert exc.value.reason == "ended"


def test_multi_turn_sources_accumulate():
    store = SessionStore()
    store.record_source("run-1", {"tool_call_id": "c1", "content": "turn1"})
    store.record_source("run-1", {"tool_call_id": "c2", "content": "turn2"})
    s = store.state("run-1")
    assert len(s.sources) == 2
    assert len(s.tainted_spans) == 2


# ---------------------------------------------------------------------------
# Idle + absolute expiry, tombstones (#147)
# ---------------------------------------------------------------------------


def test_active_session_survives_past_idle_ttl_from_creation(clock):
    """The bug: expiry counted from creation, wiping taint on an active session."""
    store = _store(clock)
    store.record_source("run-1", {"tool_call_id": "c1", "content": "evil"})
    for _ in range(6):  # 6 x 10 min = 60 min of activity, each gap < idle TTL
        clock.advance(600)
        assert store.state("run-1").tainted is True


@pytest.mark.parametrize("tainted", [False, True])
def test_idle_session_expires_regardless_of_taint(clock, tainted):
    store = _store(clock)
    store.record_source("run-1", {"tool_call_id": "c1", "content": "x"}, taint=tainted)
    clock.advance(1801)
    with pytest.raises(SessionExpired) as exc:
        store.state("run-1")
    assert exc.value.reason == "idle"
    assert "run-1" not in store._store


def test_idle_boundary_is_inclusive(clock):
    store = _store(clock)
    store.state("run-1")
    clock.advance(1800)
    store.state("run-1")  # exactly at the TTL: still live


def test_long_lived_active_session_never_expires(clock):
    """Expiry counts only from last use — a session in use for 24 h stays live."""
    store = _store(clock)
    store.record_source("run-1", {"tool_call_id": "c1", "content": "evil"})
    for _ in range(144):  # 144 x 10 min = 24 h
        clock.advance(600)
        assert store.state("run-1").tainted is True


def test_expired_tainted_id_is_never_recreated_clean(clock):
    store = _store(clock)
    store.record_source("run-1", {"tool_call_id": "c1", "content": "evil"})
    clock.advance(1801)
    for _ in range(3):
        with pytest.raises(SessionExpired):
            store.state("run-1")
    assert "run-1" not in store._store


def test_record_source_does_not_write_into_expired_session(clock):
    store = _store(clock)
    store.record_source("run-1", {"tool_call_id": "c1", "content": "evil"})
    clock.advance(1801)
    with pytest.raises(SessionExpired):
        store.record_source("run-1", {"tool_call_id": "c2", "content": "more"})


def test_sweep_reaps_abandoned_sessions(clock):
    store = _store(clock)
    store.state("abandoned")
    store.state("active")
    clock.advance(1700)
    store.state("active")
    clock.advance(200)  # abandoned idle 1900s, active idle 200s
    store.sweep()
    assert "abandoned" not in store._store
    assert "active" in store._store
    assert "abandoned" in store._tombstones


def test_periodic_sweep_runs_on_access(clock):
    store = _store(clock)
    store.state("abandoned")
    clock.advance(1801)
    store.state("other")  # any access past SWEEP_INTERVAL triggers a full sweep
    assert "abandoned" not in store._store


def test_tombstone_purged_after_ttl_allows_new_session(clock):
    store = _store(clock, tombstone_ttl=3600)
    store.record_source("run-1", {"tool_call_id": "c1", "content": "evil"})
    clock.advance(1801)
    with pytest.raises(SessionExpired):
        store.state("run-1")
    clock.advance(3601)
    assert store.state("run-1").tainted is False
    assert "run-1" not in store._tombstones


def test_sweep_purges_old_tombstones(clock):
    store = _store(clock, tombstone_ttl=3600)
    store.state("run-1")
    store.expire("run-1")
    clock.advance(3601)
    store.sweep()
    assert store._tombstones == {}


def test_reopen_clears_tombstone(clock):
    store = _store(clock)
    store.state("run-1")
    store.expire("run-1")
    store.reopen("run-1")
    assert store.state("run-1").tainted is False


def test_from_env_reads_ttls(monkeypatch):
    monkeypatch.setenv("SESSION_IDLE_TTL_SECONDS", "60")
    monkeypatch.setenv("SESSION_TOMBSTONE_TTL_SECONDS", "180")
    store = SessionStore.from_env()
    assert (store._idle_ttl, store._tombstone_ttl) == (60, 180)


def test_from_env_defaults(monkeypatch):
    for name in (
        "SESSION_IDLE_TTL_SECONDS",
        "SESSION_TOMBSTONE_TTL_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    store = SessionStore.from_env()
    assert (store._idle_ttl, store._tombstone_ttl) == (1800, 86400)


@pytest.mark.parametrize("value", ["0", "-5", "abc", "1.5"])
def test_from_env_rejects_invalid(monkeypatch, value):
    monkeypatch.setenv("SESSION_IDLE_TTL_SECONDS", value)
    with pytest.raises(ValueError, match="SESSION_IDLE_TTL_SECONDS"):
        SessionStore.from_env()
