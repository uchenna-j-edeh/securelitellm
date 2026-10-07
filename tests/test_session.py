"""Tests for the session store (issue #15)."""

from router.session import SessionStore


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


def test_expire_removes_session():
    store = SessionStore()
    store.record_source("run-1", {"tool_call_id": "c1", "content": "x"})
    store.expire("run-1")
    s = store.state("run-1")
    assert s.tainted is False  # fresh session after expire


def test_expired_ttl_returns_fresh_session():
    store = SessionStore(ttl_seconds=0)  # instant TTL
    store.record_source("run-1", {"tool_call_id": "c1", "content": "x"})
    # Avoid relying on the host clock resolution (15.625 ms on some Windows systems).
    store._store["run-1"].created_at -= 1
    s = store.state("run-1")
    assert s.tainted is False  # evicted and recreated


def test_multi_turn_sources_accumulate():
    store = SessionStore()
    store.record_source("run-1", {"tool_call_id": "c1", "content": "turn1"})
    store.record_source("run-1", {"tool_call_id": "c2", "content": "turn2"})
    s = store.state("run-1")
    assert len(s.sources) == 2
    assert len(s.tainted_spans) == 2
