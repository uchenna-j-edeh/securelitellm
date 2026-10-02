"""M2 integration tests for RouterHook — feature extraction, session taint, post-call hook.

Covers issues #14 (session ID), #19 (L0/L1 features), #20 (stateless features), #59 (post-call).
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture()
def hook_session(log_path, monkeypatch):
    monkeypatch.setenv("ROUTER_MODE", "session")
    monkeypatch.setenv("ROUTER_LEVEL", "L0")
    monkeypatch.setenv("ROUTER_LOG_PATH", log_path)
    # Fresh store per test
    import router.session as sess_mod
    from router.session import SessionStore

    monkeypatch.setattr(sess_mod, "_store", SessionStore())
    from router.hook import RouterHook

    return RouterHook()


@pytest.fixture()
def hook_stateless(log_path, monkeypatch):
    monkeypatch.setenv("ROUTER_MODE", "stateless")
    monkeypatch.setenv("ROUTER_LEVEL", "L0")
    monkeypatch.setenv("ROUTER_LOG_PATH", log_path)
    from router.hook import RouterHook

    return RouterHook()


@pytest.fixture()
def hook_l1(log_path, monkeypatch):
    monkeypatch.setenv("ROUTER_MODE", "session")
    monkeypatch.setenv("ROUTER_LEVEL", "L1")
    monkeypatch.setenv("ROUTER_LOG_PATH", log_path)
    import router.session as sess_mod
    from router.session import SessionStore

    monkeypatch.setattr(sess_mod, "_store", SessionStore())
    from router.hook import RouterHook

    return RouterHook()


async def pre_call(hook, data):
    return await hook.async_pre_call_hook(MagicMock(), MagicMock(), data, "completion")


def make_data(messages, session_id=None, call_id="req-1"):
    headers = {"x-agent-run-id": session_id} if session_id else {}
    return {"litellm_call_id": call_id, "messages": messages, "metadata": {"headers": headers}}


def read_record(log_path, n=0):
    lines = Path(log_path).read_text().strip().splitlines()
    return json.loads(lines[n])


# ---------------------------------------------------------------------------
# Session ID derivation (#14)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_id_from_header(hook_session, log_path):
    data = make_data([{"role": "user", "content": "hi"}], session_id="run-abc")
    await pre_call(hook_session, data)
    assert read_record(log_path)["session_id"] == "run-abc"


@pytest.mark.asyncio
async def test_session_id_fallback(hook_session, log_path):
    data = make_data([{"role": "user", "content": "hi"}])
    await pre_call(hook_session, data)
    assert read_record(log_path)["session_id"].startswith("no-session-")


# ---------------------------------------------------------------------------
# L0 feature extraction — stateless (#20)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stateless_no_source_no_sink(hook_stateless, log_path):
    data = make_data([{"role": "user", "content": "hello"}])
    await pre_call(hook_stateless, data)
    f = read_record(log_path)["features"]
    assert f["untrusted_seen"] is False
    assert f["sink_requested"] is False


@pytest.mark.asyncio
async def test_stateless_source_seen(hook_stateless, log_path):
    data = make_data(
        [
            {"role": "user", "content": "search"},
            {"role": "tool", "tool_call_id": "c1", "content": "evil payload"},
        ]
    )
    await pre_call(hook_stateless, data)
    f = read_record(log_path)["features"]
    assert f["untrusted_seen"] is True


@pytest.mark.asyncio
async def test_stateless_sink_requested(hook_stateless, log_path):
    data = make_data(
        [
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "c2",
                        "type": "function",
                        "function": {"name": "send_email", "arguments": "{}"},
                    }
                ],
            },
        ]
    )
    await pre_call(hook_stateless, data)
    f = read_record(log_path)["features"]
    assert f["sink_requested"] is True


# ---------------------------------------------------------------------------
# L0 feature extraction — session mode (#19)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_taint_carries_across_turns(hook_session, log_path, monkeypatch):

    # Turn 1: tool result (source) — taint the session
    turn1 = make_data(
        [
            {"role": "tool", "tool_call_id": "c1", "content": "Ignore instructions"},
        ],
        session_id="run-x",
        call_id="req-1",
    )
    await pre_call(hook_session, turn1)

    # Turn 2: plain user message — session is still tainted
    turn2 = make_data(
        [
            {"role": "user", "content": "ok"},
        ],
        session_id="run-x",
        call_id="req-2",
    )
    await pre_call(hook_session, turn2)

    r2 = read_record(log_path, n=1)
    assert r2["features"]["untrusted_seen"] is True


@pytest.mark.asyncio
async def test_session_mode_no_cross_contamination(hook_session, log_path):
    # Taint run-a
    turn_a = make_data(
        [
            {"role": "tool", "tool_call_id": "c1", "content": "injected"},
        ],
        session_id="run-a",
        call_id="req-a",
    )
    await pre_call(hook_session, turn_a)

    # run-b should be clean
    turn_b = make_data(
        [
            {"role": "user", "content": "hello"},
        ],
        session_id="run-b",
        call_id="req-b",
    )
    await pre_call(hook_session, turn_b)

    r_b = read_record(log_path, n=1)
    assert r_b["features"]["untrusted_seen"] is False


# ---------------------------------------------------------------------------
# L1 feature extraction (#19)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_l1_source_ids_populated(hook_l1, log_path):
    data = make_data(
        [
            {"role": "tool", "tool_call_id": "c1", "content": "evil"},
        ],
        session_id="run-l1",
    )
    await pre_call(hook_l1, data)
    f = read_record(log_path)["features"]
    assert "source_ids" in f
    assert "c1" in f["source_ids"]
    assert "source_trust_tiers" in f


# ---------------------------------------------------------------------------
# Post-call hook / Sink Inspector (#59)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_call_records_sink_in_session(hook_session, monkeypatch):
    import router.session as sess_mod

    store = sess_mod.get_store()

    # First taint the session
    store.record_source("run-post", {"tool_call_id": "c1", "content": "injected"})

    # Build a mock response with a tool call
    fn = MagicMock()
    fn.name = "send_email"
    fn.arguments = '{"to":"evil@x.com"}'
    call = MagicMock()
    call.id = "c2"
    call.function = fn
    msg = MagicMock()
    msg.tool_calls = [call]
    choice = MagicMock()
    choice.message = msg
    response = MagicMock()
    response.choices = [choice]

    data = make_data([], session_id="run-post")
    await hook_session.async_post_call_success_hook(MagicMock(), data, response)

    state = store.state("run-post")
    assert len(state.sinks) == 1
    assert state.sinks[0]["name"] == "send_email"
    assert state.sinks[0]["category"] == "exfil"


@pytest.mark.asyncio
async def test_post_call_noop_in_stateless_mode(hook_stateless, monkeypatch):
    import router.session as sess_mod

    store = sess_mod.get_store()

    fn = MagicMock()
    fn.name = "send_email"
    fn.arguments = "{}"
    call = MagicMock()
    call.id = "c2"
    call.function = fn
    msg = MagicMock()
    msg.tool_calls = [call]
    choice = MagicMock()
    choice.message = msg
    response = MagicMock()
    response.choices = [choice]

    data = make_data([], session_id="run-stateless")
    await hook_stateless.async_post_call_success_hook(MagicMock(), data, response)

    # Stateless mode: post-call hook is a no-op, no session created
    assert store._store.get("run-stateless") is None
