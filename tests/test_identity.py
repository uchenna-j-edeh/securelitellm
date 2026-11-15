"""Agent identity from LiteLLM virtual keys (#148)."""

import json
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from router.identity import caller_identity
from tests._sessions import issued


class _Role(str, Enum):  # LiteLLM passes user_role as a str enum
    PROXY_ADMIN = "proxy_admin"
    INTERNAL_USER = "internal_user"


def _agent_key(user_id="billing-agent"):
    return SimpleNamespace(
        token="hash-of-agent-key", user_id=user_id, user_role=_Role.INTERNAL_USER
    )


def _master_key():
    return SimpleNamespace(token="master", user_id="default_user_id", user_role=_Role.PROXY_ADMIN)


def _key_without_user():
    return SimpleNamespace(token="hash-of-loose-key", user_id=None, user_role=None)


# ---------------------------------------------------------------------------
# caller_identity
# ---------------------------------------------------------------------------


def test_a_virtual_key_resolves_to_its_user_id():
    caller = caller_identity(_agent_key())
    assert (caller.agent, caller.admin, caller.violation) == ("billing-agent", False, None)


def test_the_master_key_is_an_admin_with_no_agent():
    caller = caller_identity(_master_key())
    assert (caller.agent, caller.admin, caller.violation) == (None, True, "admin_key")


def test_an_admin_role_given_as_a_plain_string_is_still_an_admin():
    caller = caller_identity(SimpleNamespace(user_id="alice", user_role="proxy_admin"))
    assert (caller.agent, caller.admin) == (None, True)


@pytest.mark.parametrize("user_id", [None, "", "   ", 42])
def test_a_key_with_no_usable_user_id_has_no_identity(user_id):
    caller = caller_identity(SimpleNamespace(user_id=user_id, user_role=None))
    assert (caller.agent, caller.violation) == (None, "no_identity")


def test_an_unknown_auth_object_has_no_identity():
    assert caller_identity(MagicMock()).agent is None
    assert caller_identity(None).violation == "no_identity"


def test_the_logged_agent_id_is_bounded():
    assert len(caller_identity(_agent_key("a" * 5000)).agent) == 128


# ---------------------------------------------------------------------------
# The hook
# ---------------------------------------------------------------------------


def _hook(log_path, monkeypatch, *, require, enforce="true"):
    monkeypatch.setenv("ROUTER_MODE", "session")
    monkeypatch.setenv("ROUTER_LEVEL", "L3")
    monkeypatch.setenv("ROUTER_LOG_PATH", log_path)
    monkeypatch.setenv("ROUTER_ENFORCE", enforce)
    monkeypatch.setenv("ROUTER_REQUIRE_AGENT_KEY", "true" if require else "false")
    import router.session as sess_mod
    from router.session import SessionStore

    monkeypatch.setattr(sess_mod, "_store", SessionStore())
    from router.hook import RouterHook

    return RouterHook()


def _data(call_id="req-1"):
    return {
        "litellm_call_id": call_id,
        "messages": [{"role": "user", "content": "hi"}],
        "metadata": {"headers": {}},
    }


def _records(log_path):
    lines = Path(log_path).read_text().strip().splitlines()
    return [json.loads(ln) for ln in lines if json.loads(ln).get("event") != "startup"]


@pytest.mark.asyncio
async def test_decisions_name_the_agent(log_path, monkeypatch):
    hook = _hook(log_path, monkeypatch, require=False)
    await hook.async_pre_call_hook(_agent_key(), MagicMock(), _data(), "completion")
    assert _records(log_path)[0]["agent"] == "billing-agent"


@pytest.mark.asyncio
async def test_post_call_decisions_name_the_agent(log_path, monkeypatch):
    hook = _hook(log_path, monkeypatch, require=False)
    data = _data()
    await hook.async_pre_call_hook(_agent_key(), MagicMock(), data, "completion")
    function = SimpleNamespace(name="send_email", arguments='{"to":"owner@example.com"}')
    message = SimpleNamespace(
        content=None, tool_calls=[SimpleNamespace(id="c1", function=function)]
    )
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="tool_calls")]
    )
    await hook.async_post_call_success_hook(_agent_key(), data, response)
    post = [r for r in _records(log_path) if r["phase"] == "post_call"]
    assert post and post[0]["agent"] == "billing-agent"


@pytest.mark.asyncio
async def test_the_master_key_still_works_when_agent_keys_are_not_required(log_path, monkeypatch):
    hook = _hook(log_path, monkeypatch, require=False)
    await hook.async_pre_call_hook(_master_key(), MagicMock(), _data(), "completion")
    record = _records(log_path)[0]
    assert record["agent"] is None and record["action"] != "block"


@pytest.mark.asyncio
async def test_the_master_key_cannot_send_model_requests_when_agent_keys_are_required(
    log_path, monkeypatch
):
    import litellm.exceptions as _le

    hook = _hook(log_path, monkeypatch, require=True)
    with pytest.raises(_le.BadRequestError, match="administration only"):
        await hook.async_pre_call_hook(_master_key(), MagicMock(), _data(), "completion")
    record = _records(log_path)[0]
    assert record["matched_rules"] == ["agent_unidentified"]
    assert record["features"] == {"agent_violation": "admin_key"}
    assert record["action"] == "block"
    assert hook._issued == {}  # rejected before a session is issued


@pytest.mark.asyncio
async def test_a_key_with_no_user_is_rejected_when_agent_keys_are_required(log_path, monkeypatch):
    import litellm.exceptions as _le

    hook = _hook(log_path, monkeypatch, require=True)
    with pytest.raises(_le.BadRequestError, match="not registered to an agent"):
        await hook.async_pre_call_hook(_key_without_user(), MagicMock(), _data(), "completion")
    assert _records(log_path)[0]["features"] == {"agent_violation": "no_identity"}


@pytest.mark.asyncio
async def test_an_agent_key_passes_when_agent_keys_are_required(log_path, monkeypatch):
    hook = _hook(log_path, monkeypatch, require=True)
    await hook.async_pre_call_hook(_agent_key(), MagicMock(), _data(), "completion")
    record = _records(log_path)[0]
    assert record["agent"] == "billing-agent" and record["session_issued"] is True


@pytest.mark.asyncio
async def test_audit_mode_logs_an_unidentified_caller_and_continues(log_path, monkeypatch):
    hook = _hook(log_path, monkeypatch, require=True, enforce="false")
    await hook.async_pre_call_hook(_master_key(), MagicMock(), _data(), "completion")
    records = _records(log_path)
    assert records[0]["matched_rules"] == ["agent_unidentified"]
    assert records[1]["phase"] == "pre_call" and records[1]["agent"] is None


@pytest.mark.asyncio
async def test_one_agent_cannot_use_another_agents_session(log_path, monkeypatch):
    """Each agent has its own key, so the existing owner binding separates agents."""
    import litellm.exceptions as _le

    hook = _hook(log_path, monkeypatch, require=True)
    raw = issued("shared", owner="hash-of-agent-key")
    data = _data()
    data["metadata"]["headers"]["x-agent-run-id"] = raw
    other = SimpleNamespace(
        token="hash-of-other-key", user_id="support-agent", user_role="internal_user"
    )
    with pytest.raises(_le.BadRequestError, match="different API key"):
        await hook.async_pre_call_hook(other, MagicMock(), data, "completion")
    record = _records(log_path)[0]
    assert record["matched_rules"] == ["session_owner_mismatch"]
    assert record["agent"] == "support-agent"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_lock_requires_agent_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("ROUTER_LOG_PATH", str(tmp_path / "d.jsonl"))
    monkeypatch.setenv("CLASSIFIER_BACKEND", "mock")
    monkeypatch.setenv("ROUTER_LOCK", "true")
    monkeypatch.setenv("ROUTER_REQUIRE_AGENT_KEY", "false")
    from router.config import RouterConfig

    with pytest.raises(ValueError, match="require_agent_key=False"):
        RouterConfig.from_env()


def test_startup_record_reports_the_setting(monkeypatch, tmp_path):
    monkeypatch.setenv("ROUTER_LOG_PATH", str(tmp_path / "d.jsonl"))
    monkeypatch.setenv("ROUTER_REQUIRE_AGENT_KEY", "true")
    from router.config import RouterConfig

    assert RouterConfig.from_env().startup_record()["require_agent_key"] is True
