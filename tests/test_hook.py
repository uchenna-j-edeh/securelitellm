"""Tests for RouterHook — decision record emission and pass-through behaviour."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture()
def hook(log_path, monkeypatch):
    monkeypatch.setenv("ROUTER_MODE", "stateless")
    monkeypatch.setenv("ROUTER_LEVEL", "L0")
    monkeypatch.setenv("ROUTER_LOG_PATH", log_path)
    monkeypatch.setenv("ROUTER_ENFORCE", "false")
    from router.hook import RouterHook

    return RouterHook()


@pytest.fixture()
def base_data():
    return {
        "litellm_call_id": "call-test-001",
        "messages": [{"role": "user", "content": "hello"}],
        "metadata": {"headers": {}},
    }


async def call_hook(hook, data):
    return await hook.async_pre_call_hook(
        user_api_key_dict=MagicMock(),
        cache=MagicMock(),
        data=data,
        call_type="completion",
    )


@pytest.mark.asyncio
async def test_passthrough_returns_data_unchanged(hook, base_data):
    result = await call_hook(hook, base_data)
    assert result is base_data


@pytest.mark.asyncio
async def test_emits_one_record_per_request(hook, log_path, base_data):
    await call_hook(hook, base_data)
    lines = Path(log_path).read_text().strip().splitlines()
    assert len(lines) == 1


@pytest.mark.asyncio
async def test_decision_record_required_fields(hook, log_path, base_data):
    await call_hook(hook, base_data)
    record = json.loads(Path(log_path).read_text().strip())
    for field in (
        "ts",
        "session_id",
        "request_id",
        "mode",
        "level",
        "features",
        "risk_score",
        "action",
        "latency_ms",
        "phase",
    ):
        assert field in record, f"missing field: {field}"


@pytest.mark.asyncio
async def test_decision_record_values(hook, log_path, base_data):
    await call_hook(hook, base_data)
    record = json.loads(Path(log_path).read_text().strip())
    assert record["mode"] == "stateless"
    assert record["level"] == "L0"
    assert record["phase"] == "pre_call"
    assert record["action"] == "allow"
    assert record["risk_score"] == 0.0
    assert record["request_id"] == "call-test-001"
    assert record["latency_ms"] >= 0


@pytest.mark.asyncio
async def test_session_id_from_header(hook, log_path, base_data):
    base_data["metadata"]["headers"]["x-agent-run-id"] = "run-abc-123"
    await call_hook(hook, base_data)
    record = json.loads(Path(log_path).read_text().strip())
    assert record["session_id"] == "run-abc-123"


@pytest.mark.asyncio
async def test_session_id_fallback_when_no_header(hook, log_path, base_data):
    await call_hook(hook, base_data)
    record = json.loads(Path(log_path).read_text().strip())
    assert record["session_id"].startswith("no-session-")


@pytest.mark.asyncio
async def test_multiple_requests_append_records(hook, log_path, base_data):
    await call_hook(hook, {**base_data, "litellm_call_id": "req-1"})
    await call_hook(hook, {**base_data, "litellm_call_id": "req-2"})
    lines = Path(log_path).read_text().strip().splitlines()
    assert len(lines) == 2
    ids = [json.loads(line)["request_id"] for line in lines]
    assert ids == ["req-1", "req-2"]


@pytest.mark.asyncio
async def test_tool_context_captured(hook, log_path):
    data = {
        "litellm_call_id": "tool-req",
        "messages": [
            {"role": "user", "content": "search"},
            {"role": "tool", "tool_call_id": "c1", "content": "results"},
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
        ],
        "metadata": {"headers": {}},
    }
    await call_hook(hook, data)
    record = json.loads(Path(log_path).read_text().strip())
    tc = record["tool_context"]
    assert tc["tool_result_count"] == 1
    assert tc["tool_call_count"] == 1
