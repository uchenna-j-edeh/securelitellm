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


def _request_records(log_path: str) -> list[dict]:
    """Return only request decision records, skipping startup events."""
    lines = Path(log_path).read_text().strip().splitlines()
    return [json.loads(l) for l in lines if json.loads(l).get("event") != "startup"]


@pytest.mark.asyncio
async def test_passthrough_returns_data_unchanged(hook, base_data):
    result = await call_hook(hook, base_data)
    assert result is base_data


@pytest.mark.asyncio
async def test_emits_one_record_per_request(hook, log_path, base_data):
    await call_hook(hook, base_data)
    assert len(_request_records(log_path)) == 1


@pytest.mark.asyncio
async def test_decision_record_required_fields(hook, log_path, base_data):
    await call_hook(hook, base_data)
    record = _request_records(log_path)[0]
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
    record = _request_records(log_path)[0]
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
    record = _request_records(log_path)[0]
    assert record["session_id"] == "run-abc-123"


@pytest.mark.asyncio
async def test_session_id_fallback_when_no_header(hook, log_path, base_data):
    await call_hook(hook, base_data)
    record = _request_records(log_path)[0]
    assert record["session_id"].startswith("no-session-")


@pytest.mark.asyncio
async def test_multiple_requests_append_records(hook, log_path, base_data):
    await call_hook(hook, {**base_data, "litellm_call_id": "req-1"})
    await call_hook(hook, {**base_data, "litellm_call_id": "req-2"})
    records = _request_records(log_path)
    assert len(records) == 2
    assert [r["request_id"] for r in records] == ["req-1", "req-2"]


@pytest.mark.asyncio
async def test_tool_context_captured(hook, log_path):
    from router.classifiers.base import BaseClassifier, ClassifierResult

    class _FakeClassifier(BaseClassifier):
        async def classify(self, text: str) -> ClassifierResult:
            return ClassifierResult(label="BENIGN", score=0.01, latency_ms=1.0, model="fake")

    hook._classifier = _FakeClassifier()

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
    record = _request_records(log_path)[0]
    tc = record["tool_context"]
    assert tc["tool_result_count"] == 1
    assert tc["tool_call_count"] == 1


def test_startup_record_emitted(hook, log_path):
    """RouterHook emits a startup audit record as the first line in the log."""
    lines = Path(log_path).read_text().strip().splitlines()
    startup = json.loads(lines[0])
    assert startup["event"] == "startup"
    for field in ("mode", "level", "enforce", "classifier_backend", "policy_sha256", "lock"):
        assert field in startup, f"startup record missing field: {field}"
    assert len(startup["policy_sha256"]) == 64  # SHA-256 hex


def test_router_lock_rejects_unsafe_config(tmp_path, monkeypatch):
    """ROUTER_LOCK=true raises ValueError when enforce=false or classifier=none."""
    monkeypatch.setenv("ROUTER_MODE", "stateless")
    monkeypatch.setenv("ROUTER_LEVEL", "L0")
    monkeypatch.setenv("ROUTER_LOG_PATH", str(tmp_path / "d.jsonl"))
    monkeypatch.setenv("ROUTER_ENFORCE", "false")
    monkeypatch.setenv("ROUTER_LOCK", "true")
    from router.config import RouterConfig

    with pytest.raises(ValueError, match="ROUTER_LOCK"):
        RouterConfig.from_env()


def test_router_lock_allows_safe_config(tmp_path, monkeypatch):
    """ROUTER_LOCK=true passes when enforce=true and classifier is set."""
    monkeypatch.setenv("ROUTER_MODE", "stateless")
    monkeypatch.setenv("ROUTER_LEVEL", "L3")
    monkeypatch.setenv("ROUTER_LOG_PATH", str(tmp_path / "d.jsonl"))
    monkeypatch.setenv("ROUTER_ENFORCE", "true")
    monkeypatch.setenv("CLASSIFIER_BACKEND", "mock")
    monkeypatch.setenv("ROUTER_LOCK", "true")
    from router.config import RouterConfig

    cfg = RouterConfig.from_env()
    assert cfg.lock is True
