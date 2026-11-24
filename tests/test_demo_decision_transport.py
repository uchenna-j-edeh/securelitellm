"""Response metadata reaches the UI on success, block, reset and reload, without log reads."""

import json
import subprocess

import httpx
import pytest
from fastapi.testclient import TestClient

from demo import agent, server
from demo.decision_transport import response_decisions
from router.decisions import DECISION_HEADER
from router.session import session_ref
from tests.test_decision_response import record


def value(*records):
    return {"version": 1, "decisions": list(records)}


def response(records, status=200, message="hello", header=True):
    body = {"choices": [{"message": {"content": message}, "finish_reason": "stop"}]}
    if status >= 400:
        body = {
            "error": {
                "message": message,
                "provider_specific_fields": {"securelitellm_decision": value(*records)},
            }
        }
    return httpx.Response(
        status,
        json=body,
        headers={
            DECISION_HEADER: json.dumps(value(*records)),
            "x-agent-run-id": "server-only-raw-session",
        }
        if header
        else {},
    )


@pytest.mark.parametrize("header", [True, False])
def test_failed_request_carries_exact_block_decision_without_running_a_tool(monkeypatch, header):
    blocked = record(action="block", risk_score=1, risk_level="critical", route="block")
    monkeypatch.setattr(
        agent.httpx,
        "post",
        lambda *a, **kw: response(
            [blocked], status=400, message="SecureLiteLLM: Request blocked by policy", header=header
        ),
    )
    monkeypatch.setattr(
        agent, "call_tool", lambda *a, **kw: pytest.fail("blocked tools must not run")
    )
    events = list(agent.run_chat("test", [], master_key="agent-key"))
    assert [e["record"] for e in events if e["kind"] == "decision"] == [blocked]
    assert [e["record"] for e in events if e["kind"] == "block_context"] == [blocked]
    assert [e["kind"] for e in events].index("decision") < [e["kind"] for e in events].index(
        "blocked"
    )


def test_model_prose_and_malformed_headers_are_not_gateway_evidence():
    wire = response([], message=json.dumps(value(record())))
    wire.headers.pop(DECISION_HEADER)
    assert response_decisions(wire) == []
    wire.headers[DECISION_HEADER] = "not-json"
    assert response_decisions(wire) == []


@pytest.fixture()
def ui(monkeypatch):
    monkeypatch.setattr(server, "_sessions", {})
    monkeypatch.setattr(server, "ADMIN_KEY", "")
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: pytest.fail("No Docker or AWS CLI log reads")
    )
    return TestClient(server.app)


def test_ui_stream_preserves_decisions_after_session_reset_and_reload(ui, monkeypatch):
    rec = record(action="block", mode="stateless")  # actual proxy mode can differ from UI button

    def run(**kw):
        yield {
            "kind": "proxy_session",
            "session_id": "server-only-raw-session",
            "session_ref": "ref",
        }
        yield {"kind": "decision", "record": rec}
        yield {"kind": "session_reset", "message": "session expired"}

    monkeypatch.setattr(server, "run_chat", run)
    streamed = ui.post("/chat", json={"session_id": "opaque-ui-handle", "message": "go"})
    assert "server-only-raw-session" not in streamed.text
    assert "decision" in streamed.text
    assert server._sessions["opaque-ui-handle"]["proxy_id"] is None
    restored = ui.get("/decisions", params={"session_id": "opaque-ui-handle"}).json()
    assert restored["records"][0]["decision_id"] == rec["decision_id"]
    assert "server-only-raw-session" not in json.dumps(restored)


def test_browser_cannot_request_arbitrary_proxy_history(ui, monkeypatch):
    monkeypatch.setattr(server, "ADMIN_KEY", "admin-key")
    monkeypatch.setattr(
        server, "_admin_call", lambda *a: pytest.fail("Unknown browser handle cannot use admin key")
    )
    assert ui.get("/decisions", params={"session_id": "a" * 16}).json()["records"] == []


def test_history_enriches_the_same_decision_and_is_not_filtered_by_configured_agent(
    ui, monkeypatch
):
    ref = session_ref("server-only-raw-session")
    rec = record(session_id=ref, agent=None)

    def run(**kw):
        yield {"kind": "proxy_session", "session_id": "server-only-raw-session", "session_ref": ref}
        yield {"kind": "decision", "record": {"decision_id": rec["decision_id"], "action": "allow"}}

    monkeypatch.setattr(server, "run_chat", run)
    ui.post("/chat", json={"session_id": "handle", "message": "go"})
    monkeypatch.setattr(server, "ADMIN_KEY", "server-only-admin-key")
    monkeypatch.setattr(server, "_admin_call", lambda *args: (200, {"decisions": [rec]}))
    for _ in range(2):
        result = ui.get("/decisions", params={"session_id": "handle"}).json()
        assert len(result["records"]) == 1
        assert result["records"][0]["risk_score"] == 0
        assert "server-only-admin-key" not in json.dumps(result)


def test_missing_metadata_is_reported_without_inventing_a_decision(ui, monkeypatch):
    monkeypatch.setattr(
        server,
        "run_chat",
        lambda **kw: iter([{"kind": "assistant_message", "content": "I refused it"}]),
    )
    result = ui.post("/chat", json={"session_id": "handle", "message": "go"})
    events = [json.loads(line[5:]) for line in result.text.splitlines() if line.startswith("data:")]
    assert not any(e["kind"] == "decision" for e in events)
    assert next(e for e in events if e["kind"] == "decision_status")["status"] == "unavailable"
