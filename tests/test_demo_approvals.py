"""Demo agent and UI server for held-for-approval (#174)."""

import copy
import json

import httpx
import pytest

from demo import agent

APPROVAL_ID = "raw-approval-id-only-the-agent-holds"


def _held(approval_id=APPROVAL_ID, status="pending"):
    headers = {"x-securelitellm-approval-status": status} if status else {}
    if approval_id:
        headers["x-securelitellm-approval"] = approval_id
    body = {
        "choices": [
            {
                "finish_reason": "content_filter",
                "message": {"content": "SecureLiteLLM held the generated tool call for approval."},
            }
        ]
    }
    return httpx.Response(200, json=body, headers=headers)


def _tool_turn():
    call = {
        "id": "call-1",
        "type": "function",
        "function": {"name": "send_email", "arguments": json.dumps({"to": "new@example.test"})},
    }
    body = {
        "choices": [
            {"finish_reason": "tool_calls", "message": {"content": None, "tool_calls": [call]}}
        ]
    }
    return httpx.Response(200, json=body)


def _answer(text="Sent."):
    return httpx.Response(
        200, json={"choices": [{"finish_reason": "stop", "message": {"content": text}}]}
    )


class _Proxy:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.headers = []
        self.bodies = []

    def __call__(self, url, json=None, headers=None, timeout=None):
        self.headers.append(dict(headers or {}))
        self.bodies.append(copy.deepcopy(json))  # the agent keeps appending to its list
        return self.responses.pop(0)


def test_a_hold_with_an_approval_id_keeps_the_turn_for_a_retry(monkeypatch):
    proxy = _Proxy(_held())
    monkeypatch.setattr(agent.httpx, "post", proxy)
    monkeypatch.setattr(agent, "call_tool", lambda *a, **kw: pytest.fail("no tool may run"))
    events = list(agent.run_chat("email the supplier", [], session_id="run-id-123"))
    kinds = [e["kind"] for e in events]
    assert kinds == ["intercepted", "approval_pending"]
    pending = events[-1]
    assert pending["approval_id"] == APPROVAL_ID
    assert pending["messages"] == proxy.bodies[0]["messages"]  # exactly what was held


def test_resuming_sends_the_approval_once_and_runs_the_replayed_calls(monkeypatch):
    proxy = _Proxy(_tool_turn(), _answer())
    ran = []
    monkeypatch.setattr(agent.httpx, "post", proxy)
    monkeypatch.setattr(
        agent, "call_tool", lambda name, args, **kw: ran.append((name, args)) or {"ok": True}
    )
    pending = {
        "approval_id": APPROVAL_ID,
        "messages": [{"role": "user", "content": "email the supplier"}],
    }
    events = list(agent.resume_chat(pending, "run-id-123", master_key="sk-agent"))

    assert proxy.headers[0]["x-securelitellm-approval"] == APPROVAL_ID
    assert "x-securelitellm-approval" not in proxy.headers[1]  # only the held request's retry
    assert all(h["x-agent-run-id"] == "run-id-123" for h in proxy.headers)
    assert proxy.bodies[0]["messages"] == pending["messages"]
    assert ran == [("send_email", {"to": "new@example.test"})]
    assert [e["kind"] for e in events][-2:] == ["assistant_message", "done"]


@pytest.mark.parametrize("status", ["denied", "expired", "used", "pending", "mismatch"])
def test_an_unusable_approval_is_reported_and_nothing_runs(monkeypatch, status):
    monkeypatch.setattr(agent.httpx, "post", _Proxy(_held(approval_id=None, status=status)))
    monkeypatch.setattr(agent, "call_tool", lambda *a, **kw: pytest.fail("no tool may run"))
    pending = {"approval_id": APPROVAL_ID, "messages": [{"role": "user", "content": "x"}]}
    events = list(agent.resume_chat(pending, "run-id-123"))
    assert [(e["kind"], e.get("status")) for e in events] == [("approval_status", status)]


def test_a_plain_hold_has_no_approval_event(monkeypatch):
    monkeypatch.setattr(agent.httpx, "post", _Proxy(_held(approval_id=None, status=None)))
    events = list(agent.run_chat("x", [], session_id="run-id-123"))
    assert [e["kind"] for e in events] == ["intercepted"]


# ---------------------------------------------------------------------------
# UI server
# ---------------------------------------------------------------------------


@pytest.fixture()
def server(monkeypatch):
    from demo import server as srv

    monkeypatch.setattr(srv, "_sessions", {})
    monkeypatch.setattr(srv, "_decisions_for_session", lambda ref, container=None: [])
    monkeypatch.setattr(srv.time, "sleep", lambda s: None)
    return srv


def _events(response):
    return [json.loads(line[5:]) for line in response.text.splitlines() if line.startswith("data:")]


def test_the_approval_id_and_held_turn_never_reach_the_browser(server, monkeypatch):
    from fastapi.testclient import TestClient

    def run_chat(**kwargs):
        yield {"kind": "proxy_session", "session_id": "raw-session", "session_ref": "ref-1"}
        yield {"kind": "intercepted", "action": "hold", "message": "held"}
        yield {
            "kind": "approval_pending",
            "approval_id": APPROVAL_ID,
            "messages": [{"role": "user", "content": "secret turn"}],
            "message": "held",
            "session_ref": "ref-1",
        }

    monkeypatch.setattr(server, "run_chat", run_chat)
    response = TestClient(server.app).post("/chat", json={"message": "go", "session_id": "ui-1"})
    assert APPROVAL_ID not in response.text and "secret turn" not in response.text
    pending = [e for e in _events(response) if e["kind"] == "approval_pending"]
    assert pending == [{"kind": "approval_pending", "session_ref": "ref-1", "mode": "session"}]
    stored = server._sessions["ui-1"]["pending_approval"]
    assert stored["approval_id"] == APPROVAL_ID and stored["mode"] == "session"


def test_resume_uses_the_stored_turn_once(server, monkeypatch):
    from fastapi.testclient import TestClient

    server._sessions["ui-1"] = {
        "proxy_id": "raw-session",
        "history": [],
        "pending_approval": {"approval_id": APPROVAL_ID, "messages": [], "mode": "stateless"},
    }
    seen = []

    def resume_chat(pending, session_id, master_key="", proxy_url=None):
        seen.append((pending["approval_id"], session_id, proxy_url))
        yield {"kind": "assistant_message", "content": "Sent."}
        yield {"kind": "done"}

    monkeypatch.setattr(server, "resume_chat", resume_chat)
    client = TestClient(server.app)
    first = client.post("/chat/resume", json={"session_id": "ui-1"})
    assert seen == [(APPROVAL_ID, "raw-session", server.PROXY_BY_MODE["stateless"])]
    assert any(e["kind"] == "assistant_message" for e in _events(first))
    second = client.post("/chat/resume", json={"session_id": "ui-1"})
    assert _events(second)[0] == {"kind": "error", "message": "nothing is waiting for approval"}
    assert len(seen) == 1


def test_the_approval_list_shows_only_this_ui_sessions_items(server, monkeypatch):
    from fastapi.testclient import TestClient

    from router.session import session_ref

    server._sessions["ui-1"] = {"proxy_id": "raw-session", "history": []}
    mine = {"approval_ref": "a" * 16, "session_id": session_ref("raw-session"), "status": "pending"}
    other = {"approval_ref": "b" * 16, "session_id": "someone-else", "status": "pending"}
    calls = []

    def admin_call(mode, method, path):
        calls.append((mode, method, path))
        return 200, {"approvals": [mine, other]}

    monkeypatch.setattr(server, "_admin_call", admin_call)
    body = TestClient(server.app).get("/approvals?session_id=ui-1&mode=session").json()
    assert body == {"approvals": [mine]}
    assert calls == [("session", "GET", "/securelitellm/approvals")]


def test_decisions_go_to_the_proxy_as_the_admin(server, monkeypatch):
    from fastapi.testclient import TestClient

    calls = []
    monkeypatch.setattr(
        server,
        "_admin_call",
        lambda mode, method, path: (
            calls.append((mode, method, path)) or (200, {"status": "approved"})
        ),
    )
    client = TestClient(server.app)
    assert client.post("/approvals/abc/approve?mode=stateless").json() == {
        "ok": True,
        "status": "approved",
    }
    assert calls == [("stateless", "POST", "/securelitellm/approvals/abc/approve")]
    assert client.post("/approvals/abc/delete").json()["ok"] is False
    assert len(calls) == 1


def test_the_admin_calls_use_the_master_key_not_the_agent_key(server, monkeypatch):
    seen = {}

    class _Response:
        status = 200

        def read(self):
            return b'{"approvals": []}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def urlopen(request, timeout=None):
        seen["auth"] = request.get_header("Authorization")
        return _Response()

    monkeypatch.setattr(server, "ADMIN_KEY", "sk-master")
    monkeypatch.setattr(server, "MASTER_KEY", "sk-agent")
    monkeypatch.setattr(server.urllib.request, "urlopen", urlopen)
    assert server._admin_call("session", "GET", "/securelitellm/approvals") == (
        200,
        {"approvals": []},
    )
    assert seen["auth"] == "Bearer sk-master"
