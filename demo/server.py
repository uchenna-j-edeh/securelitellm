"""Demo web server — chat interface + SSE event stream.

Usage:
    make up          # start the proxy (with classifier)
    make demo        # start this server
    open http://localhost:8003
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from demo.agent import MODEL, resume_chat, run_chat  # noqa: E402
from demo.tools import TOOL_SERVER_URL  # noqa: E402
from demo.work_beats import work_beats  # noqa: E402
from router.decisions import DECISIONS_PATH  # noqa: E402
from router.session import session_ref  # noqa: E402

DEMO_DIR = Path(__file__).parent
LOGS_DIR = DEMO_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# The agent's own virtual key (#148). The demo proxies refuse model requests
# sent with the master key; it remains the fallback for a stack without agents.
AGENT_ID = os.environ.get("DEMO_AGENT_ID", "")
MASTER_KEY = os.environ.get("DEMO_AGENT_KEY") or os.environ.get("LITELLM_MASTER_KEY", "")
# The approver (#174). The demo presenter approves as the proxy admin; the
# agent's own key can't reach the approval routes. DEMO_APPROVER_KEY, a key of
# a proxy_admin user, lets a participant approve without the master key.
ADMIN_KEY = os.environ.get("DEMO_APPROVER_KEY") or os.environ.get("LITELLM_MASTER_KEY", "")
APPROVALS_PATH = "/securelitellm/approvals"

# Dual-proxy wiring for the live A/B delayed-exfil demo. Each mode points at a
# separate proxy running a different ROUTER_MODE. Decisions arrive with each
# response, including on remote deployments with no local Docker or AWS login.
PROXY_BY_MODE = {
    "session": os.environ.get("PROXY_URL_SESSION", "http://localhost:4000"),
    "stateless": os.environ.get("PROXY_URL_STATELESS", "http://localhost:4001"),
}

app = FastAPI(title="SecureLiteLLM Demo")
app.mount("/static", StaticFiles(directory=str(DEMO_DIR / "static")), name="static")

# In-memory UI sessions keyed by the browser's session handle (not a proxy id):
#   {"proxy_id": raw proxy-issued x-agent-run-id or None, "history": [messages]}
# The raw proxy id is a session secret: it stays here and never reaches the browser.
_sessions: dict[str, dict] = {}


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((DEMO_DIR / "static" / "index.html").read_text(encoding="utf-8"))


@app.get("/config")
async def demo_config() -> dict:
    if MODEL == "gpt":
        model_display = "Groq · openai/gpt-oss-120b"
    elif MODEL == "groq":
        model_display = "Groq · qwen/qwen3.8-27b"
    elif MODEL == "bedrock":
        model_display = "Amazon Bedrock · openai/gpt-oss-120b"
    else:
        model_display = MODEL
    return {
        "agent": "custom tool-calling agent",
        "agent_id": AGENT_ID if os.environ.get("DEMO_AGENT_KEY") else "",
        "model_alias": MODEL,
        "model_display": model_display,
        "tool_service": TOOL_SERVER_URL,
        "email_mode": os.environ.get("DEMO_EMAIL_MODE", "log"),
        "demo_recipient": os.environ.get("DEMO_RECIPIENT", "demo-recipient@example.test"),
        "work_beats": work_beats(),
        "decision_source": "proxy response",
        "available_modes": ["session"]
        if os.environ.get("DEMO_REMOTE") == "1" and not os.environ.get("PROXY_URL_STATELESS")
        else ["session", "stateless"],
    }


@app.post("/chat")
async def chat(request: Request) -> StreamingResponse:
    body = await request.json()
    user_message: str = body.get("message", "").strip()
    session_id: str = body.get("session_id", "")
    mode: str = body.get("mode", "session")
    if mode not in PROXY_BY_MODE:
        mode = "session"
    proxy_url = PROXY_BY_MODE[mode]

    if not user_message:
        return StreamingResponse(
            iter([f"data: {json.dumps({'kind': 'error', 'message': 'empty message'})}\n\n"]),
            media_type="text/event-stream",
        )

    ui = _sessions.setdefault(session_id, {"proxy_id": None, "history": []})
    if ui.get("mode", mode) != mode:
        return StreamingResponse(
            iter(
                [
                    f"data: {json.dumps({'kind': 'error', 'message': 'Start a new UI session before changing proxy mode.'})}\n\n",
                    f"data: {json.dumps({'kind': 'stream_end'})}\n\n",
                ]
            ),
            media_type="text/event-stream",
        )
    ui["mode"] = mode
    events = run_chat(
        user_message=user_message,
        history=ui["history"],
        session_id=ui["proxy_id"],
        master_key=MASTER_KEY,
        proxy_url=proxy_url,
    )
    return StreamingResponse(
        _stream_turn(ui, events, mode, session_id, user_message),
        media_type="text/event-stream",
    )


@app.post("/chat/resume")
async def chat_resume(request: Request) -> StreamingResponse:
    """Continue the turn held for approval, after the presenter decided (#174)."""
    body = await request.json()
    session_id: str = body.get("session_id", "")
    ui = _sessions.get(session_id) or {}
    pending = ui.get("pending_approval")
    if not pending or not ui.get("proxy_id"):
        return StreamingResponse(
            iter(
                [
                    f"data: {json.dumps({'kind': 'error', 'message': 'nothing is waiting for approval'})}\n\n",
                    f"data: {json.dumps({'kind': 'stream_end'})}\n\n",
                ]
            ),
            media_type="text/event-stream",
        )
    ui.pop("pending_approval")
    mode = pending["mode"]
    events = resume_chat(
        pending, ui["proxy_id"], master_key=MASTER_KEY, proxy_url=PROXY_BY_MODE[mode]
    )
    return StreamingResponse(
        _stream_turn(ui, events, mode, session_id, None),
        media_type="text/event-stream",
    )


def _stream_turn(ui: dict, events, mode: str, session_id: str, user_message):
    """Relay decisions from the exact response before its tools or error are shown."""
    assistant_content = None
    reset = False
    received_decision = False
    ui.setdefault("decisions", OrderedDict())
    ui.setdefault("decision_refs", [])
    ui.setdefault("mode", mode)

    for event in events:
        if event["kind"] == "proxy_session":
            ui["proxy_id"] = event["session_id"]
            ref = session_ref(ui["proxy_id"])
            if ref not in ui["decision_refs"]:
                ui["decision_refs"] = [*ui["decision_refs"], ref][-4:]
            event = {"kind": "proxy_session", "session_ref": event["session_ref"]}
        if event["kind"] == "decision":
            received_decision = True
            record = {**event["record"], "received_at": datetime.now(timezone.utc).isoformat()}
            ui["decisions"][record["decision_id"]] = record
            while len(ui["decisions"]) > 300:
                ui["decisions"].popitem(last=False)
            event = {**event, "record": record}
        if event["kind"] == "approval_pending":
            # The approval ID and the held turn stay here; the browser gets neither.
            ui["pending_approval"] = {
                "approval_id": event["approval_id"],
                "messages": event["messages"],
                "mode": mode,
            }
            event = {
                "kind": "approval_pending",
                "session_ref": event["session_ref"],
                "mode": mode,
            }
        yield f"data: {json.dumps(event)}\n\n"

        if event["kind"] == "assistant_message":
            assistant_content = event["content"]
        if event["kind"] == "session_reset":
            reset = True

    if not received_decision:
        yield f"data: {json.dumps({'kind': 'decision_status', 'status': 'unavailable', 'message': 'No structured decision received for this turn. The proxy may be unreachable or may need the decision response update.'})}\n\n"

    # The proxy rejected the session (expired, restarted, ...): start clean.
    if reset:
        ui["proxy_id"], ui["history"] = None, []
        ui.pop("pending_approval", None)
    # Persist turn to session history
    elif session_id:
        hist = ui["history"]
        if user_message is not None:
            hist.append({"role": "user", "content": user_message})
        if assistant_content:
            hist.append({"role": "assistant", "content": assistant_content})
        # Keep last 20 messages
        ui["history"] = hist[-20:]

    yield f"data: {json.dumps({'kind': 'stream_end'})}\n\n"


def _admin_call(mode: str, method: str, path: str) -> tuple[int, dict]:
    """Call the proxy's approval API as the admin."""
    request = urllib.request.Request(
        PROXY_BY_MODE[mode] + path,
        method=method,
        headers={"Authorization": f"Bearer {ADMIN_KEY}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except ValueError:
            return exc.code, {"detail": "approval API error"}
    except OSError as exc:
        return 502, {"detail": f"proxy unreachable: {exc}"}


@app.get("/approvals")
async def approvals(session_id: str = "", mode: str = "session") -> dict:
    """What is waiting for approval in this UI session, as the approver sees it."""
    if mode not in PROXY_BY_MODE:
        mode = "session"
    status, body = _admin_call(mode, "GET", APPROVALS_PATH)
    if status != 200:
        return {"approvals": [], "error": body.get("detail") or f"HTTP {status}"}
    ui = _sessions.get(session_id) or {}
    ref = session_ref(ui["proxy_id"]) if ui.get("proxy_id") else None
    return {"approvals": [a for a in body.get("approvals", []) if a.get("session_id") == ref]}


@app.post("/approvals/{approval_ref}/{decision}")
async def decide(approval_ref: str, decision: str, mode: str = "session") -> dict:
    if decision not in ("approve", "deny") or mode not in PROXY_BY_MODE:
        return {"ok": False, "detail": "unknown decision"}
    ref = urllib.parse.quote(approval_ref, safe="")
    status, body = _admin_call(mode, "POST", f"{APPROVALS_PATH}/{ref}/{decision}")
    return {"ok": status == 200, **body}


@app.delete("/session/{session_id}")
async def clear_session(session_id: str) -> dict:
    _sessions.pop(session_id, None)
    return {"status": "cleared"}


@app.get("/outbox")
async def outbox() -> dict:
    p = LOGS_DIR / "outbox.jsonl"
    if not p.exists():
        return {"emails": []}
    return {
        "emails": [
            json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()
        ][-20:]
    }


@app.get("/webhook_log")
async def webhook_log() -> dict:
    p = LOGS_DIR / "webhook_log.jsonl"
    if not p.exists():
        return {"posts": []}
    return {
        "posts": [
            json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()
        ][-20:]
    }


@app.delete("/logs")
async def clear_logs() -> dict:
    for f in ["outbox.jsonl", "webhook_log.jsonl"]:
        p = LOGS_DIR / f
        if p.exists():
            p.unlink()
    return {"status": "cleared"}


@app.get("/decisions")
def decisions(session_id: str = "", mode: str = "session") -> dict:
    """Restore one server-owned UI session; never accept an arbitrary audit ref."""
    ui = _sessions.get(session_id)
    if not ui or ui.get("mode", mode) != mode or mode not in PROXY_BY_MODE:
        return {
            "source": "proxy response",
            "status": "waiting",
            "records": [],
            "message": "No retained UI session. Start a new session.",
        }
    cached = ui.setdefault("decisions", OrderedDict())
    message = "Restored decisions received by this UI session."
    if ADMIN_KEY:
        for ref in ui.get("decision_refs", []):
            status, body = _admin_call(mode, "GET", DECISIONS_PATH + "?session=" + ref)
            if status != 200:
                message = "Showing received decisions; gateway history is unavailable."
                continue
            for record in body.get("decisions", []):
                if record.get("session_id") == ref and isinstance(record.get("decision_id"), str):
                    identifier = record["decision_id"]
                    cached[identifier] = {**cached.get(identifier, {}), **record}
    while len(cached) > 300:
        cached.popitem(last=False)
    return {
        "source": "proxy response",
        "status": "ready" if cached else "waiting",
        "records": list(cached.values()),
        "message": message,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("DEMO_PORT", "8003")))
