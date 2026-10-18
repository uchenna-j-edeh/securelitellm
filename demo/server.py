"""Demo web server — chat interface + SSE event stream.

Usage:
    make up          # start the proxy (with classifier)
    make demo        # start this server
    open http://localhost:8003
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from demo.agent import MODEL, run_chat  # noqa: E402
from demo.tools import TOOL_SERVER_URL  # noqa: E402
from router.session import session_ref  # noqa: E402

DEMO_DIR = Path(__file__).parent
LOGS_DIR = DEMO_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

MASTER_KEY = os.environ.get("LITELLM_MASTER_KEY", "")
CONTAINER_NAME = os.environ.get("E2E_CONTAINER_NAME", "deploy-litellm-1")

# Dual-proxy wiring for the live A/B delayed-exfil demo. Each mode points at a
# separate proxy container running a different ROUTER_MODE; the decision log is
# read from whichever container served the turn.
PROXY_BY_MODE = {
    "session": os.environ.get("PROXY_URL_SESSION", "http://localhost:4000"),
    "stateless": os.environ.get("PROXY_URL_STATELESS", "http://localhost:4001"),
}
CONTAINER_BY_MODE = {
    "session": os.environ.get("CONTAINER_SESSION", CONTAINER_NAME),
    "stateless": os.environ.get("CONTAINER_STATELESS", "deploy-litellm-stateless-1"),
}

app = FastAPI(title="SecureLiteLLM Demo")
app.mount("/static", StaticFiles(directory=str(DEMO_DIR / "static")), name="static")

# In-memory UI sessions keyed by the browser's session handle (not a proxy id):
#   {"proxy_id": raw proxy-issued x-agent-run-id or None, "history": [messages]}
# The raw proxy id is a session secret: it stays here and never reaches the browser.
_sessions: dict[str, dict] = {}


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((DEMO_DIR / "static" / "index.html").read_text())


@app.get("/config")
async def demo_config() -> dict:
    if MODEL == "llama":
        model_display = "Groq · openai/gpt-oss-120b"
    elif MODEL == "groq":
        model_display = "Groq · qwen/qwen3.8-27b"
    else:
        model_display = MODEL
    return {
        "agent": "custom tool-calling agent",
        "model_alias": MODEL,
        "model_display": model_display,
        "tool_service": TOOL_SERVER_URL,
        "email_mode": os.environ.get("DEMO_EMAIL_MODE", "log"),
        "demo_recipient": os.environ.get("DEMO_RECIPIENT", "demo-recipient@example.test"),
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
    container = CONTAINER_BY_MODE[mode]

    if not user_message:
        return StreamingResponse(
            iter([f"data: {json.dumps({'kind': 'error', 'message': 'empty message'})}\n\n"]),
            media_type="text/event-stream",
        )

    ui = _sessions.setdefault(session_id, {"proxy_id": None, "history": []})

    def stream():
        assistant_content = None
        was_blocked = False
        reset = False

        for event in run_chat(
            user_message=user_message,
            history=ui["history"],
            session_id=ui["proxy_id"],
            master_key=MASTER_KEY,
            proxy_url=proxy_url,
        ):
            if event["kind"] == "proxy_session":
                ui["proxy_id"] = event["session_id"]
                event = {"kind": "proxy_session", "session_ref": event["session_ref"]}
            yield f"data: {json.dumps(event)}\n\n"

            if event["kind"] == "assistant_message":
                assistant_content = event["content"]
            if event["kind"] == "blocked":
                was_blocked = True
            if event["kind"] == "session_reset":
                reset = True

        # Pull decision records for this session from container logs
        time.sleep(0.5)
        ref = session_ref(ui["proxy_id"]) if ui["proxy_id"] else None
        decisions = _decisions_for_session(ref, container) if ref else []
        for d in decisions:
            yield f"data: {json.dumps({'kind': 'decision', 'record': d})}\n\n"

        # Enrich the blocked banner with the last decision's context
        if was_blocked and decisions:
            last = decisions[-1]
            yield f"data: {json.dumps({'kind': 'block_context', 'record': last})}\n\n"

        # The proxy rejected the session (expired, restarted, ...): start clean.
        if reset:
            ui["proxy_id"], ui["history"] = None, []
        # Persist turn to session history
        elif session_id:
            hist = ui["history"]
            hist.append({"role": "user", "content": user_message})
            if assistant_content:
                hist.append({"role": "assistant", "content": assistant_content})
            # Keep last 20 messages
            ui["history"] = hist[-20:]

        yield f"data: {json.dumps({'kind': 'stream_end'})}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


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
        "emails": [json.loads(line) for line in p.read_text().splitlines() if line.strip()][-20:]
    }


@app.get("/webhook_log")
async def webhook_log() -> dict:
    p = LOGS_DIR / "webhook_log.jsonl"
    if not p.exists():
        return {"posts": []}
    return {
        "posts": [json.loads(line) for line in p.read_text().splitlines() if line.strip()][-20:]
    }


@app.delete("/logs")
async def clear_logs() -> dict:
    for f in ["outbox.jsonl", "webhook_log.jsonl"]:
        p = LOGS_DIR / f
        if p.exists():
            p.unlink()
    return {"status": "cleared"}


def _decisions_for_session(ref: str, container: str = CONTAINER_NAME) -> list[dict]:
    """Decision records whose session_id (a session_ref) matches *ref*."""
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", "200", container],
            capture_output=True,
            text=True,
            timeout=5,
        )
        records = []
        for line in (result.stdout + result.stderr).splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
                if d.get("session_id") == ref and "features" in d:
                    records.append(d)
            except json.JSONDecodeError:
                pass
        return records
    except Exception:
        return []


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("DEMO_PORT", "8003")))
