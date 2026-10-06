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

from demo.agent import run_chat  # noqa: E402

DEMO_DIR = Path(__file__).parent
LOGS_DIR = DEMO_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

MASTER_KEY = os.environ.get("LITELLM_MASTER_KEY", "")
CONTAINER_NAME = os.environ.get("E2E_CONTAINER_NAME", "deploy-litellm-1")

app = FastAPI(title="SecureLiteLLM Demo")
app.mount("/static", StaticFiles(directory=str(DEMO_DIR / "static")), name="static")

# In-memory session store  {session_id: [messages]}
_sessions: dict[str, list[dict]] = {}


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((DEMO_DIR / "static" / "index.html").read_text())


@app.post("/chat")
async def chat(request: Request) -> StreamingResponse:
    body = await request.json()
    user_message: str = body.get("message", "").strip()
    session_id: str = body.get("session_id", "")

    if not user_message:
        return StreamingResponse(
            iter([f"data: {json.dumps({'kind': 'error', 'message': 'empty message'})}\n\n"]),
            media_type="text/event-stream",
        )

    history = _sessions.get(session_id, [])

    def stream():
        assistant_content = None
        tool_results_seen: list[dict] = []

        for event in run_chat(
            user_message=user_message,
            history=history,
            session_id=session_id,
            master_key=MASTER_KEY,
        ):
            yield f"data: {json.dumps(event)}\n\n"

            # Track assistant final message for history
            if event["kind"] == "assistant_message":
                assistant_content = event["content"]

        # Pull decision records for this session from container logs
        time.sleep(0.5)
        decisions = _decisions_for_session(session_id)
        for d in decisions:
            yield f"data: {json.dumps({'kind': 'decision', 'record': d})}\n\n"

        # Persist turn to session history
        if session_id:
            hist = _sessions.setdefault(session_id, [])
            hist.append({"role": "user", "content": user_message})
            if assistant_content:
                hist.append({"role": "assistant", "content": assistant_content})
            # Keep last 20 messages
            _sessions[session_id] = hist[-20:]

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
    return {"emails": [json.loads(l) for l in p.read_text().splitlines() if l.strip()][-20:]}


@app.get("/webhook_log")
async def webhook_log() -> dict:
    p = LOGS_DIR / "webhook_log.jsonl"
    if not p.exists():
        return {"posts": []}
    return {"posts": [json.loads(l) for l in p.read_text().splitlines() if l.strip()][-20:]}


@app.delete("/logs")
async def clear_logs() -> dict:
    for f in ["outbox.jsonl", "webhook_log.jsonl"]:
        p = LOGS_DIR / f
        if p.exists():
            p.unlink()
    return {"status": "cleared"}


def _decisions_for_session(session_id: str) -> list[dict]:
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", "200", CONTAINER_NAME],
            capture_output=True, text=True, timeout=5,
        )
        records = []
        for line in (result.stdout + result.stderr).splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
                if d.get("session_id") == session_id and "features" in d:
                    records.append(d)
            except json.JSONDecodeError:
                pass
        return records
    except Exception:
        return []


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("DEMO_PORT", "8003")))
