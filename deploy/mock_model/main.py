"""Deterministic mock OpenAI-compatible completion server.

Serves /v1/chat/completions with scripted or echo responses so tests and eval
runs never depend on paid APIs.

Scripted mode: set MOCK_SCRIPT env var to a JSON file path.
The file is a list of response objects served in round-robin order.
This allows scenarios to inject tool calls or specific content.

Per-request replies (#177): a request carrying a "mock_reply" assistant message
gets exactly that reply. The eval harness sends each scripted turn's reply this
way (LiteLLM forwards unknown top-level keys but drops the OpenAI "user" field).
Like a real provider, the mock does not return tool calls to a request that
offers no tools or sets tool_choice "none" (the quarantine route): it returns
the reply's text instead.
"""

import json
import os
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="mock-model")

_script: list[dict] = []
_call_index = 0
MOCK_REPLY_KEY = "mock_reply"
_NO_TOOLS_TEXT = "[mock] no tools available"


@app.on_event("startup")
def load_script() -> None:
    global _script
    path = os.getenv("MOCK_SCRIPT", "")
    if path and os.path.isfile(path):
        with open(path) as f:
            _script = json.load(f)


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    global _call_index
    body = await request.json()

    if isinstance(body.get(MOCK_REPLY_KEY), dict):
        return JSONResponse(_completion(body, _scripted_message(body, body[MOCK_REPLY_KEY])))

    if _script:
        response = _script[_call_index % len(_script)]
        _call_index += 1
        return JSONResponse(response)

    last_content = ""
    for msg in reversed(body.get("messages", [])):
        if msg.get("role") == "user" and msg.get("content"):
            last_content = str(msg["content"])[:120]
            break

    return JSONResponse(
        _completion(body, {"role": "assistant", "content": f"[mock] {last_content}"})
    )


def _scripted_message(body: dict, reply: dict) -> dict:
    """The scripted assistant message, minus tool calls the request did not allow."""
    tool_calls = reply.get("tool_calls")
    if tool_calls and body.get("tools") and body.get("tool_choice") != "none":
        return {"role": "assistant", "content": reply.get("content"), "tool_calls": tool_calls}
    return {"role": "assistant", "content": reply.get("content") or _NO_TOOLS_TEXT}


def _completion(body: dict, message: dict) -> dict:
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model", "mock"),
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if message.get("tool_calls") else "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
