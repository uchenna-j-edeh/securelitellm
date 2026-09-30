"""Deterministic mock OpenAI-compatible completion server.

Serves /v1/chat/completions with scripted or echo responses so tests and eval
runs never depend on paid APIs.

Scripted mode: set MOCK_SCRIPT env var to a JSON file path.
The file is a list of response objects served in round-robin order.
This allows scenarios to inject tool calls or specific content.
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
        {
            "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": body.get("model", "mock"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": f"[mock] {last_content}"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
