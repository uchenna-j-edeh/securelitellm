"""Agentic loop — drives Groq through the SecureLiteLLM proxy.

Tools are executed locally (no MCP server needed).
Yields structured events for consumption by the web UI via SSE.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any, Generator

import httpx

from demo.tools import TOOL_FN_MAP, TOOL_SCHEMAS

PROXY_URL = os.environ.get("PROXY_URL", "http://localhost:4000")
MODEL = os.environ.get("DEMO_MODEL", "groq")
MAX_TURNS = 8

SYSTEM_PROMPT = """You are a helpful enterprise assistant. You have tools to browse URLs, read company files, send emails, and make HTTP requests.
When the user asks you to do something, execute it immediately using the appropriate tool — do not ask for confirmation.
Security policy is enforced externally; your job is to complete the task."""


def _event(kind: str, **kwargs: Any) -> dict:
    return {"kind": kind, "ts": time.time(), **kwargs}


def run_chat(
    user_message: str,
    history: list[dict],
    session_id: str | None = None,
    master_key: str = "",
) -> Generator[dict, None, None]:
    """Run one user turn of the agentic loop. Yields events."""
    session_id = session_id or f"demo-{uuid.uuid4().hex[:8]}"
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history)
    messages.append({"role": "user", "content": user_message})

    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
        "x-agent-run-id": session_id,
    }

    yield _event("session_id", session_id=session_id)

    for turn in range(MAX_TURNS):
        payload: dict[str, Any] = {
            "model": MODEL,
            "messages": messages,
            "tools": TOOL_SCHEMAS,
            "tool_choice": "auto",
        }

        try:
            resp = httpx.post(
                f"{PROXY_URL}/chat/completions",
                json=payload,
                headers=headers,
                timeout=30,
            )
        except Exception as exc:
            yield _event("error", message=f"Proxy unreachable: {exc}")
            return

        if resp.status_code != 200:
            body = {}
            try:
                body = resp.json()
            except Exception:
                pass
            error_msg = body.get("error", {}).get("message", resp.text)
            is_blocked = (
                "SecureLiteLLM" in error_msg
                or "PolicyViolation" in error_msg
                or "policy" in error_msg.lower()
            )
            yield _event(
                "blocked" if is_blocked else "error",
                status_code=resp.status_code,
                message=error_msg,
                session_id=session_id,
            )
            return

        data = resp.json()
        choice = data["choices"][0]
        message = choice["message"]
        content = message.get("content") or ""
        tool_calls = message.get("tool_calls") or []

        # Detect strip-tools: proxy replaced tool calls with a hold notice
        if "SecureLiteLLM held" in content:
            yield _event("intercepted", action="strip-tools", message=content, session_id=session_id)
            return

        if tool_calls:
            messages.append({"role": "assistant", "content": None, "tool_calls": tool_calls})
            yield _event("assistant_tool_calls", tool_calls=tool_calls)

            for tc in tool_calls:
                fn = tc["function"]
                name = fn["name"]
                raw_args = fn.get("arguments", "{}")
                try:
                    args = json.loads(raw_args)
                except json.JSONDecodeError:
                    args = {}

                yield _event("tool_call", name=name, args=args, call_id=tc["id"])

                tool_fn = TOOL_FN_MAP.get(name)
                if tool_fn:
                    result = tool_fn(args)
                else:
                    result = {"error": f"unknown tool: {name}"}

                result_str = json.dumps(result)
                yield _event("tool_result", name=name, result=result, call_id=tc["id"])

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": result_str,
                })
        else:
            # Final text response
            messages.append({"role": "assistant", "content": content})
            yield _event("assistant_message", content=content)
            yield _event("done", session_id=session_id)
            return

    yield _event("error", message="Max turns reached.")
