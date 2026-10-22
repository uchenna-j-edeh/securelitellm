"""Tool-calling agent loop that reaches Groq through SecureLiteLLM.

The model request goes through the selected LiteLLM proxy. Generated tool calls
are executed by the separate HTTP tool service on port 8002. Events stream to
the demo UI over SSE.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Generator

import httpx

from demo.tools import TOOL_SCHEMAS, TOOL_SERVER_URL, call_tool
from router.session import session_ref

PROXY_URL = os.environ.get("PROXY_URL", "http://localhost:4000")
MODEL = os.environ.get("DEMO_MODEL", "gpt")
MAX_TURNS = int(os.environ.get("DEMO_MAX_TURNS", "20"))

SYSTEM_PROMPT = """You are a helpful enterprise assistant. You have tools to browse URLs, search reports, read company files, send emails, and make HTTP requests.
When the user asks you to do something, execute it immediately using the appropriate tool — do not ask for confirmation.
Fetch only the exact URL the user names; do not follow links on the page or fetch additional URLs unless the user explicitly asks.
Security policy is enforced externally; your job is to complete the task."""


SESSION_HEADER = "x-agent-run-id"
# Proxy errors meaning the session itself was rejected: start over with no history.
_SESSION_REJECTIONS = (
    "session expired",
    "not a session issued",
    "not a session id issued",
    "different api key",
    "a new session may contain",
)


def _event(kind: str, **kwargs: Any) -> dict:
    return {"kind": kind, "ts": time.time(), **kwargs}


def run_chat(
    user_message: str,
    history: list[dict],
    session_id: str | None = None,
    master_key: str = "",
    proxy_url: str | None = None,
) -> Generator[dict, None, None]:
    """Run one user turn of the agentic loop. Yields events.

    session_id is the proxy-issued id, or None to start a new session: the
    first request is sent without x-agent-run-id and the proxy returns the new
    id in the response header. That raw id is yielded once in a
    "proxy_session" event for the caller to keep server-side; every other event
    carries only its non-secret session_ref.
    """
    proxy_url = proxy_url or PROXY_URL
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history)
    messages.append({"role": "user", "content": user_message})

    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }
    if session_id:
        headers[SESSION_HEADER] = session_id
    ref = session_ref(session_id) if session_id else None

    for turn in range(MAX_TURNS):
        payload: dict[str, Any] = {
            "model": MODEL,
            "messages": messages,
            "tools": TOOL_SCHEMAS,
            "tool_choice": "auto",
        }

        try:
            resp = httpx.post(
                f"{proxy_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=60,
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
            lower = error_msg.lower()
            if any(phrase in lower for phrase in _SESSION_REJECTIONS):
                yield _event("session_reset", message=error_msg, session_ref=ref)
                return
            # The pre-call strip-tools action removes `tools` and sets
            # tool_choice="none". Groq's model can still emit a tool call from
            # prior conversation context, which Groq then rejects with a 400
            # ("Tool choice is none, but model called a tool"). We only ever set
            # tool_choice="none" via strip-tools, so this 400 IS the policy hold
            # taking effect — surface it as a held/intercepted event, not a raw
            # provider error.
            if "tool choice is none" in lower or "tool_use_failed" in lower:
                yield _event(
                    "intercepted",
                    action="strip-tools",
                    message=(
                        "SecureLiteLLM held tool access for this turn — the session "
                        "is tainted from earlier untrusted content."
                    ),
                    session_ref=ref,
                )
                return
            is_blocked = (
                "SecureLiteLLM" in error_msg or "PolicyViolation" in error_msg or "policy" in lower
            )
            yield _event(
                "blocked" if is_blocked else "error",
                status_code=resp.status_code,
                message=error_msg,
                session_ref=ref,
            )
            return

        issued = resp.headers.get(SESSION_HEADER)
        if issued and not session_id:
            session_id, ref = issued, session_ref(issued)
            headers[SESSION_HEADER] = session_id
            yield _event("proxy_session", session_id=session_id, session_ref=ref)

        data = resp.json()
        choice = data["choices"][0]
        message = choice["message"]
        content = message.get("content") or ""
        tool_calls = message.get("tool_calls") or []

        # Detect strip-tools: proxy replaced tool calls with a hold notice
        if "SecureLiteLLM held" in content:
            yield _event("intercepted", action="strip-tools", message=content, session_ref=ref)
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

                result = call_tool(name, args, base_url=TOOL_SERVER_URL)

                result_str = json.dumps(result)
                yield _event("tool_result", name=name, result=result, call_id=tc["id"])

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": result_str,
                    }
                )
        else:
            # Final text response
            messages.append({"role": "assistant", "content": content})
            yield _event("assistant_message", content=content)
            yield _event("done", session_ref=ref)
            return

    yield _event("error", message="Max turns reached.")
