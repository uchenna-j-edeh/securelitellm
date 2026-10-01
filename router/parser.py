"""Extract tool call and tool result context from OpenAI-style message arrays.

role=tool messages  → source candidates (untrusted content flowing in)
role=assistant with tool_calls → sink candidates (exfil-capable actions going out)
"""

from typing import Any


def extract_tool_context(messages: list[dict[str, Any]]) -> dict[str, Any]:
    tool_results: list[dict] = []
    tool_calls: list[dict] = []

    for msg in messages:
        role = msg.get("role", "")

        if role == "tool":
            tool_results.append(
                {
                    "tool_call_id": msg.get("tool_call_id"),
                    "content_length": len(str(msg.get("content", ""))),
                }
            )

        elif role == "assistant":
            for call in msg.get("tool_calls") or []:
                fn = call.get("function", {})
                tool_calls.append(
                    {
                        "id": call.get("id"),
                        "name": fn.get("name"),
                        "args_length": len(fn.get("arguments", "")),
                    }
                )

    return {
        "tool_result_count": len(tool_results),
        "tool_call_count": len(tool_calls),
        "tool_results": tool_results,
        "tool_calls": tool_calls,
    }
