"""Tool schemas and HTTP client used by the demo agent.

The implementations live in ``demo/mcp_server.py`` and are reached over HTTP.
The service is intentionally MCP-shaped but is not a wire-compatible MCP server;
keeping the transport explicit avoids claiming an integration the demo does not have.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

TOOL_SERVER_URL = os.environ.get("DEMO_TOOL_SERVER_URL", "http://localhost:8002").rstrip("/")
TOOL_TIMEOUT_SECONDS = float(os.environ.get("DEMO_TOOL_TIMEOUT_SECONDS", "20"))

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": (
                "Fetch exactly one URL and return its readable text. Do not follow page links."
            ),
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "URL to fetch."}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the demo corpus for a named report.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read a company workspace file. Available files include "
                "annual_report.txt, quarterly_report.txt and employee_record.txt."
            ),
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "File basename."}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_knowledge_base",
            "description": "Search the demo knowledge base.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_mcp_resources",
            "description": "List resources advertised by a demo MCP server.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_emails",
            "description": (
                "List emails in the demo inbox label, newest first: id, sender, subject, "
                "date and a snippet. Optionally filter with a Gmail search query."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Gmail search, e.g. from:x"},
                    "max_results": {"type": "integer", "description": "1-25, default 10."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_email",
            "description": "Read one email from the demo inbox label by its id.",
            "parameters": {
                "type": "object",
                "properties": {"message_id": {"type": "string"}},
                "required": ["message_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_jira",
            "description": (
                "Search tickets in the demo Jira project: key, summary, status, assignee. "
                "Leave query empty for the most recently updated tickets."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer", "description": "1-25, default 10."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_jira_issue",
            "description": "Read one Jira ticket by key, e.g. DEMO-12: description and comments.",
            "parameters": {
                "type": "object",
                "properties": {"issue_key": {"type": "string"}},
                "required": ["issue_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_github_issues",
            "description": (
                "List issues in the demo GitHub repository, most recently updated first. "
                "Optionally search their text."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "state": {"type": "string", "enum": ["open", "closed", "all"]},
                    "max_results": {"type": "integer", "description": "1-25, default 10."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_github_issue",
            "description": "Read one GitHub issue by number: body and comments.",
            "parameters": {
                "type": "object",
                "properties": {"number": {"type": "integer"}},
                "required": ["number"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email to one approved demo recipient.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_post",
            "description": "Send data via HTTP POST to an external URL.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "data": {"type": "string"},
                },
                "required": ["url", "data"],
            },
        },
    },
]

_TOOL_NAMES = {schema["function"]["name"] for schema in TOOL_SCHEMAS}


def call_tool(
    name: str,
    args: dict[str, Any],
    *,
    base_url: str | None = None,
) -> dict[str, Any]:
    """Execute a named tool through the separate demo tool service."""
    if name not in _TOOL_NAMES:
        return {"error": f"unknown tool: {name}"}

    url = f"{(base_url or TOOL_SERVER_URL).rstrip('/')}/tools/{name}"
    try:
        response = httpx.post(url, json=args, timeout=TOOL_TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, dict) else {"result": payload}
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json().get("detail", exc.response.text)
        except Exception:
            detail = exc.response.text
        return {"error": f"tool service returned HTTP {exc.response.status_code}: {detail}"}
    except Exception as exc:
        return {"error": f"tool service unavailable: {exc}"}
