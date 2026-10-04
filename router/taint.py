"""Source/sink classification and taint model.

Sources — role=tool messages: untrusted content flowing into the agent context
  (tool outputs, MCP server responses, retrieved documents).

Sinks — role=assistant messages with tool_calls whose function names indicate
  egress capability (email, webhook, HTTP POST, file write, etc.).

Trust tiers (L1):
  "internal"  — first-party tool defined in the system config (trusted)
  "retrieval" — RAG / search result (untrusted external content)
  "mcp"       — MCP server output (untrusted third-party)
  "tool"      — generic tool output (default; treat as untrusted)

Sink categories:
  "exfil"  — can transmit data externally (email, webhook, HTTP)
  "write"  — can persist data (file, database)
  "read"   — read-only; not an exfil risk
  "other"  — unknown capability
"""

from typing import Any

# Known sink function-name prefixes/substrings → category.
# Extend as the corpus grows.
_EXFIL_PATTERNS = (
    "send_email",
    "send_message",
    "send_mail",
    "post_webhook",
    "http_post",
    "http_request",
    "upload",
    "exfil",
    "forward",
    "slack_post",
    "teams_post",
    "discord_send",
)

_WRITE_PATTERNS = (
    "write_file",
    "save_file",
    "append_file",
    "db_insert",
    "db_update",
    "sql_exec",
    "create_record",
    "update_record",
)

_READ_PATTERNS = (
    "read_file",
    "read_email",
    "search",
    "query",
    "get_",
    "fetch_",
    "list_",
    "retrieve_",
)


def _sink_category(fn_name: str) -> str:
    name = fn_name.lower()
    for pat in _EXFIL_PATTERNS:
        if pat in name:
            return "exfil"
    for pat in _WRITE_PATTERNS:
        if pat in name:
            return "write"
    for pat in _READ_PATTERNS:
        if any(name.startswith(p) or p in name for p in _READ_PATTERNS):
            return "read"
    return "other"


def classify_sources(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract role=tool messages as source candidates with trust tier."""
    sources = []
    for msg in messages:
        if msg.get("role") != "tool":
            continue
        content = msg.get("content", "")
        sources.append(
            {
                "tool_call_id": msg.get("tool_call_id"),
                "trust_tier": _infer_trust_tier(msg),
                "content_length": len(str(content)),
                "content_preview": str(content)[:120],
            }
        )
    return sources


def classify_sinks(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract assistant tool_calls that have egress capability."""
    sinks = []
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        for call in msg.get("tool_calls") or []:
            fn = call.get("function", {})
            name = fn.get("name", "")
            sinks.append(
                {
                    "id": call.get("id"),
                    "name": name,
                    "category": _sink_category(name),
                    "args_length": len(fn.get("arguments", "")),
                }
            )
    return sinks


def tainted_spans_in_sink_args(
    tainted_spans: list[str],
    sinks: list[dict[str, Any]],
    messages: list[dict[str, Any]],
) -> bool:
    """L3: check if any tainted content hash appears in a sink's arguments.

    Checks both the whole args string and individual string values inside the
    parsed JSON object — so {"body": "PAYLOAD"} matches SHA-256("PAYLOAD").
    """
    import hashlib
    import json

    # Build a map of sink id -> raw args from the message list
    sink_args: dict[str, str] = {}
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        for call in msg.get("tool_calls") or []:
            sid = call.get("id", "")
            sink_args[sid] = call.get("function", {}).get("arguments", "")

    span_set = set(tainted_spans)

    for args in sink_args.values():
        # Check whole args string
        if hashlib.sha256(args.encode()).hexdigest() in span_set:
            return True
        # Check each string value inside a JSON object
        try:
            parsed = json.loads(args)
            values = parsed.values() if isinstance(parsed, dict) else [parsed]
            for v in values:
                if hashlib.sha256(str(v).encode()).hexdigest() in span_set:
                    return True
        except (json.JSONDecodeError, AttributeError):
            pass
    return False


def _infer_trust_tier(msg: dict[str, Any]) -> str:
    # Future: inspect msg metadata (server name, tool registry) for real tier.
    # For now, all tool outputs default to "tool" (untrusted).
    meta = msg.get("metadata") or {}
    server = meta.get("mcp_server")
    if server:
        return "mcp"
    source_type = meta.get("source_type", "")
    if source_type == "retrieval":
        return "retrieval"
    if source_type == "internal":
        return "internal"
    return "tool"
