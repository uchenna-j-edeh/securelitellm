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

import hashlib
import json
from typing import Any, Iterator

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
    if any(name.startswith(pattern) or pattern in name for pattern in _READ_PATTERNS):
        return "read"
    return "other"


def _sink_result_ids(messages: list[dict[str, Any]]) -> set[str]:
    """tool_call_ids whose originating assistant call is an exfil/write sink.

    A sink's own result (e.g. {"status": "sent"}) is first-party scaffolding —
    a receipt the agent produced, not untrusted external content. Scanning it as
    a source both (a) feeds out-of-distribution JSON to the injection classifier,
    which false-positives on it, and (b) wrongly marks the session as having seen
    untrusted content. Read-tool results (file/web/search) are NOT excluded —
    those carry the genuinely untrusted external content we must scan.
    """
    sink_ids: set[str] = set()
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        for call in msg.get("tool_calls") or []:
            name = call.get("function", {}).get("name", "")
            if _sink_category(name) in ("exfil", "write"):
                cid = call.get("id")
                if cid:
                    sink_ids.add(cid)
    return sink_ids


# Strings inside JSON can themselves be JSON (a tool that returns another
# tool's output); decode that far, no further.
_MAX_JSON_DEPTH = 3


def _text_parts(content: Any) -> str | None:
    """The text of list-of-parts content, or None if *content* is not a list of parts."""
    if not isinstance(content, list):
        return None
    return "\n".join(
        part["text"]
        for part in content
        if isinstance(part, dict) and isinstance(part.get("text"), str)
    )


def _json_strings(value: Any, depth: int) -> Iterator[str]:
    """Every string in a decoded JSON value, keys included; strings that are JSON are decoded too."""
    if isinstance(value, str):
        decoded = _decode_json(value, depth)
        if decoded is None:
            yield value
        else:
            yield from _json_strings(decoded, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _json_strings(item, depth)
    elif isinstance(value, list):
        for item in value:
            yield from _json_strings(item, depth)
    # Numbers, booleans and null carry no instructions.


def _decode_json(text: str, depth: int) -> Any:
    """*text* parsed as a JSON object or array, or None if it is not one (or too deep)."""
    stripped = text.strip()
    if depth >= _MAX_JSON_DEPTH or not stripped.startswith(("{", "[")):
        return None
    try:
        return json.loads(stripped)
    except ValueError:
        return None


def classifier_text(content: Any) -> str:
    """The text the injection classifier should read for a tool result (#189).

    The classifier is trained on natural text. JSON-encoded tool results reach
    it as escaped blobs (literal \\n, \\u2014, braces and keys), which it scores
    as injections even when the text is benign. So a JSON object or array is
    replaced by its strings, one per line, keys included because a tool's
    output can put attacker text in a key. List-of-parts content becomes its
    text. Anything else is classified as is. Nothing is dropped except
    numbers, booleans and null. Only the classifier's input changes: the
    model, taint hashes and the sensitive-data detectors see the original.
    """
    parts = _text_parts(content)
    text = parts if parts is not None else str(content if content is not None else "")
    decoded = _decode_json(text, 0)
    if decoded is None:
        return text
    return "\n".join(_json_strings(decoded, 1))


def classify_sources(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract role=tool messages as source candidates with trust tier.

    Sink-result echoes are tagged trust_tier="internal" (trusted first-party
    scaffolding) so downstream scanning treats them as safe — see
    _sink_result_ids.
    """
    sink_result_ids = _sink_result_ids(messages)
    sources = []
    for msg in messages:
        if msg.get("role") != "tool":
            continue
        content = str(msg.get("content", ""))
        # A sink's own confirmation is first-party scaffolding, not untrusted
        # external content — mark it trusted so it is never scanned or tainted.
        if msg.get("tool_call_id") in sink_result_ids:
            trust_tier = "internal"
        else:
            trust_tier = _infer_trust_tier(msg)
        sources.append(
            {
                "tool_call_id": msg.get("tool_call_id"),
                "trust_tier": trust_tier,
                "content_length": len(content),
                "content_for_classifier": classifier_text(msg.get("content")),
                "content_hash": hashlib.sha256(content.encode()).hexdigest(),
            }
        )
    return sources


def is_trusted_source(source: dict[str, Any]) -> bool:
    """True for first-party sources that must never be scanned or tainted."""
    return source.get("trust_tier") == "internal"


def classify_sinks(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract assistant tool calls that can write, transmit, or have unknown capability.

    Known read-only tools are deliberately excluded. Unknown tools remain sinks so
    a new or misspelled function name fails closed instead of bypassing policy.
    """
    sinks = []
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        for call in msg.get("tool_calls") or []:
            fn = call.get("function", {})
            name = fn.get("name", "")
            category = _sink_category(name)
            if category == "read":
                continue
            sinks.append(
                {
                    "id": call.get("id"),
                    "name": name,
                    "category": category,
                    "args_length": len(fn.get("arguments", "")),
                }
            )
    return sinks


# Deepest JSON nesting accepted in tool arguments. json.loads recurses per
# level in C; very deep input overflows the stack on platforms with small
# thread stacks (Windows) and crashes the process instead of raising.
MAX_ARGUMENT_DEPTH = 64


_NON_BRACKET_BYTES = bytes(b for b in range(256) if b not in b"[]{}")
_TO_SQUARE = bytes.maketrans(b"{}", b"[]")


def _exceeds_depth(text: str, limit: int = MAX_ARGUMENT_DEPTH) -> bool:
    """True if JSON *text* may nest objects/arrays deeper than *limit*.

    Conservative: brackets inside string literals are counted too, so text
    whose strings carry more than *limit* unbalanced brackets is reported as
    well — that only fails closed. Runs in C: keep only the brackets, then
    peel one level of innermost "[]" pairs per pass.
    """
    if text.count("[") + text.count("{") <= limit:
        return False
    brackets = text.encode("utf-8", "surrogatepass").translate(_TO_SQUARE, _NON_BRACKET_BYTES)
    for depth in range(limit + 1):
        reduced = brackets.replace(b"[]", b"")
        if reduced == brackets:
            # Left over: "]"*a + "["*b — b unclosed opens wrap the matched depth.
            return depth + reduced.count(b"[") > limit
        brackets = reduced
    return True


def tool_call_defect(name: Any, arguments: Any) -> str | None:
    """Why a generated tool call cannot be inspected, or None if it can (#82, #156).

    A call must have a non-empty string name, and its arguments must be empty
    (a no-argument call) or a JSON object nested at most MAX_ARGUMENT_DEPTH
    levels. Anything else is malformed: the caller fails closed instead of
    treating the call as safe or absent.
    """
    if not isinstance(name, str) or not name.strip():
        return "missing_name"
    if arguments is None:
        return None
    if not isinstance(arguments, str):
        return "arguments_not_string"
    if not arguments.strip():
        return None
    if _exceeds_depth(arguments):
        return "too_deep"
    try:
        parsed = json.loads(arguments)
    except (json.JSONDecodeError, RecursionError):
        return "invalid_json"
    if not isinstance(parsed, dict):
        return "arguments_not_object"
    return None


def tainted_spans_in_sink_args(
    tainted_spans: list[str],
    sinks: list[dict[str, Any]],
    messages: list[dict[str, Any]],
) -> bool:
    """L3: check if any tainted content hash appears in a sink's arguments.

    Checks both the whole args string and individual string values inside the
    parsed JSON object — so {"body": "PAYLOAD"} matches SHA-256("PAYLOAD").
    """
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
        if _exceeds_depth(args):
            continue  # never parsed; post-call holds it as malformed (too_deep)
        try:
            parsed = json.loads(args)
            for value in _iter_string_values(parsed):
                if hashlib.sha256(value.encode()).hexdigest() in span_set:
                    return True
        except (json.JSONDecodeError, RecursionError, AttributeError):
            pass
    return False


def _iter_string_values(value: Any) -> Iterator[str]:
    """Yield strings recursively from decoded JSON tool arguments."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from _iter_string_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _iter_string_values(nested)


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
