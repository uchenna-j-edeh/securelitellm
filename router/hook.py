"""LiteLLM CustomLogger implementing async_pre_call_hook and async_post_call_success_hook.

Registered in litellm_config.yaml under litellm_settings.callbacks.
M1 — pass-through that logs a structured decision record per request.
M2 — session ID hardened; session taint store wired; L0/L1 features populated;
     async_post_call_success_hook added to close the taint loop.
M3/M4 — classifier calls and policy enforcement added in later milestones.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Any

from litellm.integrations.custom_logger import CustomLogger

from router.config import RouterConfig
from router.logger import DecisionLogger
from router.parser import extract_tool_context
from router.session import get_store
from router.taint import classify_sinks, classify_sources, tainted_spans_in_sink_args


def _derive_session_id(data: dict, request_id: str) -> str:
    headers = data.get("metadata", {}).get("headers", {}) or {}
    run_id = headers.get("x-agent-run-id", "").strip()
    return run_id if run_id else f"no-session-{request_id[:8]}"


def _extract_features(
    session_id: str,
    messages: list[dict],
    level: str,
    mode: str,
) -> dict[str, Any]:
    sources = classify_sources(messages)
    sinks = classify_sinks(messages)

    # L0 — bare boolean flags
    features: dict[str, Any] = {
        "untrusted_seen": False,
        "sink_requested": len(sinks) > 0,
    }

    if mode == "session":
        store = get_store()
        state = store.state(session_id)
        features["untrusted_seen"] = state.tainted or len(sources) > 0
    else:
        # Stateless: per-request only, no session state
        features["untrusted_seen"] = len(sources) > 0

    if level in ("L1", "L2", "L3"):
        features["source_ids"] = [s["tool_call_id"] for s in sources]
        features["source_trust_tiers"] = {
            s["tool_call_id"]: s["trust_tier"] for s in sources if s["tool_call_id"]
        }

    if level == "L3" and mode == "session":
        store = get_store()
        state = store.state(session_id)
        features["tainted_spans_in_sink_args"] = tainted_spans_in_sink_args(
            state.tainted_spans, sinks, messages
        )

    return features


class RouterHook(CustomLogger):
    def __init__(self) -> None:
        super().__init__()
        self.config = RouterConfig.from_env()
        self.decision_logger = DecisionLogger(self.config.log_path)

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> dict:
        t0 = time.perf_counter()

        request_id = data.get("litellm_call_id") or str(uuid.uuid4())
        session_id = _derive_session_id(data, request_id)
        messages = data.get("messages", [])

        features = _extract_features(session_id, messages, self.config.level, self.config.mode)

        # Record sources into session store (session mode only)
        if self.config.mode == "session":
            store = get_store()
            for src in classify_sources(messages):
                store.record_source(session_id, src)

        tool_context = extract_tool_context(messages)
        latency_ms = round((time.perf_counter() - t0) * 1000, 3)

        self.decision_logger.emit(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "request_id": request_id,
                "mode": self.config.mode,
                "level": self.config.level,
                "features": features,
                "risk_score": 0.0,
                "action": "allow",
                "latency_ms": latency_ms,
                "tool_context": tool_context,
            }
        )

        return data  # pass-through until M4 policy enforcement

    async def async_post_call_success_hook(
        self,
        user_api_key_dict: Any,
        data: dict,
        response: Any,
    ) -> None:
        """Sink Inspector — closes the taint loop after the LLM responds.

        Extracts any tool calls in the response (egress sinks) and records
        them in the session taint store so subsequent turns see the full
        source→sink chain.
        """
        if self.config.mode != "session":
            return

        request_id = data.get("litellm_call_id") or ""
        session_id = _derive_session_id(data, request_id)

        # Extract tool calls from the response choices
        egress_sinks = _extract_response_sinks(response)
        if not egress_sinks:
            return

        store = get_store()
        for sink in egress_sinks:
            store.record_sink(session_id, sink)


def _extract_response_sinks(response: Any) -> list[dict[str, Any]]:
    """Pull tool_calls out of a LiteLLM completion response object."""
    from router.taint import _sink_category

    sinks = []
    try:
        choices = getattr(response, "choices", None) or []
        for choice in choices:
            msg = getattr(choice, "message", None)
            if msg is None:
                continue
            tool_calls = getattr(msg, "tool_calls", None) or []
            for call in tool_calls:
                fn = getattr(call, "function", None)
                if fn is None:
                    continue
                name = getattr(fn, "name", "") or ""
                sinks.append(
                    {
                        "id": getattr(call, "id", None),
                        "name": name,
                        "category": _sink_category(name),
                        "args_length": len(getattr(fn, "arguments", "") or ""),
                    }
                )
    except Exception:
        pass
    return sinks


# Module-level instance — LiteLLM config callbacks must point at an instance, not a class.
proxy_handler_instance = RouterHook()
