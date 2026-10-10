"""LiteLLM CustomLogger implementing async_pre_call_hook and async_post_call_success_hook.

Registered in litellm_config.yaml under litellm_settings.callbacks.
M1 — pass-through that logs a structured decision record per request.
M2 — session ID hardened; session taint store wired; L0/L1 features populated;
     async_post_call_success_hook added to close the taint loop.
M3 — classifier integrated at L2/L3; classifier_verdicts added to features.
M4 — policy engine wired; routing actions allow/route-hardened/strip-tools/block.
M5 — generated non-streaming tool calls are re-evaluated before release and
     mapped to execute/hold/block; streaming tool requests fail closed.
"""

import asyncio
import copy
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from litellm.integrations.custom_logger import CustomLogger

from router.classifiers.base import BaseClassifier
from router.config import RouterConfig
from router.logger import DecisionLogger
from router.parser import extract_tool_context
from router.policy import PolicyEngine, PolicyViolation
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
        # Session mode: untrusted_seen only when content was actually flagged as
        # tainted (by classifier or fail-closed without classifier). This prevents
        # clean read→write flows from triggering false positives.
        features["untrusted_seen"] = state.tainted
    else:
        # Stateless: no session memory, fall back to structural signal
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
        self._classifier: BaseClassifier | None = _init_classifier(self.config.classifier_backend)
        self._policy = PolicyEngine.from_yaml(self.config.policy_path or None)
        self.decision_logger.emit(self.config.startup_record())

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
        features["streaming_tool_request"] = bool(data.get("stream") and data.get("tools"))

        sources = classify_sources(messages)
        classifier_verdicts: list[dict] = []

        # Classifier is mandatory whenever tool results are present.
        # No valid production path bypasses classification.
        if sources and self._classifier is None:
            import litellm.exceptions as _le

            raise _le.BadRequestError(
                message=(
                    "SecureLiteLLM: classifier is required but not configured. "
                    "Set CLASSIFIER_BACKEND and ensure the classifier sidecar is reachable."
                ),
                model=data.get("model", ""),
                llm_provider="",
            )

        # Run classifier on ALL levels (not only L2/L3) when sources are present.
        if sources and self._classifier is not None:
            classifier_verdicts = await _classify_sources(self._classifier, sources)
            features["classifier_verdicts"] = classifier_verdicts
            features["classifier_injection"] = any(
                v.get("label") == "INJECTION" for v in classifier_verdicts
            )
            features["classifier_error"] = any(
                v.get("label") == "UNKNOWN" for v in classifier_verdicts
            )

        # Record sources into session store (session mode only).
        # With classifier:    only taint sources flagged INJECTION — clean content passes through.
        # Without classifier: taint all sources (fail-closed, same as before).
        if self.config.mode == "session":
            store = get_store()
            injected_ids = {
                v["source_id"] for v in classifier_verdicts if v.get("label") == "INJECTION"
            }
            for src in sources:
                taint = not classifier_verdicts or src.get("tool_call_id") in injected_ids
                store.record_source(session_id, src, taint=taint)
            # Refresh after recording so the logged feature and policy both see
            # taint set by tool results in the current request.
            features["untrusted_seen"] = store.state(session_id).tainted

        # M4: evaluate policy rules → risk score → action
        risk_score, action, matched_rules = self._policy.evaluate(features)

        # Escalation counter (session mode only, non-allow actions)
        escalation_count = 0
        if self.config.mode == "session" and action != "allow":
            escalation_count = get_store().record_escalation(session_id)
            features["escalation_count"] = escalation_count

        tool_context = extract_tool_context(messages)
        latency_ms = round((time.perf_counter() - t0) * 1000, 3)

        self.decision_logger.emit(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "phase": "pre_call",
                "session_id": session_id,
                "request_id": request_id,
                "mode": self.config.mode,
                "level": self.config.level,
                "features": features,
                "risk_score": round(risk_score, 4),
                "action": action,
                "matched_rules": matched_rules,
                "enforce": self.config.enforce,
                "latency_ms": latency_ms,
                "tool_context": tool_context,
            }
        )

        # Audit mode: log action but always pass through
        if not self.config.enforce:
            return data

        # Enforcement
        if action == "block":
            import litellm.exceptions as _le

            raise _le.BadRequestError(
                message=str(PolicyViolation(risk_score, matched_rules)),
                model=data.get("model", ""),
                llm_provider="",
            )

        if action == "strip-tools":
            data = dict(data)
            data.pop("tools", None)
            # Explicitly forbid tool use so the model produces a text response
            # instead of generating a tool call that the API will reject.
            data["tool_choice"] = "none"

        if action == "route-hardened":
            data = dict(data)
            data["model"] = self.config.hardened_model

        return data

    async def async_post_call_success_hook(
        self,
        user_api_key_dict: Any,
        data: dict,
        response: Any,
    ) -> Any:
        """Inspect generated tool calls before a non-streaming response is released.

        Safe calls are returned unchanged. Moderate-risk calls are held by
        removing them from the response. Confirmed source-to-sink chains are
        blocked by raising PolicyViolation. Streaming tool requests are blocked
        in the pre-call hook because CustomLogger post-call streaming callbacks
        run after content has already reached the client.
        """
        request_id = data.get("litellm_call_id") or ""
        session_id = _derive_session_id(data, request_id)
        messages = data.get("messages", [])

        egress_sinks = _extract_response_sinks(response)
        if not egress_sinks:
            return None

        features = _extract_features(session_id, messages, self.config.level, self.config.mode)
        features["sink_requested"] = True
        features["streaming_tool_request"] = False

        sources = classify_sources(messages)
        if sources and self._classifier is not None:
            verdicts = await _classify_sources(self._classifier, sources)
            features["classifier_verdicts"] = verdicts
            features["classifier_injection"] = any(
                verdict.get("label") == "INJECTION" for verdict in verdicts
            )
            features["classifier_error"] = any(
                verdict.get("label") == "UNKNOWN" for verdict in verdicts
            )

        if self.config.level == "L3":
            if self.config.mode == "session":
                tainted_hashes = get_store().state(session_id).tainted_spans
            else:
                tainted_hashes = [source["content_hash"] for source in sources]
            features["tainted_spans_in_sink_args"] = tainted_spans_in_sink_args(
                tainted_hashes,
                egress_sinks,
                [_response_sink_message(egress_sinks)],
            )

        risk_score, policy_action, matched_rules = self._policy.evaluate(features)
        output_action = _output_action(policy_action)

        if self.config.mode == "session":
            store = get_store()
            for sink in egress_sinks:
                store.record_sink(session_id, _public_sink(sink))
            if policy_action != "allow":
                features["escalation_count"] = store.record_escalation(session_id)

        self.decision_logger.emit(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "phase": "post_call",
                "session_id": session_id,
                "request_id": request_id,
                "mode": self.config.mode,
                "level": self.config.level,
                "features": features,
                "risk_score": round(risk_score, 4),
                "action": output_action,
                "policy_action": policy_action,
                "matched_rules": matched_rules,
                "enforce": self.config.enforce,
                "tool_context": {
                    "generated_tool_call_count": len(egress_sinks),
                    "generated_tool_calls": [_public_sink(sink) for sink in egress_sinks],
                },
            }
        )

        if not self.config.enforce or policy_action == "allow":
            return None
        if policy_action == "block":
            import litellm.exceptions as _le

            raise _le.BadRequestError(
                message=str(PolicyViolation(risk_score, matched_rules)),
                model=data.get("model", ""),
                llm_provider="",
            )
        return _hold_response_tool_calls(response, risk_score, matched_rules)


def _init_classifier(backend: str) -> BaseClassifier | None:
    """Instantiate a configured classifier and fail closed on setup errors."""
    if backend == "none":
        return None
    try:
        from router.classifiers import get_classifier

        return get_classifier()
    except Exception as exc:
        raise RuntimeError(
            f"Failed to initialize configured classifier backend {backend!r}"
        ) from exc


async def _classify_sources(
    classifier: BaseClassifier,
    sources: list[dict],
) -> list[dict]:
    """Run safe_classify on each source's content concurrently."""

    async def _one(src: dict) -> dict:
        content = src.get("content_for_classifier", "") or ""
        result = await classifier.safe_classify(content)
        verdict = classifier.to_verdict(result)
        verdict["source_id"] = src.get("tool_call_id")
        return verdict

    return await asyncio.gather(*[_one(s) for s in sources])


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
                category = _sink_category(name)
                if category == "read":
                    continue
                arguments = getattr(fn, "arguments", "") or ""
                sinks.append(
                    {
                        "id": getattr(call, "id", None),
                        "name": name,
                        "category": category,
                        "args_length": len(arguments),
                        "_arguments": arguments,
                    }
                )
    except Exception:
        pass
    return sinks


def _response_sink_message(sinks: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "role": "assistant",
        "tool_calls": [
            {
                "id": sink.get("id"),
                "type": "function",
                "function": {
                    "name": sink.get("name", ""),
                    "arguments": sink.get("_arguments", ""),
                },
            }
            for sink in sinks
        ],
    }


def _public_sink(sink: dict[str, Any]) -> dict[str, Any]:
    """Drop raw arguments before logging or retaining a sink."""
    return {key: value for key, value in sink.items() if not key.startswith("_")}


def _output_action(policy_action: str) -> str:
    if policy_action == "allow":
        return "execute"
    if policy_action == "block":
        return "block"
    return "hold"


def _hold_response_tool_calls(
    response: Any,
    risk_score: float,
    matched_rules: list[str],
) -> Any:
    """Return a copy of a response with generated tool calls removed."""
    held = copy.deepcopy(response)
    reason = ", ".join(matched_rules) or "policy review"
    notice = (
        "SecureLiteLLM held the generated tool call for review "
        f"(risk={risk_score:.3f}; rules={reason})."
    )

    for choice in getattr(held, "choices", None) or []:
        message = getattr(choice, "message", None)
        if message is None or not (getattr(message, "tool_calls", None) or []):
            continue
        message.tool_calls = None
        message.content = notice
        if hasattr(choice, "finish_reason"):
            choice.finish_reason = "content_filter"
    return held


# Module-level instance — LiteLLM config callbacks must point at an instance, not a class.
proxy_handler_instance = RouterHook()
