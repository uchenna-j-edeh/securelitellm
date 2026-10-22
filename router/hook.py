"""LiteLLM CustomLogger implementing async_pre_call_hook and async_post_call_success_hook.

Registered in litellm_config.yaml under litellm_settings.callbacks.
M1 — pass-through that logs a structured decision record per request.
M2 — session ID hardened; session taint store wired; L0/L1 features populated;
     async_post_call_success_hook added to close the taint loop.
M3 — classifier integrated at L2/L3; classifier_verdicts added to features.
M4 — policy engine wired; routing actions allow/route-hardened/strip-tools/block.
#140 — risk score → risk level → route, from the admin routing table in the policy.
     Route controls: model group, tool removal, safety prompt, and holds on
     generated tool calls. Post-call routes on the higher of the pre-call and
     post-call risk levels, so a request is never relaxed after the model call.
M5 — generated non-streaming tool calls are re-evaluated before release and
     mapped to execute/hold/block; streaming tool requests fail closed.

Sessions (#145, #146, #147) — the proxy issues session ids. A request without
x-agent-run-id starts a session: it may contain only system/user messages, and
the new id is returned in the x-agent-run-id response header. Every later
request must present that id; malformed, unknown, expired, or foreign-key ids
are rejected. Logs carry session_ref (a hash prefix), never the raw id.
"""

import asyncio
import copy
import sys
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from litellm.integrations.custom_logger import CustomLogger

from router.classifiers.base import BaseClassifier
from router.config import RouterConfig
from router.logger import DecisionLogger
from router.parser import extract_tool_context
from router.policy import (
    RISK_LEVELS,
    PolicyEngine,
    PolicyViolation,
    RiskLevel,
    load_policy_document,
)
from router.routing import Route, RoutingTable, verify_model_groups
from router.session import (
    SessionError,
    SessionExpired,
    get_store,
    is_well_formed,
    session_key,
    session_ref,
)
from router.taint import (
    classify_sinks,
    classify_sources,
    is_trusted_source,
    tainted_spans_in_sink_args,
)

SESSION_HEADER = "x-agent-run-id"
# Pre-call writes its risk level here for post-call. The key lives in LiteLLM's
# request metadata (not sent to the model) and pre-call always overwrites it,
# so a client cannot pre-set it.
ROUTE_METADATA_KEY = "securelitellm_route"
_MISSING_PRE_CALL_LEVEL: RiskLevel = "elevated"  # fail closed if pre-call left no level
_SESSION_START_ROLES = frozenset({"system", "developer", "user"})
_ISSUED_CACHE_MAX = 10_000  # request_id -> raw id, until the response headers are sent


@dataclass
class _Session:
    key: str  # session_key(raw id): the store key
    ref: str  # session_ref(raw id): logged
    issued: bool = False  # True if this request started the session


class _SessionViolation(Exception):
    def __init__(self, reason: str, message: str, ref: str | None = None, **detail: Any) -> None:
        self.reason = reason
        self.ref = ref
        self.detail = detail
        super().__init__(message)


def _session_header(data: dict) -> str | None:
    """Raw x-agent-run-id value, or None if the header is absent."""
    headers = data.get("metadata", {}).get("headers", {}) or {}
    value = headers.get(SESSION_HEADER)
    return value if value is None else str(value)


def _api_key_owner(user_api_key_dict: Any) -> str:
    """Hashed LiteLLM API key the session is bound to ("" if unavailable)."""
    token = getattr(user_api_key_dict, "token", None)
    return token if isinstance(token, str) else ""


def _uses_legacy_function_calling(data: dict, messages: list[dict]) -> bool:
    """True if the request uses OpenAI's deprecated functions/function_call format (#95).

    No control inspects that format — function results (role=function) are
    never classified and function_call sinks are never seen — so it is
    rejected by policy rather than passed through uninspected.
    """
    if data.get("functions") is not None or data.get("function_call") is not None:
        return True
    return any(m.get("role") == "function" or m.get("function_call") is not None for m in messages)


def _max_level(*levels: RiskLevel) -> RiskLevel:
    return max(levels, key=RISK_LEVELS.index)


def _stamp_route(data: dict, risk_level: RiskLevel, route: Route) -> None:
    """Record the pre-call risk level and route for post-call (mutates metadata in place)."""
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        metadata = data["metadata"] = {}
    metadata[ROUTE_METADATA_KEY] = {"risk_level": risk_level, "route": route.name}


def _pre_call_level(data: dict) -> RiskLevel | None:
    metadata = data.get("metadata")
    stamp = metadata.get(ROUTE_METADATA_KEY) if isinstance(metadata, dict) else None
    level = stamp.get("risk_level") if isinstance(stamp, dict) else None
    return level if level in RISK_LEVELS else None


def _with_prompt(messages: list[dict], prompt: str) -> list[dict]:
    """Send the route's safety prompt as a system message ahead of the conversation."""
    return [{"role": "system", "content": prompt}, *messages]


def _is_session_start(messages: list[dict]) -> bool:
    """A new session may carry only system/developer/user messages.

    Assistant turns, tool calls, or tool results mean the run is already in
    progress — starting a fresh session there would shed its taint.
    """
    return all(m.get("role") in _SESSION_START_ROLES for m in messages)


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
        # Stateless: no session memory, fall back to structural signal.
        # Trusted first-party sources (e.g. sink-result echoes) don't count.
        features["untrusted_seen"] = any(not is_trusted_source(s) for s in sources)

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
        policy_document = load_policy_document(self.config.policy_path or None)
        self._policy = PolicyEngine.from_mapping(policy_document)
        self._routing = RoutingTable.from_mapping(policy_document)
        if self.config.lock and self._routing.source == "legacy":
            raise ValueError("ROUTER_LOCK=true requires the policy to define 'routes' and 'matrix'")
        verify_model_groups(self._routing, self.config.litellm_config_path)
        self._issued: OrderedDict[str, str] = OrderedDict()
        self.decision_logger.emit(
            {**self.config.startup_record(), "routing": self._routing.summary()}
        )

    def _issue_session(self, request_id: str, owner: str) -> _Session:
        raw = get_store().issue(owner)
        self._issued[request_id] = raw
        while len(self._issued) > _ISSUED_CACHE_MAX:
            self._issued.popitem(last=False)
        return _Session(key=session_key(raw), ref=session_ref(raw), issued=True)

    def _check_session(
        self, data: dict, request_id: str, owner: str, messages: list[dict], phase: str
    ) -> _Session:
        """Resolve the request's session or raise _SessionViolation."""
        issued_raw = self._issued.get(request_id)
        if issued_raw is not None:  # post-call of the request that started the session
            raw = issued_raw
        else:
            raw = _session_header(data)
            if raw is None:
                if phase != "pre_call":
                    raise _SessionViolation("missing", f"{SESSION_HEADER} is required")
                if not _is_session_start(messages):
                    raise _SessionViolation(
                        "start_with_history",
                        f"a new session may contain only system and user messages; "
                        f"send the {SESSION_HEADER} issued for this run",
                    )
                return self._issue_session(request_id, owner)
            if not is_well_formed(raw):
                raise _SessionViolation(
                    "malformed",
                    f"{SESSION_HEADER} is not a session id issued by this proxy",
                    header_length=len(raw),
                )
        key = session_key(raw)
        try:
            get_store().authorize(key, owner)
        except SessionExpired as exc:
            raise _SessionViolation(
                "expired", str(exc), ref=session_ref(raw), expired_reason=exc.reason
            ) from exc
        except SessionError as exc:
            raise _SessionViolation(exc.reason, str(exc), ref=session_ref(raw)) from exc
        return _Session(key=key, ref=session_ref(raw))

    def _resolve_session(
        self,
        data: dict,
        request_id: str,
        user_api_key_dict: Any,
        messages: list[dict],
        phase: str,
    ) -> _Session:
        """Enforce the session contract. Violations are logged and rejected.

        In audit mode (ROUTER_ENFORCE=false) a violation is logged and the
        request continues in a newly issued session.
        """
        owner = _api_key_owner(user_api_key_dict)
        try:
            return self._check_session(data, request_id, owner, messages, phase)
        except _SessionViolation as exc:
            self.decision_logger.emit(
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "phase": phase,
                    "session_id": exc.ref,
                    "request_id": request_id,
                    "mode": self.config.mode,
                    "level": self.config.level,
                    "features": {"session_violation": exc.reason, **exc.detail},
                    "risk_score": 1.0,
                    "action": "block",
                    "matched_rules": [f"session_{exc.reason}"],
                    "enforce": self.config.enforce,
                }
            )
            if not self.config.enforce:
                return self._issue_session(request_id, owner)
            import litellm.exceptions as _le

            raise _le.BadRequestError(
                message=f"SecureLiteLLM: {exc}",
                model=data.get("model", ""),
                llm_provider="",
            ) from exc

    def _check_live_model_group(self, route: Route, data: dict, request_id: str) -> None:
        """Reject the request if the route's model group is missing from the live router.

        The startup check reads the config file; this catches groups removed
        afterwards (e.g. through the LiteLLM database). Outside the proxy
        (unit tests, scripts) there is no live router and nothing to check.
        """
        proxy = sys.modules.get("litellm.proxy.proxy_server")
        llm_router = getattr(proxy, "llm_router", None)
        if llm_router is None or route.model in set(llm_router.get_model_names()):
            return
        self.decision_logger.emit(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": "routing_config_mismatch",
                "request_id": request_id,
                "route": route.name,
                "missing_model_group": route.model,
            }
        )
        import litellm.exceptions as _le

        raise _le.BadRequestError(
            message=(
                f"SecureLiteLLM: route {route.name!r} needs model group {route.model!r}, "
                "which the proxy does not serve"
            ),
            model=data.get("model", ""),
            llm_provider="",
        )

    async def async_post_call_response_headers_hook(
        self,
        data: dict,
        user_api_key_dict: Any,
        response: Any,
        request_headers: dict[str, str] | None = None,
        litellm_call_info: dict[str, object] | None = None,
    ) -> dict[str, str] | None:
        """Return a newly issued session id to the client — the only time it is sent."""
        raw = self._issued.pop(data.get("litellm_call_id") or "", None)
        return {SESSION_HEADER: raw} if raw else None

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> dict:
        t0 = time.perf_counter()

        request_id = data.setdefault("litellm_call_id", str(uuid.uuid4()))
        messages = data.get("messages", [])
        session = self._resolve_session(data, request_id, user_api_key_dict, messages, "pre_call")
        session_id = session.key

        features = _extract_features(session_id, messages, self.config.level, self.config.mode)
        features["streaming_tool_request"] = bool(
            data.get("stream") and (data.get("tools") or data.get("functions"))
        )
        features["legacy_function_calling"] = _uses_legacy_function_calling(data, messages)

        sources = classify_sources(messages)
        # Trusted first-party sources (sink-result echoes) are never scanned or
        # tainted — only genuinely untrusted content reaches the classifier.
        # They still get a SAFE verdict so they remain visible in the decision log.
        untrusted_sources = [s for s in sources if not is_trusted_source(s)]
        safe_verdicts = [_safe_verdict(s) for s in sources if is_trusted_source(s)]

        # Classifier is mandatory whenever untrusted tool results are present.
        # No valid production path bypasses classification.
        if untrusted_sources and self._classifier is None:
            import litellm.exceptions as _le

            raise _le.BadRequestError(
                message=(
                    "SecureLiteLLM: classifier is required but not configured. "
                    "Set CLASSIFIER_BACKEND and ensure the classifier sidecar is reachable."
                ),
                model=data.get("model", ""),
                llm_provider="",
            )

        # Run classifier on ALL levels (not only L2/L3) when untrusted sources are present.
        untrusted_verdicts: list[dict] = []
        if untrusted_sources and self._classifier is not None:
            untrusted_verdicts = await _classify_sources(self._classifier, untrusted_sources)

        classifier_verdicts = safe_verdicts + untrusted_verdicts
        if classifier_verdicts:
            features["classifier_verdicts"] = classifier_verdicts
            features["classifier_injection"] = any(
                v.get("label") == "INJECTION" for v in classifier_verdicts
            )
            features["classifier_error"] = any(
                v.get("label") == "UNKNOWN" for v in classifier_verdicts
            )

        # Record sources into session store (session mode only).
        # With classifier:    only taint untrusted sources flagged INJECTION — clean content passes.
        # Without verdicts:   taint untrusted sources (fail-closed).
        # Trusted first-party sources are recorded but never tainted.
        if self.config.mode == "session":
            store = get_store()
            injected_ids = {
                v["source_id"] for v in untrusted_verdicts if v.get("label") == "INJECTION"
            }
            for src in sources:
                if is_trusted_source(src):
                    taint = False
                else:
                    taint = not untrusted_verdicts or src.get("tool_call_id") in injected_ids
                store.record_source(session_id, src, taint=taint)
            # Refresh after recording so the logged feature and policy both see
            # taint set by tool results in the current request.
            features["untrusted_seen"] = store.state(session_id).tainted
        else:
            # Stateless: no session memory, so judge the current request on the
            # classifier's verdict rather than bare provenance. Untrusted content
            # counts as "seen" only if it was flagged INJECTION, or the classifier
            # errored (fail-closed). Clean BENIGN reads no longer trip untrusted_and_sink.
            features["untrusted_seen"] = features.get(
                "classifier_injection", False
            ) or features.get("classifier_error", False)

        # M4: evaluate policy rules → risk score → risk level → route (#140)
        risk_score, risk_level, matched_rules = self._policy.assess(features)
        data_class = "public"
        route = self._routing.resolve(risk_level, data_class)
        action = route.legacy_action
        _stamp_route(data, risk_level, route)

        # Escalation counter (session mode only, any policy hit)
        escalation_count = 0
        if self.config.mode == "session" and risk_level != "low":
            escalation_count = get_store().record_escalation(session_id)
            features["escalation_count"] = escalation_count

        tool_context = extract_tool_context(messages)
        latency_ms = round((time.perf_counter() - t0) * 1000, 3)

        self.decision_logger.emit(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "phase": "pre_call",
                "session_id": session.ref,
                "session_issued": session.issued,
                "request_id": request_id,
                "mode": self.config.mode,
                "level": self.config.level,
                "features": features,
                "risk_score": round(risk_score, 4),
                "risk_level": risk_level,
                "data_class": data_class,
                "route": route.name,
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

        # Enforcement: apply the route's controls
        if route.blocks:
            import litellm.exceptions as _le

            raise _le.BadRequestError(
                message=str(PolicyViolation(risk_score, matched_rules)),
                model=data.get("model", ""),
                llm_provider="",
            )

        if route.strips_tools:
            data = dict(data)
            data.pop("tools", None)
            data.pop("functions", None)
            data.pop("function_call", None)
            # Explicitly forbid tool use so the model produces a text response
            # instead of generating a tool call that the API will reject.
            data["tool_choice"] = "none"

        prompt = self._routing.prompt_text(route)
        if prompt is not None:
            data = dict(data)
            data["messages"] = _with_prompt(messages, prompt)

        if route.model is not None:
            self._check_live_model_group(route, data, request_id)
            data = dict(data)
            data["model"] = route.model

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

        The route is resolved from the higher of the pre-call and post-call
        risk levels, and its hold control applies whatever the post-call score.
        """
        request_id = data.get("litellm_call_id") or ""
        messages = data.get("messages", [])

        generated_calls = _extract_response_sinks(response, include_reads=True)
        if not generated_calls:
            return None
        egress_sinks = [c for c in generated_calls if c["category"] != "read" or "malformed" in c]
        pre_level = _pre_call_level(data)
        pre_route = self._routing.resolve(pre_level or _MISSING_PRE_CALL_LEVEL)
        if not egress_sinks and pre_route.hold != "all":
            return None  # read-only calls are released unless the route holds everything
        session = self._resolve_session(data, request_id, user_api_key_dict, messages, "post_call")
        session_id = session.key

        features = _extract_features(session_id, messages, self.config.level, self.config.mode)
        features["sink_requested"] = bool(egress_sinks)
        features["streaming_tool_request"] = False
        features["malformed_tool_call"] = any("malformed" in s for s in egress_sinks)

        sources = classify_sources(messages)
        untrusted_sources = [s for s in sources if not is_trusted_source(s)]
        verdicts = [_safe_verdict(s) for s in sources if is_trusted_source(s)]
        if untrusted_sources and self._classifier is not None:
            verdicts.extend(await _classify_sources(self._classifier, untrusted_sources))
        injected_ids = {v["source_id"] for v in verdicts if v.get("label") == "INJECTION"}
        if verdicts:
            features["classifier_verdicts"] = verdicts
            features["classifier_injection"] = len(injected_ids) > 0
            features["classifier_error"] = any(
                verdict.get("label") == "UNKNOWN" for verdict in verdicts
            )

        if self.config.mode != "session":
            # Stateless: judge on the classifier verdict, not bare provenance.
            features["untrusted_seen"] = features.get(
                "classifier_injection", False
            ) or features.get("classifier_error", False)

        if self.config.level == "L3":
            if self.config.mode == "session":
                tainted_hashes = get_store().state(session_id).tainted_spans
            else:
                # Stateless: only content the classifier actually flagged INJECTION
                # is a tainted span — a clean file emailed verbatim must not match.
                tainted_hashes = [
                    s["content_hash"]
                    for s in untrusted_sources
                    if s.get("tool_call_id") in injected_ids
                ]
            features["tainted_spans_in_sink_args"] = tainted_spans_in_sink_args(
                tainted_hashes,
                egress_sinks,
                [_response_sink_message(egress_sinks)],
            )

        risk_score, assessed_level, matched_rules = self._policy.assess(features)
        risk_level = _max_level(assessed_level, pre_level or _MISSING_PRE_CALL_LEVEL)
        data_class = "public"
        route = self._routing.resolve(risk_level, data_class)
        policy_action = route.legacy_action
        output_action = _output_action(route, assessed_level, generated_calls, egress_sinks)

        if self.config.mode == "session":
            store = get_store()
            for sink in egress_sinks:
                store.record_sink(session_id, _public_sink(sink))
            if assessed_level != "low":
                features["escalation_count"] = store.record_escalation(session_id)

        self.decision_logger.emit(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "phase": "post_call",
                "session_id": session.ref,
                "request_id": request_id,
                "mode": self.config.mode,
                "level": self.config.level,
                "features": features,
                "risk_score": round(risk_score, 4),
                "risk_level": risk_level,
                "assessed_risk_level": assessed_level,
                "pre_call_risk_level": pre_level,
                "data_class": data_class,
                "route": route.name,
                "action": output_action,
                "policy_action": policy_action,
                "matched_rules": matched_rules,
                "enforce": self.config.enforce,
                "tool_context": {
                    "generated_tool_call_count": len(generated_calls),
                    "generated_tool_calls": [_public_sink(call) for call in generated_calls],
                },
            }
        )

        if not self.config.enforce or output_action == "execute":
            return None
        if output_action == "block":
            import litellm.exceptions as _le

            raise _le.BadRequestError(
                message=str(PolicyViolation(risk_score, matched_rules)),
                model=data.get("model", ""),
                llm_provider="",
            )
        return _hold_response_tool_calls(
            response, risk_score, matched_rules or [f"route {route.name}"]
        )


def _output_action(
    route: Route,
    assessed_level: RiskLevel,
    generated_calls: list[dict[str, Any]],
    egress_sinks: list[dict[str, Any]],
) -> str:
    """execute / hold / block for the generated tool calls of one response."""
    if route.blocks:
        return "block"
    if route.hold == "all" and generated_calls:
        return "hold"
    if egress_sinks and (route.hold == "sinks" or assessed_level != "low"):
        # Any post-call policy hit holds sink calls, whatever the route (pre-#140 behavior).
        return "hold"
    return "execute"


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


def _safe_verdict(src: dict) -> dict:
    """Synthetic BENIGN verdict for a trusted first-party source.

    Trusted sources (sink-result echoes) are never sent to the classifier, but
    we emit a verdict so they stay visible in the decision log, labelled safe.
    """
    return {
        "label": "BENIGN",
        "score": 0.0,
        "model": "trusted-first-party",
        "cached": False,
        "latency_ms": 0.0,
        "source_id": src.get("tool_call_id"),
        "trusted": True,
    }


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


def _extract_response_sinks(response: Any, include_reads: bool = False) -> list[dict[str, Any]]:
    """Pull tool_calls out of a LiteLLM completion response object.

    Read-only calls are skipped unless include_reads is set. Fails closed
    (#82, #156): a call whose name or arguments cannot be parsed is returned
    as a sink with ``malformed`` set — even if its name looks like a read
    tool — so policy holds it rather than releasing it uninspected.
    """
    from router.taint import _sink_category, tool_call_defect

    sinks = []
    for choice in getattr(response, "choices", None) or []:
        msg = getattr(choice, "message", None)
        if msg is None:
            continue
        for call in getattr(msg, "tool_calls", None) or []:
            fn = getattr(call, "function", None)
            name = getattr(fn, "name", None)
            arguments = getattr(fn, "arguments", None)
            defect = tool_call_defect(name, arguments)
            category = _sink_category(name) if isinstance(name, str) else "other"
            if category == "read" and defect is None and not include_reads:
                continue
            arguments = arguments if isinstance(arguments, str) else ""
            sink = {
                "id": getattr(call, "id", None),
                "name": name if isinstance(name, str) else "",
                "category": category,
                "args_length": len(arguments),
                "_arguments": arguments,
            }
            if defect is not None:
                sink["malformed"] = defect
            sinks.append(sink)
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
