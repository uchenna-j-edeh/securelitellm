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
#181 — data classification: a regex detector scans user messages and tool
     results; data_classes rules make the request public or sensitive, and
     sensitive requests take the sensitive column of the routing table (a model
     group cleared for sensitive data). In session mode the class is sticky.
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
import hashlib
import hmac
import json
import os
import re
import sys
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from weakref import WeakKeyDictionary

from litellm.integrations.custom_logger import CustomLogger

from router.allowlist import (
    Allowlist,
    latest_user_request,
    not_user_named,
    sinks_with_arguments,
)
from router.approvals import ApprovalError, ApprovalStore, ttl_from_env
from router.classifiers.base import BaseClassifier
from router.config import RouterConfig
from router.controls import resolve_controls
from router.decisions import (
    DECISION_HEADER,
    DECISION_METADATA_KEY,
    DECISIONS_PATH,
    history_store,
    response_value,
)
from router.decisions import (
    summary as decision_summary,
)
from router.identity import Caller, caller_identity
from router.inventory import Inventory
from router.logger import DecisionLogger
from router.parser import extract_tool_context
from router.policy import (
    DATA_CLASSES,
    RISK_LEVELS,
    DataClass,
    PolicyEngine,
    PolicyViolation,
    RiskLevel,
    load_policy_document,
)
from router.routing import Route, RoutingTable, verify_model_groups
from router.sensitive import scan_messages
from router.session import (
    SessionError,
    SessionExpired,
    SessionStoreUnavailable,
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
ROUTE_HEADER = "x-securelitellm-route"  # "<route>; risk=<level>", when ROUTER_ROUTE_HEADER=true
# Pre-call writes its risk level here for post-call, and post-call updates it
# with the final route for the route header. The key lives in LiteLLM's
# request metadata (not sent to the model) and pre-call always overwrites it,
# so a client cannot pre-set it.
ROUTE_METADATA_KEY = "securelitellm_route"
_MISSING_PRE_CALL_LEVEL: RiskLevel = "elevated"  # fail closed if pre-call left no level
_MISSING_PRE_CALL_CLASS: DataClass = "sensitive"  # fail closed if pre-call left no class
_SESSION_START_ROLES = frozenset({"system", "developer", "user"})
_ISSUED_CACHE_MAX = 10_000  # request_id -> raw id, until the response headers are sent
# Held for approval (#174). The agent sends the approval ID back in this request
# header to retry; a response carries a new ID, or the status of the one sent.
APPROVAL_HEADER = "x-securelitellm-approval"
APPROVAL_STATUS_HEADER = "x-securelitellm-approval-status"
APPROVALS_PATH = "/securelitellm/approvals"
_GATEWAY_ONLY_FIELDS = ("mock_tool_calls", "mock_response")
_DECIDING_ROLES = frozenset({"proxy_admin"})
_VIEWING_ROLES = frozenset({"proxy_admin", "proxy_admin_viewer"})
_APPROVAL_NOTICES = {
    "pending": "this action is still waiting for approval; retry once it is approved",
    "denied": "this action was denied by an approver; do not retry it",
    "expired": "the approval for this action expired before it was used; ask again if it is "
    "still needed",
    "used": "this approval was already used; an approved action runs once",
    "unknown": "this approval ID is not valid for this session and key",
    "mismatch": "this approval ID is not valid for this session and key",
    "tampered": "this approval failed its integrity check and can't be used",
    "replay_mismatch": "the replayed action did not match what was approved, so it was held",
}


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


def _approval_header(data: dict) -> str | None:
    """Approval ID the agent sent to retry a held action, or None."""
    headers = data.get("metadata", {}).get("headers", {}) or {}
    value = headers.get(APPROVAL_HEADER)
    return str(value).strip() if value else None


def _role(user_api_key_dict: Any) -> str | None:
    role = getattr(user_api_key_dict, "user_role", None)
    role = getattr(role, "value", role)
    return role if isinstance(role, str) else None


def _remember(cache: OrderedDict, key: str, value: Any) -> None:
    """Keep a per-request value until the post-call or headers hook takes it (bounded)."""
    cache[key] = value
    while len(cache) > _ISSUED_CACHE_MAX:
        cache.popitem(last=False)


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


def _stamp_route(data: dict, risk_level: RiskLevel, data_class: DataClass, route: Route) -> None:
    """Record the risk level, data class and route in the request metadata (mutated in place).

    Pre-call writes it for post-call; post-call overwrites it with the final
    route for the route header.
    """
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        metadata = data["metadata"] = {}
    metadata[ROUTE_METADATA_KEY] = {
        "risk_level": risk_level,
        "data_class": data_class,
        "route": route.name,
    }


def _route_stamp(data: dict) -> dict[str, str] | None:
    metadata = data.get("metadata")
    stamp = metadata.get(ROUTE_METADATA_KEY) if isinstance(metadata, dict) else None
    if not isinstance(stamp, dict) or stamp.get("risk_level") not in RISK_LEVELS:
        return None
    return stamp


def _pre_call_level(data: dict) -> RiskLevel | None:
    stamp = _route_stamp(data)
    return None if stamp is None else stamp["risk_level"]


def _pre_call_class(data: dict) -> DataClass | None:
    stamp = _route_stamp(data)
    data_class = None if stamp is None else stamp.get("data_class")
    return data_class if data_class in DATA_CLASSES else None


def _with_prompt(messages: list[dict], prompt: str) -> list[dict]:
    """Send the route's safety prompt as a system message ahead of the conversation."""
    return [{"role": "system", "content": prompt}, *messages]


# A route that strips tools still forwards the conversation's earlier tool calls
# and results. Providers that need tool definitions to accept tool history
# (Bedrock) get it from LiteLLM as text, "[tool call <id>: name(args)]" and
# "[tool result for <id>: ...]", and the model then imitated that text in its
# reply: fake tool calls and its <reasoning> in the answer (found in the AWS
# demo, 2026-11-18). Nothing ran (the client executes only structured calls),
# but the reply looked broken. The notice asks for prose; the post-call hook
# removes what slips through.
TOOLS_REMOVED_NOTICE = (
    "Gateway notice: your tools have been removed for this reply. Earlier tool use "
    "may appear in the conversation as bracketed notes such as [tool call ...] or "
    "[tool result ...]; they are records, not a format to copy. Do not write tool "
    "calls, function-call syntax or bracketed notes, and do not show your reasoning. "
    "You cannot take any action in this reply, so do not say that you did. Answer the "
    "user in plain prose."
)
TOOLS_REMOVED_FALLBACK = (
    "SecureLiteLLM removed tool access for this reply because the conversation was "
    "flagged as high risk, so the request could not be completed."
)
_REASONING_BLOCK = re.compile(r"<(reasoning|thinking)>.*?</\1>", re.IGNORECASE | re.DOTALL)
_REASONING_TAG = re.compile(r"</?(?:reasoning|thinking)>", re.IGNORECASE)
_TOOL_NOTE = re.compile(r"\[tool call\b[^\n]*?\)\]|\[tool result for\b[^\n]*\]", re.IGNORECASE)


def tidy_tool_free_text(text: str) -> str:
    """A reply written without tools, minus imitated tool notes and reasoning."""
    # Removed text becomes a line break so the sentences around it stay apart.
    cleaned = _REASONING_BLOCK.sub("\n", text)
    cleaned = _REASONING_TAG.sub("\n", cleaned)
    cleaned = _TOOL_NOTE.sub("\n", cleaned)
    cleaned = re.sub(r"[ \t]+\n", "\n", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return cleaned or TOOLS_REMOVED_FALLBACK


def _tidied_response(response: Any) -> Any | None:
    """A copy with each choice's text tidied, or None if nothing changed."""
    changed = False
    tidied = copy.deepcopy(response)
    for choice in getattr(tidied, "choices", None) or []:
        message = getattr(choice, "message", None)
        content = getattr(message, "content", None)
        if not isinstance(content, str):
            continue
        clean = tidy_tool_free_text(content)
        if clean != content:
            message.content = clean
            changed = True
    return tidied if changed else None


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
    inventory: Inventory | None = None,
) -> dict[str, Any]:
    sources = classify_sources(messages)
    sinks = classify_sinks(messages, inventory)

    # L0 — bare boolean flags
    features: dict[str, Any] = {
        "untrusted_seen": False,
        "sink_requested": len(sinks) > 0,
    }
    _check_inventory(features, sinks)

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
        policy_document = load_policy_document(self.config.policy_path or None)
        self._controls = resolve_controls(policy_document)
        # Validated whenever present, so a typo fails at startup either way;
        # enforced only with allowlist=on (#167).
        allowlist = (
            Allowlist.from_entries(policy_document["allowed_destinations"])
            if "allowed_destinations" in policy_document
            else None
        )
        self._allowlist = allowlist if self._controls.allowlist else None
        # The user's own destinations count as named (#212); validated whenever present.
        self._own_destinations = Allowlist.from_entries(
            policy_document.get("own_destinations") or []
        )
        # Declared tools (#176): None when the policy declares none, so the
        # name patterns decide as before.
        self._inventory = Inventory.from_mapping(policy_document)
        if self.config.lock and not self._controls.classifier:
            raise ValueError("ROUTER_LOCK=true rejects unsafe config: classifier=off")
        # classifier=off (#196): not part of this configuration, so not created.
        self._classifier: BaseClassifier | None = (
            _init_classifier(self.config.classifier_backend) if self._controls.classifier else None
        )
        self._policy = PolicyEngine.from_mapping(policy_document)
        self._routing = RoutingTable.from_mapping(policy_document)
        if self.config.lock and self._routing.source == "legacy":
            raise ValueError("ROUTER_LOCK=true requires the policy to define 'routes' and 'matrix'")
        verify_model_groups(self._routing, self.config.litellm_config_path)
        session_mode = self.config.mode == "session"
        check_single_worker(
            dict(os.environ),
            # A shared store (#169) is the same for every worker; memory is not.
            # Approvals live wherever sessions do.
            session_mode=session_mode and not get_store().shared,
            approvals=self._controls.approvals and not get_store().shared,
        )
        if session_mode or (self._controls.approvals and get_store().shared):
            # A store that can't be reached or has no tables fails here, at
            # startup, rather than on the first request.
            get_store().check()
        self._issued: OrderedDict[str, str] = OrderedDict()
        # Held for approval (#174): only with approvals=on.
        self._approvals: ApprovalStore | None = None
        self._approval_headers: OrderedDict[str, dict[str, str]] = OrderedDict()
        self._replays: OrderedDict[str, tuple[str, str | None]] = OrderedDict()
        self._refusals: OrderedDict[str, str] = OrderedDict()
        self._decision_captures: OrderedDict[str, dict] = OrderedDict()
        self._decision_error_secret = uuid.uuid4().bytes
        self._decision_history = history_store(get_store())
        if self._controls.approvals:
            self._approvals = _approval_store(ttl_from_env(dict(os.environ), get_store().idle_ttl))
        self.decision_logger.emit(
            {
                **self.config.startup_record(),
                "controls": self._controls.summary(),
                "routing": self._routing.summary(),
                "tools": self._inventory.summary() if self._inventory is not None else None,
                "session_store": get_store().backend if session_mode else None,
                "approval_store": (
                    self._approvals.backend if self._approvals is not None else None
                ),
                "approval_ttl_seconds": (
                    int(self._approvals.ttl) if self._approvals is not None else None
                ),
            }
        )

    def register_proxy_routes(self, app: Any = None, auth: Any = None) -> None:
        """Explicit proxy wiring; offline hook construction never imports the server."""
        if app is None:
            app, auth = _proxy_app_and_auth()
        bound = _DECISION_ROUTE_HOOKS.get(app)
        if bound is not None and bound is not self:
            raise RuntimeError("decision routes are already bound to another proxy hook")
        register_decision_routes(app, auth, self)
        if self._approvals is not None:
            register_approval_routes(app, auth, self)

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
        except SessionStoreUnavailable:
            raise  # not the caller's fault: refused and logged at the hook's entry points
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
        agent: str | None = None,
    ) -> _Session:
        """Enforce the session contract. Violations are logged and rejected.

        In audit mode (ROUTER_ENFORCE=false) a violation is logged and the
        request continues in a newly issued session.
        """
        owner = _api_key_owner(user_api_key_dict)
        try:
            return self._check_session(data, request_id, owner, messages, phase)
        except _SessionViolation as exc:
            self._record_decision(
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "phase": phase,
                    "session_id": exc.ref,
                    "agent": agent,
                    "request_id": request_id,
                    "mode": self.config.mode,
                    "level": self.config.level,
                    "controls": self._controls.summary(),
                    "features": {"session_violation": exc.reason, **exc.detail},
                    "risk_score": 1.0,
                    "action": "block",
                    "matched_rules": [f"session_{exc.reason}"],
                    "enforce": self.config.enforce,
                },
                data,
                user_api_key_dict,
            )
            if not self.config.enforce:
                return self._issue_session(request_id, owner)
            import litellm.exceptions as _le

            raise _le.BadRequestError(
                message=f"SecureLiteLLM: {exc}",
                model=data.get("model", ""),
                llm_provider="",
            ) from exc

    def _require_agent(self, caller: Caller, data: dict, request_id: str, auth: Any) -> None:
        """Reject a model request that no agent key authenticated (#148).

        Only with ROUTER_REQUIRE_AGENT_KEY=true. The master key, or a virtual
        key with no user_id, can't be attributed to an agent or revoked on its
        own. In audit mode the violation is logged and the request continues.
        """
        violation = caller.violation
        if violation is None or not self.config.require_agent_key:
            return
        self._record_decision(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "phase": "pre_call",
                "session_id": None,
                "agent": None,
                "request_id": request_id,
                "mode": self.config.mode,
                "level": self.config.level,
                "controls": self._controls.summary(),
                "features": {"agent_violation": violation},
                "risk_score": 1.0,
                "action": "block",
                "matched_rules": ["agent_unidentified"],
                "enforce": self.config.enforce,
            },
            data,
            auth,
        )
        if not self.config.enforce:
            return
        import litellm.exceptions as _le

        reason = (
            "the master key is for administration only"
            if violation == "admin_key"
            else "this API key is not registered to an agent"
        )
        raise _le.BadRequestError(
            message=f"SecureLiteLLM: {reason}; send model requests with an agent's own key",
            model=data.get("model", ""),
            llm_provider="",
        )

    def _classify_data(
        self, session_id: str, messages: list[dict], features: dict[str, Any]
    ) -> tuple[DataClass, list[str]]:
        """The request's data class and matching data-class rules (#181).

        Logs which detectors matched, never the matched text. In session mode
        the class is sticky: once sensitive data enters the session, every
        later request is sensitive.
        """
        detected = scan_messages(messages)
        features["sensitive_detectors"] = sorted(k for k, v in detected.items() if v)
        data_class, rules = self._policy.classify(detected)
        if self.config.mode == "session":
            store = get_store()
            if data_class == "sensitive":
                store.mark_sensitive(session_id)
            elif store.state(session_id).sensitive:
                data_class = "sensitive"
                features["session_sensitive"] = True
        return data_class, rules

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
        """Return a newly issued session id (the only time it is sent) and, if enabled, the route.

        LiteLLM calls this after the post-call hook, so the route reflects any
        post-call escalation.
        """
        headers: dict[str, str] = {}
        capture = self._capture(data, user_api_key_dict)
        if capture and capture["records"]:
            await self._save_decisions(capture)
            headers[DECISION_HEADER] = json.dumps(
                self._decision_value(capture, user_api_key_dict),
                ensure_ascii=True,
                separators=(",", ":"),
            )
        elif (value := self._failed_decision(data, user_api_key_dict)) is not None:
            headers[DECISION_HEADER] = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        metadata = data.get("metadata") or {}
        metadata.pop("securelitellm_failed_decision", None)
        self._decision_captures.pop(metadata.get(DECISION_METADATA_KEY, ""), None)
        raw = self._issued.pop(data.get("litellm_call_id") or "", None)
        if raw:
            headers[SESSION_HEADER] = raw
        headers.update(self._approval_headers.pop(data.get("litellm_call_id") or "", {}))
        if self.config.route_header:
            stamp = _route_stamp(data)
            if stamp is not None:
                headers[ROUTE_HEADER] = f"{stamp['route']}; risk={stamp['risk_level']}"
        return headers or None

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> dict:
        metadata = data.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            metadata = data["metadata"] = {}
        # A client cannot attach another request's decision or its capture token.
        metadata.pop(DECISION_METADATA_KEY, None)
        metadata.pop("securelitellm_failed_decision", None)
        # The configured module callback can have been imported before proxy
        # startup. Bind lazily in that case, never for an offline/eval hook.
        proxy = sys.modules.get("litellm.proxy.proxy_server")
        if (
            self is globals().get("proxy_handler_instance")
            and getattr(proxy, "app", None) is not None
        ):
            self.register_proxy_routes()
        self._capture(data, user_api_key_dict, create=True)
        try:
            return await self._pre_call(user_api_key_dict, cache, data, call_type)
        except SessionStoreUnavailable as exc:
            error = self._store_outage(exc, "pre_call", data, user_api_key_dict)
            self._attach_decision_error(error, data, user_api_key_dict)
            raise error from exc
        except Exception as exc:
            self._attach_decision_error(exc, data, user_api_key_dict)
            raise

    def _capture(self, data: dict, auth: Any, *, create: bool = False) -> dict | None:
        metadata = data.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            if not create:
                return None
            metadata = data["metadata"] = {}
        token = metadata.get(DECISION_METADATA_KEY)
        capture = self._decision_captures.get(token) if isinstance(token, str) else None
        owner = _api_key_owner(auth)
        if capture is not None and capture["owner"] == owner:
            return capture
        if not create:
            return None
        token = uuid.uuid4().hex
        metadata[DECISION_METADATA_KEY] = token
        capture = {"owner": owner, "records": [], "saved": False, "history_available": True}
        _remember(self._decision_captures, token, capture)
        return capture

    def _record_decision(self, record: dict, data: dict, auth: Any) -> None:
        record["decision_id"] = uuid.uuid4().hex
        self.decision_logger.emit(record)
        capture = self._capture(data, auth, create=True)
        capture["records"].append(decision_summary(record))

    def _detailed_decisions(self, auth: Any) -> bool:
        return self.config.expose_decisions or _role(auth) in _VIEWING_ROLES

    def _decision_value(self, capture: dict, auth: Any) -> dict:
        return response_value(
            capture["records"], self._detailed_decisions(auth), capture["history_available"]
        )

    async def _save_decisions(self, capture: dict) -> None:
        if capture["saved"]:
            return
        capture["saved"] = True
        try:
            # Database work never freezes the ASGI event loop. No AWS CLI or
            # remote log read participates in returning the current decision.
            await asyncio.to_thread(
                self._decision_history.append, capture["records"], capture["owner"]
            )
        except SessionStoreUnavailable:
            capture["history_available"] = False
            self.decision_logger.emit({"event": "decision_history_unavailable"})

    def _attach_decision_error(self, exc: Exception, data: dict, auth: Any) -> None:
        capture = self._capture(data, auth)
        if not capture or not capture["records"]:
            return
        # LiteLLM serializes this field into error.provider_specific_fields.
        # It survives errors where there is no normal model response.
        fields = getattr(exc, "provider_specific_fields", None)
        exc.provider_specific_fields = {  # type: ignore[attr-defined]
            **(fields if isinstance(fields, dict) else {}),
            "securelitellm_decision": self._decision_value(capture, auth),
        }
        if not self._detailed_decisions(auth) and "Request blocked by policy" in str(exc):
            exc.message = "SecureLiteLLM: Request blocked by policy"  # type: ignore[attr-defined]
            exc.args = (exc.message,)

    async def async_post_call_failure_hook(
        self,
        request_data: dict,
        original_exception: Exception,
        user_api_key_dict: Any,
        traceback_str: str | None = None,
    ) -> None:
        capture = self._capture(request_data, user_api_key_dict)
        if capture and capture["records"]:
            await self._save_decisions(capture)
            self._attach_decision_error(original_exception, request_data, user_api_key_dict)
            value = self._decision_value(capture, user_api_key_dict)
            # Request-scoped, signed metadata survives LiteLLM versions which
            # run the headers hook AFTER the failure hook. No global failure
            # cache remains when that headers hook is never called.
            metadata = request_data["metadata"]
            metadata["securelitellm_failed_decision"] = {
                "value": value,
                "signature": self._failure_signature(value, user_api_key_dict),
            }
        metadata = request_data.get("metadata") or {}
        self._decision_captures.pop(metadata.get(DECISION_METADATA_KEY, ""), None)

    def _failure_signature(self, value: dict, auth: Any) -> str:
        material = json.dumps([_api_key_owner(auth), value], sort_keys=True, separators=(",", ":"))
        return hmac.new(self._decision_error_secret, material.encode(), hashlib.sha256).hexdigest()

    def _failed_decision(self, data: dict, auth: Any) -> dict | None:
        metadata = data.get("metadata") or {}
        envelope = metadata.get("securelitellm_failed_decision")
        if not isinstance(envelope, dict) or not isinstance(envelope.get("value"), dict):
            return None
        signature = envelope.get("signature")
        if isinstance(signature, str) and hmac.compare_digest(
            signature, self._failure_signature(envelope["value"], auth)
        ):
            return envelope["value"]
        return None

    def _store_outage(
        self, exc: SessionStoreUnavailable, phase: str, data: dict, user_api_key_dict: Any
    ) -> Exception:
        """Log a session store outage and return the error that refuses the request.

        Fail closed (#169), in audit mode too, wherever in the request the
        store was needed: without it there is no session to judge the request
        against, and a fresh one would hand a tainted session a clean start.
        """
        self._record_decision(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "phase": phase,
                "session_id": None,
                "agent": caller_identity(user_api_key_dict).agent,
                "request_id": data.get("litellm_call_id") or "",
                "mode": self.config.mode,
                "level": self.config.level,
                "controls": self._controls.summary(),
                "features": {"session_violation": exc.reason},
                "risk_score": 1.0,
                "action": "block",
                "matched_rules": [f"session_{exc.reason}"],
                "enforce": self.config.enforce,
            },
            data,
            user_api_key_dict,
        )
        import litellm.exceptions as _le

        return _le.ServiceUnavailableError(
            message="SecureLiteLLM: the session store is unavailable; the request was refused",
            model=data.get("model", ""),
            llm_provider="",
        )

    async def _pre_call(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> dict:
        t0 = time.perf_counter()

        request_id = data.setdefault("litellm_call_id", str(uuid.uuid4()))
        messages = data.get("messages", [])
        # Only the gateway may answer for the model (#174). LiteLLM already strips
        # these from client bodies unless a key has allow_client_mock_response.
        for field in _GATEWAY_ONLY_FIELDS:
            data.pop(field, None)
        self._log_expired_approvals()
        caller = caller_identity(user_api_key_dict)
        self._require_agent(
            caller, data, request_id, user_api_key_dict
        )  # before a session is issued
        session = self._resolve_session(
            data, request_id, user_api_key_dict, messages, "pre_call", agent=caller.agent
        )
        session_id = session.key

        features = _extract_features(
            session_id, messages, self.config.level, self.config.mode, self._inventory
        )
        features["streaming_tool_request"] = bool(
            data.get("stream") and (data.get("tools") or data.get("functions"))
        )
        features["legacy_function_calling"] = _uses_legacy_function_calling(data, messages)
        if self._allowlist is not None or self._controls.user_named:
            request_sinks = sinks_with_arguments(
                classify_sinks(messages, self._inventory), messages
            )
            if self._allowlist is not None:
                _check_destinations(features, self._allowlist, request_sinks)
            if self._controls.user_named:
                _check_user_named(features, request_sinks, self._own_destinations)

        sources = classify_sources(messages)
        # Trusted first-party sources (sink-result echoes) are never scanned or
        # tainted — only genuinely untrusted content reaches the classifier.
        # They still get a SAFE verdict so they remain visible in the decision log.
        untrusted_sources = [s for s in sources if not is_trusted_source(s)]
        safe_verdicts = [_safe_verdict(s) for s in sources if is_trusted_source(s)]

        # Classifier is mandatory whenever untrusted tool results are present.
        # No valid production path bypasses classification.
        if untrusted_sources and self._controls.classifier and self._classifier is None:
            import litellm.exceptions as _le

            self._record_decision(
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "phase": "pre_call",
                    "session_id": session.ref,
                    "agent": caller.agent,
                    "request_id": request_id,
                    "mode": self.config.mode,
                    "level": self.config.level,
                    "controls": self._controls.summary(),
                    "risk_score": 1.0,
                    "risk_level": "critical",
                    "route": "block",
                    "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
                    "features": {},
                    "action": "block",
                    "enforce": True,
                    "matched_rules": ["classifier_unavailable"],
                },
                data,
                user_api_key_dict,
            )
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
        elif self._controls.classifier:
            # Stateless: no session memory, so judge the current request on the
            # classifier's verdict rather than bare provenance. Untrusted content
            # counts as "seen" only if it was flagged INJECTION, or the classifier
            # errored (fail-closed). Clean BENIGN reads no longer trip untrusted_and_sink.
            features["untrusted_seen"] = features.get(
                "classifier_injection", False
            ) or features.get("classifier_error", False)
        else:
            # classifier=off (#196): provenance only — any untrusted source counts.
            features["untrusted_seen"] = bool(untrusted_sources)

        # M4: evaluate policy rules → risk score → risk level → route (#140)
        risk_score, risk_level, matched_rules = self._policy.assess(features)
        data_class, data_class_rules = self._classify_data(session_id, messages, features)
        route = self._routing.resolve(risk_level, data_class)
        # action reports the risk response (the public column), so it stays
        # comparable across data classes; route names the route actually taken.
        action = self._routing.resolve(risk_level).legacy_action
        _stamp_route(data, risk_level, data_class, route)

        # Escalation counter (session mode only, any policy hit)
        escalation_count = 0
        if self.config.mode == "session" and risk_level != "low":
            escalation_count = get_store().record_escalation(session_id)
            features["escalation_count"] = escalation_count

        tool_context = extract_tool_context(messages)
        latency_ms = round((time.perf_counter() - t0) * 1000, 3)

        self._record_decision(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "phase": "pre_call",
                "session_id": session.ref,
                "session_issued": session.issued,
                "agent": caller.agent,
                "request_id": request_id,
                "mode": self.config.mode,
                "level": self.config.level,
                "controls": self._controls.summary(),
                "features": features,
                "risk_score": round(risk_score, 4),
                "risk_level": risk_level,
                "data_class": data_class,
                "data_class_rules": data_class_rules,
                "route": route.name,
                "action": action,
                "matched_rules": matched_rules,
                "enforce": self.config.enforce,
                "latency_ms": latency_ms,
                "tool_context": tool_context,
            },
            data,
            user_api_key_dict,
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

        approval_id = _approval_header(data)
        if approval_id is not None and self._approvals is not None:
            data = self._use_approval(
                approval_id, data, session, caller.agent, user_api_key_dict, request_id
            )

        if route.strips_tools:
            data = dict(data)
            data.pop("tools", None)
            data.pop("functions", None)
            data.pop("function_call", None)
            # Explicitly forbid tool use so the model produces a text response
            # instead of generating a tool call that the API will reject.
            data["tool_choice"] = "none"
            messages = _with_prompt(messages, TOOLS_REMOVED_NOTICE)
            data["messages"] = messages

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
        try:
            return await self._post_call(user_api_key_dict, data, response)
        except SessionStoreUnavailable as exc:
            # The response is not released: its tool calls were never checked.
            error = self._store_outage(exc, "post_call", data, user_api_key_dict)
            self._attach_decision_error(error, data, user_api_key_dict)
            raise error from exc
        except Exception as exc:
            self._attach_decision_error(exc, data, user_api_key_dict)
            raise

    def _pre_call_stripped_tools(self, data: dict) -> bool:
        """Whether the pre-call route removed this request's tools."""
        stamp = _route_stamp(data)
        route = self._routing.routes.get(stamp.get("route", "")) if stamp else None
        return route is not None and route.strips_tools

    async def _post_call(
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

        refused = self._refusals.pop(request_id, None)
        if refused is not None:  # the retry's approval wasn't usable; nothing was generated
            return _approval_notice_response(response, refused)
        replay = self._replays.pop(request_id, None)
        replay_ok = False
        if replay is not None and self._approvals is not None:
            replay_ok = self._approvals.verify_replay(replay[0], _turn_calls(response)[0])
            if not replay_ok:
                self._emit_approval("replay_mismatch", replay[0], None, None, request_id)
                _remember(
                    self._approval_headers, request_id, {APPROVAL_STATUS_HEADER: "replay_mismatch"}
                )
                return _approval_notice_response(response, "replay_mismatch")

        generated_calls = _extract_response_sinks(
            response, include_reads=True, inventory=self._inventory
        )
        if not generated_calls:
            if self.config.enforce and self._pre_call_stripped_tools(data):
                return _tidied_response(response)
            return None
        egress_sinks = [
            c
            for c in generated_calls
            if c["category"] != "read" or "malformed" in c or "inventory" in c
        ]
        pre_level = _pre_call_level(data)
        data_class = _pre_call_class(data) or _MISSING_PRE_CALL_CLASS
        pre_route = self._routing.resolve(pre_level or _MISSING_PRE_CALL_LEVEL, data_class)
        if not egress_sinks and pre_route.hold != "all":
            # Read-only calls are released unless the route holds everything.
            return _replayed_response(response, replay[1]) if replay_ok and replay else None
        caller = caller_identity(user_api_key_dict)
        session = self._resolve_session(
            data, request_id, user_api_key_dict, messages, "post_call", agent=caller.agent
        )
        session_id = session.key

        features = _extract_features(
            session_id, messages, self.config.level, self.config.mode, self._inventory
        )
        features["sink_requested"] = bool(egress_sinks)
        features["streaming_tool_request"] = False
        features["malformed_tool_call"] = any("malformed" in s for s in egress_sinks)
        _check_inventory(features, egress_sinks)  # the generated calls, not the request's

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

        if self.config.mode != "session" and self._controls.classifier:
            # Stateless: judge on the classifier verdict, not bare provenance.
            features["untrusted_seen"] = features.get(
                "classifier_injection", False
            ) or features.get("classifier_error", False)
        elif self.config.mode != "session":
            # classifier=off (#196): provenance only — any untrusted source counts.
            features["untrusted_seen"] = bool(untrusted_sources)

        if self.config.level == "L3":
            if self.config.mode == "session":
                tainted_hashes = get_store().state(session_id).tainted_spans
            else:
                # Stateless: only content the classifier actually flagged INJECTION
                # is a tainted span — a clean file emailed verbatim must not match.
                # With classifier=off (#196) every untrusted source is tainted.
                tainted_hashes = [
                    s["content_hash"]
                    for s in untrusted_sources
                    if not self._controls.classifier or s.get("tool_call_id") in injected_ids
                ]
            features["tainted_spans_in_sink_args"] = tainted_spans_in_sink_args(
                tainted_hashes,
                egress_sinks,
                [_response_sink_message(egress_sinks)],
            )

        if self._allowlist is not None:
            _check_destinations(features, self._allowlist, egress_sinks)
        if self._controls.user_named:
            user_request = latest_user_request(messages)
            _check_user_named(
                features,
                [{**sink, "_user_request": user_request} for sink in egress_sinks],
                self._own_destinations,
            )

        risk_score, assessed_level, matched_rules = self._policy.assess(features)
        risk_level = _max_level(assessed_level, pre_level or _MISSING_PRE_CALL_LEVEL)
        route = self._routing.resolve(risk_level, data_class)
        policy_action = self._routing.resolve(risk_level).legacy_action
        output_action = _output_action(route, assessed_level, generated_calls, egress_sinks)
        _stamp_route(
            data, risk_level, data_class, route
        )  # the route header reports the final route

        if self.config.mode == "session":
            store = get_store()
            for sink in egress_sinks:
                store.record_sink(session_id, _public_sink(sink))
            if assessed_level != "low" and not replay_ok:  # the hold already counted
                features["escalation_count"] = store.record_escalation(session_id)

        final_action = output_action
        approval: dict[str, Any] | None = None
        pending_id: str | None = None
        if replay_ok and replay is not None and output_action != "block":
            final_action = "execute"  # approved: a block still wins
            approval = {"approval_ref": replay[0], "event": "replayed"}
        elif self._approvals is not None and self.config.enforce and output_action == "hold":
            calls, content, eligible = _turn_calls(response)
            if eligible and not any("malformed" in call for call in generated_calls):
                pending_id, record = self._approvals.create(
                    session_key=session_id,
                    session_ref=session.ref,
                    owner=_api_key_owner(user_api_key_dict),
                    agent=caller.agent,
                    calls=calls,
                    content=content,
                    summary={
                        "tools": [call["function"]["name"] for call in calls],
                        "unlisted_destinations": features.get("unlisted_destinations", []),
                        "matched_rules": matched_rules,
                        "risk_score": round(risk_score, 4),
                        "risk_level": risk_level,
                        "route": route.name,
                    },
                )
                approval = {
                    "approval_ref": record.ref,
                    "event": "requested",
                    "expires_in_seconds": int(self._approvals.ttl),
                }

        self._record_decision(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "phase": "post_call",
                "session_id": session.ref,
                "agent": caller.agent,
                "request_id": request_id,
                "mode": self.config.mode,
                "level": self.config.level,
                "controls": self._controls.summary(),
                "features": features,
                "risk_score": round(risk_score, 4),
                "risk_level": risk_level,
                "assessed_risk_level": assessed_level,
                "pre_call_risk_level": pre_level,
                "data_class": data_class,
                "route": route.name,
                "action": final_action,
                "policy_action": policy_action,
                **({"approval": approval} if approval is not None else {}),
                "matched_rules": matched_rules,
                "enforce": self.config.enforce,
                "tool_context": {
                    "generated_tool_call_count": len(generated_calls),
                    "generated_tool_calls": [_public_sink(call) for call in generated_calls],
                },
            },
            data,
            user_api_key_dict,
        )

        if not self.config.enforce or final_action == "execute":
            return _replayed_response(response, replay[1]) if replay_ok and replay else None
        if final_action == "block":
            import litellm.exceptions as _le

            raise _le.BadRequestError(
                message=str(PolicyViolation(risk_score, matched_rules)),
                model=data.get("model", ""),
                llm_provider="",
            )
        if pending_id is not None:
            _remember(
                self._approval_headers,
                request_id,
                {APPROVAL_HEADER: pending_id, APPROVAL_STATUS_HEADER: "pending"},
            )
        return _hold_response_tool_calls(
            response,
            risk_score,
            matched_rules or [f"route {route.name}"],
            pending=pending_id is not None,
            detailed=self._detailed_decisions(user_api_key_dict),
        )

    # ------------------------------------------------------------------
    # Held for approval (#174)
    # ------------------------------------------------------------------

    def _use_approval(
        self,
        approval_id: str,
        data: dict,
        session: _Session,
        agent: str | None,
        user_api_key_dict: Any,
        request_id: str,
    ) -> dict:
        """Claim an approval on retry; replay its calls, or answer why not.

        The streaming check comes first so a streaming retry never uses the
        approval: LiteLLM's mock path drops tool calls when streaming.
        """
        assert self._approvals is not None
        if data.get("stream"):
            self._emit_approval(
                "replay_refused", None, session.ref, agent, request_id, status="streaming"
            )
            import litellm.exceptions as _le

            raise _le.BadRequestError(
                message="SecureLiteLLM: retry an approved action without streaming; "
                "the approval has not been used",
                model=data.get("model", ""),
                llm_provider="",
            )
        claim = self._approvals.claim(
            approval_id, session_key=session.key, owner=_api_key_owner(user_api_key_dict)
        )
        self._emit_approval(
            "replay_claimed" if claim.ok else "replay_refused",
            claim.ref,
            session.ref,
            agent,
            request_id,
            status=claim.status,
        )
        data = dict(data)
        if claim.ok:
            # LiteLLM returns these calls without calling the model (mock path),
            # with their original ids and byte-identical arguments.
            data["mock_tool_calls"] = claim.calls
            _remember(self._replays, request_id, (claim.ref, claim.content))
        else:
            data["mock_response"] = "SecureLiteLLM approval not usable"  # replaced in post-call
            _remember(self._refusals, request_id, claim.status)
            _remember(self._approval_headers, request_id, {APPROVAL_STATUS_HEADER: claim.status})
        return data

    def _emit_approval(
        self,
        event: str,
        ref: str | None,
        session_ref: str | None,
        agent: str | None,
        request_id: str | None,
        **extra: Any,
    ) -> None:
        self.decision_logger.emit(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "phase": "approval",
                "event": event,
                "approval_ref": ref,
                "session_id": session_ref,
                "agent": agent,
                "request_id": request_id,
                "mode": self.config.mode,
                "level": self.config.level,
                "controls": self._controls.summary(),
                "features": {},
                "action": event,
                "matched_rules": [],
                "enforce": self.config.enforce,
                **extra,
            }
        )

    def _log_expired_approvals(self) -> None:
        if self._approvals is None:
            return
        for record in self._approvals.due_expiries():
            self._emit_approval("expired", record.ref, record.session_ref, record.agent, None)

    def approvals_list(self, user_api_key_dict: Any) -> dict[str, Any]:
        """Admin API: approvals waiting for a decision or a retry, with full arguments."""
        if self._approvals is None:
            raise ApprovalError(404, "approvals are not enabled")
        if _role(user_api_key_dict) not in _VIEWING_ROLES:
            raise ApprovalError(403, "only an admin can view approvals")
        self._log_expired_approvals()
        return {
            "approvals": [
                {
                    **record.public(with_arguments=True),
                    "expires_in_seconds": self._approvals.expires_in(record),
                }
                for record in self._approvals.pending()
            ]
        }

    def approvals_decide(self, ref: str, approve: bool, user_api_key_dict: Any) -> dict[str, Any]:
        """Admin API: approve or deny a pending approval. A denial counts as an escalation."""
        if self._approvals is None:
            raise ApprovalError(404, "approvals are not enabled")
        if _role(user_api_key_dict) not in _DECIDING_ROLES:
            raise ApprovalError(403, "only an admin can decide approvals")
        approver = getattr(user_api_key_dict, "user_id", None)
        approver = approver if isinstance(approver, str) else None
        record = self._approvals.decide(ref, approve=approve, approver=approver)
        extra: dict[str, Any] = {"approver": approver}
        if not approve and self.config.mode == "session":
            try:
                extra["escalation_count"] = get_store().record_escalation(record.session_key)
            except SessionStoreUnavailable:
                # The denial itself is already recorded and stands; only the
                # session's escalation count could not be raised.
                extra["escalation_count"] = None
                extra["escalation_recorded"] = False
        self._emit_approval(
            "approved" if approve else "denied",
            record.ref,
            record.session_ref,
            record.agent,
            None,
            **extra,
        )
        self._log_expired_approvals()
        return {**record.public(), "expires_in_seconds": self._approvals.expires_in(record)}


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


def _check_destinations(
    features: dict[str, Any], allowlist: Allowlist, sinks: list[dict[str, Any]]
) -> None:
    """Set the allowlist features (#167): which send destinations are not listed.

    Labels are domains, hosts or channels only, never a full address.
    """
    unlisted = allowlist.unlisted(sinks)
    features["destination_not_allowed"] = bool(unlisted)
    features["unlisted_destinations"] = unlisted


def _check_inventory(features: dict[str, Any], sinks: list[dict[str, Any]]) -> None:
    """Set the inventory features (#176): calls that contradict or escape the declared tools.

    Only tool names are recorded, never arguments.
    """
    violations = sorted({s["name"] for s in sinks if s.get("inventory") == "capability_violation"})
    unlisted = sorted({s["name"] for s in sinks if s.get("inventory") == "unlisted"})
    features["capability_violation"] = bool(violations)
    features["tool_unlisted"] = bool(unlisted)
    if violations:
        features["capability_violations"] = violations
    if unlisted:
        features["unlisted_tools"] = unlisted


def _check_user_named(
    features: dict[str, Any], sinks: list[dict[str, Any]], own: Allowlist
) -> None:
    """Set the user-named features (#212): which send destinations the user didn't type.

    Labels are domains, hosts or channels only, never a full address.
    """
    unnamed = not_user_named(sinks, own)
    features["destination_not_user_named"] = bool(unnamed)
    features["unnamed_destinations"] = unnamed


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


def _extract_response_sinks(
    response: Any, include_reads: bool = False, inventory: Inventory | None = None
) -> list[dict[str, Any]]:
    """Pull tool_calls out of a LiteLLM completion response object.

    Read-only calls are skipped unless include_reads is set. Fails closed
    (#82, #156): a call whose name or arguments cannot be parsed is returned
    as a sink with ``malformed`` set — even if its name looks like a read
    tool — so policy holds it rather than releasing it uninspected. With a
    declared inventory (#176) each sink carries ``inventory`` when the call
    contradicts its declaration or names an undeclared tool.
    """
    from router.taint import sink_category, tool_call_defect

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
            if isinstance(name, str):
                category = sink_category(name, arguments, inventory)
                flag = inventory.check(name, arguments) if inventory is not None else None
            else:
                category, flag = "other", None
            if category == "read" and defect is None and flag is None and not include_reads:
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
            if flag is not None:
                sink["inventory"] = flag
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
    pending: bool = False,
    detailed: bool = True,
) -> Any:
    """Return a copy of a response with generated tool calls removed."""
    held = copy.deepcopy(response)
    reason = ", ".join(matched_rules) or "policy review"
    purpose = "approval" if pending else "review"
    detail = f" (risk={risk_score:.3f}; rules={reason})" if detailed else ""
    notice = f"SecureLiteLLM held the generated tool call for {purpose}{detail}."

    for choice in getattr(held, "choices", None) or []:
        message = getattr(choice, "message", None)
        if message is None or not (getattr(message, "tool_calls", None) or []):
            continue
        message.tool_calls = None
        message.content = notice
        if hasattr(choice, "finish_reason"):
            choice.finish_reason = "content_filter"
    return held


def _turn_calls(response: Any) -> tuple[list[dict[str, Any]], str | None, bool]:
    """The held assistant turn: (tool calls with raw arguments, content, eligible).

    Eligible only for a single-choice response whose calls all have an id, a
    name and string arguments: the whole turn is approved or denied as one unit.
    """
    choices = getattr(response, "choices", None) or []
    if len(choices) != 1:
        return [], None, False
    message = getattr(choices[0], "message", None)
    tool_calls = getattr(message, "tool_calls", None) or []
    calls = []
    for call in tool_calls:
        function = getattr(call, "function", None)
        name = getattr(function, "name", None)
        arguments = getattr(function, "arguments", None)
        call_id = getattr(call, "id", None)
        if not (isinstance(name, str) and isinstance(arguments, str) and call_id):
            return [], None, False
        calls.append(
            {
                "id": call_id,
                "type": getattr(call, "type", None) or "function",
                "function": {"name": name, "arguments": arguments},
            }
        )
    content = getattr(message, "content", None)
    return calls, content if isinstance(content, str) else None, bool(calls)


def _replayed_response(response: Any, content: str | None) -> Any:
    """An approved replay, shaped like the original tool turn.

    LiteLLM's mock path answers with finish_reason "stop" and filler text.
    """
    released = copy.deepcopy(response)
    for choice in getattr(released, "choices", None) or []:
        message = getattr(choice, "message", None)
        if message is not None:
            message.content = content
        if hasattr(choice, "finish_reason"):
            choice.finish_reason = "tool_calls"
    return released


def _approval_notice_response(response: Any, status: str) -> Any:
    """A held-shaped answer to a retry whose approval can't be used."""
    held = copy.deepcopy(response)
    reason = _APPROVAL_NOTICES.get(status, _APPROVAL_NOTICES["unknown"])
    for choice in getattr(held, "choices", None) or []:
        message = getattr(choice, "message", None)
        if message is not None:
            message.tool_calls = None
            message.content = f"SecureLiteLLM: {reason}."
        if hasattr(choice, "finish_reason"):
            choice.finish_reason = "content_filter"
    return held


_WORKER_ENV = ("NUM_WORKERS", "WEB_CONCURRENCY")


def check_single_worker(environ: dict[str, str], *, session_mode: bool, approvals: bool) -> None:
    """Refuse to start with in-process state across more than one worker.

    With the memory session store, sessions, escalation counts and approvals
    live in this process's memory, behind a lock that covers this process
    only. (Pass ``False`` for both when the store is shared, #169.) With several workers each
    has its own copy: a follow-up request on another worker is rejected as an
    unknown session, an approval can't be found or decided, and per-session
    escalation is split. Until the shared store (#169) lands, these need one
    worker. LiteLLM's CLI exports NUM_WORKERS for uvicorn, gunicorn and granian;
    WEB_CONCURRENCY covers servers started outside it that honour it. A server
    started some other way (e.g. ``uvicorn --workers N`` by hand) is not seen.
    """
    stateful = [
        name
        for name, on in (("ROUTER_MODE=session", session_mode), ("approvals: on", approvals))
        if on
    ]
    if not stateful:
        return
    for var in _WORKER_ENV:
        raw = environ.get(var, "").strip()
        if not raw:
            continue
        try:
            workers = int(raw)
        except ValueError:
            raise ValueError(f"{var} must be an integer, got {raw!r}") from None
        if workers > 1:
            raise ValueError(
                f"{var}={workers}, but {' and '.join(stateful)} keep state in this process's "
                "memory, which other workers can't see; run one worker until the shared "
                "store (#169) lands"
            )


def _approval_store(ttl: float) -> Any:
    """Approvals live where sessions do: Postgres with SESSION_STORE=postgres (#169)."""
    store = get_store()
    if store.backend == "postgres":
        from router.pg_approvals import PostgresApprovalStore

        return PostgresApprovalStore(store.database, store.secret, ttl)  # type: ignore[attr-defined]
    return ApprovalStore(ttl)


def _proxy_app_and_auth() -> tuple[Any, Any]:
    """LiteLLM's proxy app and its key authentication (tests replace this)."""
    from litellm.proxy.auth.user_api_key_auth import user_api_key_auth
    from litellm.proxy.proxy_server import app

    return app, user_api_key_auth


# app id -> the hook its approval routes serve. Routes are added once per app;
# a later hook instance (tests) takes them over.
_APPROVAL_ROUTE_HOOKS: dict[int, "RouterHook"] = {}
_DECISION_ROUTE_HOOKS: WeakKeyDictionary[Any, "RouterHook"] = WeakKeyDictionary()


def register_decision_routes(app: Any, auth_dependency: Any, hook: "RouterHook") -> None:
    """Authenticated history; normal keys cannot inspect classifier feedback by default."""
    first = app not in _DECISION_ROUTE_HOOKS
    _DECISION_ROUTE_HOOKS[app] = hook
    if not first:
        return
    from fastapi import Depends, HTTPException, Query

    async def history(
        session: str = Query(pattern=r"^[0-9a-f]{16}$"),
        auth: Any = Depends(auth_dependency),
    ) -> dict:
        current = _DECISION_ROUTE_HOOKS[app]
        admin = _role(auth) in _VIEWING_ROLES
        owner = _api_key_owner(auth)
        if not admin and not (current.config.expose_decisions and owner):
            raise HTTPException(403, "only an admin can view decision history")
        try:
            records = await asyncio.to_thread(
                current._decision_history.read, session, None if admin else owner
            )
        except SessionStoreUnavailable as exc:
            raise HTTPException(503, "decision history is unavailable") from exc
        return {
            "decisions": records,
            "session_id": session,
            "retention_seconds": 3600,
            "limit": 300,
            "backend": current._decision_history.backend,
        }

    app.add_api_route(DECISIONS_PATH, history, methods=["GET"])


def register_approval_routes(app: Any, auth_dependency: Any, hook: "RouterHook") -> None:
    """Add the admin approval API to the proxy (#174).

    Served by the same process as the hook, so it shares the approval store,
    and authenticated by LiteLLM's own key check. Agent keys limited to the
    chat routes (#148) are refused by LiteLLM before reaching these handlers;
    the handlers also require an admin role.
    """
    first = id(app) not in _APPROVAL_ROUTE_HOOKS
    _APPROVAL_ROUTE_HOOKS[id(app)] = hook
    if not first:
        return
    from fastapi import Depends, HTTPException

    def current() -> "RouterHook":
        return _APPROVAL_ROUTE_HOOKS[id(app)]

    async def list_approvals(auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        try:
            return current().approvals_list(auth)
        except ApprovalError as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
        except SessionStoreUnavailable as exc:
            raise HTTPException(
                status_code=503, detail="the approval store is unavailable"
            ) from exc

    async def approve(approval_ref: str, auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        try:
            return current().approvals_decide(approval_ref, True, auth)
        except ApprovalError as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
        except SessionStoreUnavailable as exc:
            raise HTTPException(
                status_code=503, detail="the approval store is unavailable"
            ) from exc

    async def deny(approval_ref: str, auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        try:
            return current().approvals_decide(approval_ref, False, auth)
        except ApprovalError as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
        except SessionStoreUnavailable as exc:
            raise HTTPException(
                status_code=503, detail="the approval store is unavailable"
            ) from exc

    app.add_api_route(APPROVALS_PATH, list_approvals, methods=["GET"])
    app.add_api_route(APPROVALS_PATH + "/{approval_ref}/approve", approve, methods=["POST"])
    app.add_api_route(APPROVALS_PATH + "/{approval_ref}/deny", deny, methods=["POST"])


# Module-level instance — LiteLLM config callbacks must point at an instance, not a class.
proxy_handler_instance = RouterHook()
if getattr(sys.modules.get("litellm.proxy.proxy_server"), "app", None) is not None:
    proxy_handler_instance.register_proxy_routes()
