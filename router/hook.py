"""LiteLLM CustomLogger implementing async_pre_call_hook.

Registered in litellm_config.yaml under litellm_settings.callbacks.
Pass-through in M1 — observes and logs every request without modification.
Taint tracking, classification, and policy enforcement added in M2-M4.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Any

from litellm.integrations.custom_logger import CustomLogger

from router.config import RouterConfig
from router.logger import DecisionLogger
from router.parser import extract_tool_context


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

        # Session ID from agent-injected header; falls back to per-request stub.
        # M2 adds proper per-run session derivation.
        headers = data.get("metadata", {}).get("headers", {}) or {}
        session_id = headers.get("x-agent-run-id") or f"no-session-{request_id[:8]}"

        tool_context = extract_tool_context(data.get("messages", []))

        latency_ms = round((time.perf_counter() - t0) * 1000, 3)

        self.decision_logger.emit(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "request_id": request_id,
                "mode": self.config.mode,
                "level": self.config.level,
                "features": {},
                "risk_score": 0.0,
                "action": "allow",
                "latency_ms": latency_ms,
                "tool_context": tool_context,
            }
        )

        return data  # pass-through


# Module-level instance — LiteLLM config callbacks must point at an instance, not a class.
proxy_handler_instance = RouterHook()
