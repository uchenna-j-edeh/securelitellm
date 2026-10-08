"""Router configuration loaded from environment variables."""

import os
from dataclasses import dataclass
from typing import Literal

Mode = Literal["stateless", "session"]
Level = Literal["L0", "L1", "L2", "L3"]
ClassifierBackend = Literal["local", "promptguard", "llmguard", "mock", "none"]

_VALID_MODES = ("stateless", "session")
_VALID_LEVELS = ("L0", "L1", "L2", "L3")
_VALID_BACKENDS = ("local", "promptguard", "llmguard", "mock", "none")


@dataclass
class RouterConfig:
    mode: Mode = "session"
    level: Level = "L3"
    log_path: str = "-"  # "-" = stdout
    classifier_backend: ClassifierBackend = "none"
    enforce: bool = True  # secure by default; set false explicitly for audit-only experiments
    policy_path: str = ""  # empty = use bundled deploy/policy.yaml
    hardened_model: str = "mock"  # model alias to route-hardened requests to

    @classmethod
    def from_env(cls) -> "RouterConfig":
        mode = os.getenv("ROUTER_MODE", "session")
        level = os.getenv("ROUTER_LEVEL", "L3")
        log_path = os.getenv("ROUTER_LOG_PATH", "-")
        classifier_backend = os.getenv("CLASSIFIER_BACKEND", "none").lower()
        enforce = os.getenv("ROUTER_ENFORCE", "true").lower() in ("1", "true", "yes")
        policy_path = os.getenv("POLICY_PATH", "")
        hardened_model = os.getenv("ROUTER_HARDENED_MODEL", "mock")

        if mode not in _VALID_MODES:
            raise ValueError(f"ROUTER_MODE must be one of {_VALID_MODES}, got {mode!r}")
        if level not in _VALID_LEVELS:
            raise ValueError(f"ROUTER_LEVEL must be one of {_VALID_LEVELS}, got {level!r}")
        if classifier_backend not in _VALID_BACKENDS:
            raise ValueError(
                f"CLASSIFIER_BACKEND must be one of {_VALID_BACKENDS}, got {classifier_backend!r}"
            )

        return cls(  # type: ignore[arg-type]
            mode=mode,
            level=level,
            log_path=log_path,
            classifier_backend=classifier_backend,
            enforce=enforce,
            policy_path=policy_path,
            hardened_model=hardened_model,
        )
