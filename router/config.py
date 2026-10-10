"""Router configuration loaded from environment variables."""

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Mode = Literal["stateless", "session"]
Level = Literal["L0", "L1", "L2", "L3"]
ClassifierBackend = Literal["local", "promptguard", "llmguard", "mock", "none"]

_VALID_MODES = ("stateless", "session")
_VALID_LEVELS = ("L0", "L1", "L2", "L3")
_VALID_BACKENDS = ("local", "promptguard", "llmguard", "mock", "none")

_BUNDLED_POLICY = Path(__file__).parent.parent / "deploy" / "policy.yaml"

# Configurations considered unsafe under ROUTER_LOCK=true.
_UNSAFE_IF_LOCKED: list[tuple[str, object]] = [
    ("enforce", False),
    ("classifier_backend", "none"),
]


def _policy_sha256(policy_path: str) -> str:
    """Return hex SHA-256 of the resolved policy file, or 'missing' if not found."""
    resolved = Path(policy_path) if policy_path else _BUNDLED_POLICY
    try:
        return hashlib.sha256(resolved.read_bytes()).hexdigest()
    except OSError:
        return "missing"


@dataclass
class RouterConfig:
    mode: Mode = "session"
    level: Level = "L3"
    log_path: str = "-"  # "-" = stdout
    classifier_backend: ClassifierBackend = "none"
    enforce: bool = True  # secure by default; set false explicitly for audit-only experiments
    policy_path: str = ""  # empty = use bundled deploy/policy.yaml
    hardened_model: str = "mock"  # model alias to route-hardened requests to
    lock: bool = False  # ROUTER_LOCK=true rejects unsafe configs at startup

    @classmethod
    def from_env(cls) -> "RouterConfig":
        mode = os.getenv("ROUTER_MODE", "session")
        level = os.getenv("ROUTER_LEVEL", "L3")
        log_path = os.getenv("ROUTER_LOG_PATH", "-")
        classifier_backend = os.getenv("CLASSIFIER_BACKEND", "none").lower()
        enforce = os.getenv("ROUTER_ENFORCE", "true").lower() in ("1", "true", "yes")
        policy_path = os.getenv("POLICY_PATH", "")
        hardened_model = os.getenv("ROUTER_HARDENED_MODEL", "mock")
        lock = os.getenv("ROUTER_LOCK", "false").lower() in ("1", "true", "yes")

        if mode not in _VALID_MODES:
            raise ValueError(f"ROUTER_MODE must be one of {_VALID_MODES}, got {mode!r}")
        if level not in _VALID_LEVELS:
            raise ValueError(f"ROUTER_LEVEL must be one of {_VALID_LEVELS}, got {level!r}")
        if classifier_backend not in _VALID_BACKENDS:
            raise ValueError(
                f"CLASSIFIER_BACKEND must be one of {_VALID_BACKENDS}, got {classifier_backend!r}"
            )

        cfg = cls(  # type: ignore[arg-type]
            mode=mode,
            level=level,
            log_path=log_path,
            classifier_backend=classifier_backend,
            enforce=enforce,
            policy_path=policy_path,
            hardened_model=hardened_model,
            lock=lock,
        )

        if lock:
            for field, unsafe_value in _UNSAFE_IF_LOCKED:
                if getattr(cfg, field) == unsafe_value:
                    raise ValueError(
                        f"ROUTER_LOCK=true rejects unsafe config: {field}={unsafe_value!r}"
                    )

        return cfg

    def startup_record(self) -> dict:
        """Return a structured audit record describing the effective config at startup."""
        return {
            "event": "startup",
            "mode": self.mode,
            "level": self.level,
            "enforce": self.enforce,
            "classifier_backend": self.classifier_backend,
            "hardened_model": self.hardened_model,
            "policy_path": self.policy_path or str(_BUNDLED_POLICY),
            "policy_sha256": _policy_sha256(self.policy_path),
            "lock": self.lock,
        }
