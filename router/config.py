"""Router configuration loaded from environment variables."""

import os
from dataclasses import dataclass
from typing import Literal

Mode = Literal["stateless", "session"]
Level = Literal["L0", "L1", "L2", "L3"]

_VALID_MODES = ("stateless", "session")
_VALID_LEVELS = ("L0", "L1", "L2", "L3")


@dataclass
class RouterConfig:
    mode: Mode = "stateless"
    level: Level = "L0"
    log_path: str = "-"  # "-" = stdout

    @classmethod
    def from_env(cls) -> "RouterConfig":
        mode = os.getenv("ROUTER_MODE", "stateless")
        level = os.getenv("ROUTER_LEVEL", "L0")
        log_path = os.getenv("ROUTER_LOG_PATH", "-")

        if mode not in _VALID_MODES:
            raise ValueError(f"ROUTER_MODE must be one of {_VALID_MODES}, got {mode!r}")
        if level not in _VALID_LEVELS:
            raise ValueError(f"ROUTER_LEVEL must be one of {_VALID_LEVELS}, got {level!r}")

        return cls(mode=mode, level=level, log_path=log_path)  # type: ignore[arg-type]
