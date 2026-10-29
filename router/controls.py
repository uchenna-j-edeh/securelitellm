"""Protection switches (#196): which controls are part of this configuration.

Each protection can be switched on or off so the eval can measure every
combination and the demo can run the best one. Session memory is ROUTER_MODE
and stays there; this module covers the rest.

  classifier  on: tool results are judged by the injection classifier, which is
                  then required (a missing classifier rejects the request, C10b).
              off: the classifier is not part of the configuration. Every
                  untrusted tool result counts as untrusted because of where it
                  came from (provenance-only taint, #192), in both modes.
  allowlist   on: every send destination must be on the policy's
                  allowed_destinations (#167, router/allowlist.py).
              off: destinations are not checked.

Set in the policy's ``controls:`` section; ROUTER_CONTROLS overrides it, e.g.
``ROUTER_CONTROLS="classifier=off,allowlist=off"``. Unknown names or values
stop startup.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, replace
from typing import Any

CONTROLS_ENV = "ROUTER_CONTROLS"

_ON = {"on", "true", "yes", "1"}
_OFF = {"off", "false", "no", "0"}


@dataclass(frozen=True)
class Controls:
    classifier: bool = True
    allowlist: bool = False

    def summary(self) -> dict[str, str]:
        """{"classifier": "on", ...} for startup and decision records."""
        return {name: "on" if value else "off" for name, value in asdict(self).items()}

    def label(self) -> str:
        """``classifier=on,allowlist=off``: the ROUTER_CONTROLS form, used in eval output."""
        return ",".join(f"{name}={value}" for name, value in self.summary().items())


_NAMES = tuple(asdict(Controls()))


def _switch(name: str, value: Any, where: str) -> bool:
    # YAML 1.1 reads bare on/off as booleans; accept those and the strings.
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _ON:
        return True
    if text in _OFF:
        return False
    raise ValueError(f"{where}: {name} must be on or off, got {value!r}")


def _apply(controls: Controls, values: dict[str, Any], where: str) -> Controls:
    unknown = sorted(set(values) - set(_NAMES))
    if unknown:
        raise ValueError(f"{where}: unknown controls {unknown}; known: {list(_NAMES)}")
    return replace(controls, **{n: _switch(n, v, where) for n, v in values.items()})


def parse_env(value: str) -> dict[str, str]:
    """``"classifier=off,allowlist=on"`` → {"classifier": "off", "allowlist": "on"}."""
    values: dict[str, str] = {}
    for item in value.split(","):
        if not item.strip():
            continue
        name, sep, setting = item.partition("=")
        if not sep or not name.strip():
            raise ValueError(f"{CONTROLS_ENV}: expected name=on|off, got {item.strip()!r}")
        values[name.strip()] = setting.strip()
    return values


def resolve_controls(policy_document: dict[str, Any], env: str | None = None) -> Controls:
    """Defaults, then the policy's ``controls:`` section, then ROUTER_CONTROLS."""
    section = policy_document.get("controls") or {}
    if not isinstance(section, dict):
        raise ValueError("policy controls must be a mapping of name: on|off")
    controls = _apply(Controls(), section, "policy controls")
    env_value = os.environ.get(CONTROLS_ENV, "") if env is None else env
    controls = _apply(controls, parse_env(env_value), CONTROLS_ENV)
    if controls.allowlist and "allowed_destinations" not in policy_document:
        # Refuse rather than run without the list the switch promises to enforce.
        raise ValueError("allowlist=on needs an allowed_destinations section in the policy")
    return controls
