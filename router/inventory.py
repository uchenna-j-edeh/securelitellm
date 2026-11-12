"""Declared tool inventory (#176).

The ``tools:`` section of the policy declares what each tool *is*, so the
router stops guessing a tool's capability from its name::

    tools:
      read_file:          {capability: local-read}
      get_github_issue:   {capability: network-read, destination: https://api.github.com}
      fetch_url:          {capability: network-read}
      send_email:         {capability: egress}
      run_command:        {capability: exec}

A declaration is a claim, not a promise the tool keeps. The inventory decides
what the gateway will *release*; what a tool can actually do is bounded by its
credentials and network (#111, #223). What the gateway can check is a
contradiction between the claim and the call:

- a ``local-read`` tool whose call names any destination (a URL, host,
  address or channel) is a ``capability_violation``;
- a ``network-read`` tool with a fixed ``destination`` whose call names any
  other host, or any address or channel, is a ``capability_violation``;
- a tool missing from a non-empty inventory is ``unlisted``.

The policy turns both into risk (rules ``capability_violation`` and
``tool_unlisted``). Without a ``tools:`` section nothing changes: the name
patterns in :mod:`router.taint` decide, as before.

Capabilities:

- ``local-read``: reads local data; never names a destination.
- ``network-read``: requests a remote service. With ``destination`` set, only
  that origin (``scheme://host[:port]``, deploy-time config, never the tool's
  own metadata). Without, the destination is decided per call by the
  allowlist and user-named checks (#218).
- ``egress``: sends data out; destinations come from ``allowed_destinations``.
- ``write``: persists data.
- ``exec``: runs commands. Never a plain grant; command policy is #222.

The declared destination never relaxes the allowlist or user-named checks:
a URL in a call is still authorized exactly (#229). It only adds the
contradiction check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

from router.allowlist import _URL_ARGS, call_destinations, destinations
from router.taint import network_targets

CAPABILITIES = ("local-read", "network-read", "egress", "write", "exec")

# Sink category (router.taint) for each capability. ``exec`` is "other":
# unknown to every destination check, so it is held whenever the allowlist is
# on, until #222 gives it a policy of its own.
_CATEGORY = {
    "local-read": "read",
    "network-read": "read",
    "egress": "exfil",
    "write": "write",
    "exec": "other",
}
_DEFAULT_PORTS = {"http": 80, "https": 443}

UNLISTED = "unlisted"
CAPABILITY_VIOLATION = "capability_violation"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    capability: str
    destination: str | None = None  # origin, for network-read only


def origin(url: str) -> str | None:
    """``scheme://host[:port]`` of *url*, lowercased, default port dropped; None if unparseable."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".").lower()
    if not scheme or not host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def _parse_destination(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Tool {name!r}: destination must be a URL origin like https://host")
    parts = urlsplit(value.strip())
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Tool {name!r}: destination must start with http:// or https://")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError(
            f"Tool {name!r}: destination is an origin (scheme://host[:port]) with no path or query"
        )
    result = origin(value)
    if result is None:
        raise ValueError(f"Tool {name!r}: destination {value!r} is not a valid URL origin")
    return result


class Inventory:
    """The declared tools of one policy."""

    def __init__(self, tools: Mapping[str, ToolSpec]) -> None:
        self._tools = dict(tools)

    @classmethod
    def from_mapping(cls, document: Mapping[str, Any]) -> Inventory | None:
        """The inventory in a policy document, or None if it declares none."""
        if "tools" not in document:
            return None
        raw = document.get("tools")
        if raw is None:
            raw = {}
        if not isinstance(raw, Mapping):
            raise ValueError("Policy 'tools' must be a mapping of tool name to declaration")
        tools: dict[str, ToolSpec] = {}
        for name, spec in raw.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError("Policy 'tools' has an empty tool name")
            if not isinstance(spec, Mapping):
                raise ValueError(f"Tool {name!r}: declaration must be a mapping")
            unknown = set(spec) - {"capability", "destination"}
            if unknown:
                raise ValueError(f"Tool {name!r}: unknown keys {sorted(unknown)}")
            capability = spec.get("capability")
            if capability not in CAPABILITIES:
                raise ValueError(f"Tool {name!r}: capability must be one of {list(CAPABILITIES)}")
            destination = None
            if "destination" in spec:
                if capability != "network-read":
                    raise ValueError(
                        f"Tool {name!r}: only network-read tools take a destination; "
                        "egress destinations belong in allowed_destinations"
                    )
                destination = _parse_destination(name, spec["destination"])
            tools[name] = ToolSpec(name=name, capability=capability, destination=destination)
        return cls(tools)

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def category(self, name: str) -> str | None:
        """The sink category a declared tool starts from, or None if not declared."""
        spec = self._tools.get(name)
        return _CATEGORY[spec.capability] if spec else None

    def check(self, name: str, arguments: Any) -> str | None:
        """``unlisted``, ``capability_violation`` or None for one tool call."""
        spec = self._tools.get(name)
        if spec is None:
            return UNLISTED
        if spec.capability == "local-read":
            return CAPABILITY_VIOLATION if call_destinations(arguments) else None
        if spec.capability == "network-read" and spec.destination:
            if any(origin(url) != spec.destination for url in network_targets(arguments)):
                return CAPABILITY_VIOLATION
            text = arguments if isinstance(arguments, str) else ""
            if any(True for _ in destinations(text, skip=_URL_ARGS)):
                return CAPABILITY_VIOLATION
        return None

    def summary(self) -> dict[str, Any]:
        """Counts per capability, for the startup record."""
        counts = {capability: 0 for capability in CAPABILITIES}
        for spec in self._tools.values():
            counts[spec.capability] += 1
        return {"declared": len(self._tools), **{k: v for k, v in counts.items() if v}}
