"""Admin routing table: (risk level, data class) → route (#140).

A route is a LiteLLM model group plus the controls the hook enforces for it.
The policy file declares routes and a matrix:

    routes:
      standard:   { model: requested }            # keep the client's model
      hardened:   { model: hardened }
      quarantine: { model: requested, tools: none }

    matrix:
      low:      { public: standard }
      elevated: { public: hardened }
      high:     { public: quarantine }
      critical: block

Safety properties enforced at load time (a violation raises ValueError, so the
proxy refuses to start):

- every (risk level, data class) cell is filled with a defined route or `block`;
- a column never becomes less restrictive as the risk level rises;
- the `critical` row is `block` in every column (policy floor, #121).

A policy file without `routes`/`matrix` gets the legacy table, which
reproduces the pre-#140 actions exactly: low → allow, elevated →
ROUTER_HARDENED_MODEL, high → strip tools, critical → block.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from router.policy import LEGACY_ACTIONS, RISK_LEVELS, Action, RiskLevel

DataClass = Literal["public"]
DATA_CLASSES: tuple[DataClass, ...] = ("public",)  # #181 adds internal/sensitive

BLOCK = "block"
REQUESTED = "requested"  # route model value: keep the client's requested model

_ROUTE_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_ROUTE_KEYS = {"model", "tools"}
_TOOLS_MODES = ("keep", "none")


@dataclass(frozen=True)
class Route:
    name: str
    model: str | None = None  # None = keep the client's requested model
    tools: Literal["keep", "none"] = "keep"

    @property
    def blocks(self) -> bool:
        return self.name == BLOCK

    @property
    def strips_tools(self) -> bool:
        return self.tools == "none"

    @property
    def rank(self) -> int:
        """Restrictiveness, derived from enforced controls (model choice is not a control)."""
        if self.blocks:
            return 2
        return 1 if self.strips_tools else 0

    @property
    def legacy_action(self) -> Action:
        """The pre-#140 action this route corresponds to, for decision records."""
        if self.blocks:
            return "block"
        if self.strips_tools:
            return "strip-tools"
        if self.model is not None:
            return "route-hardened"
        return "allow"


BLOCK_ROUTE = Route(name=BLOCK)


@dataclass(frozen=True)
class RoutingTable:
    routes: dict[str, Route]
    matrix: dict[tuple[RiskLevel, DataClass], Route]
    source: Literal["policy", "legacy"]

    def resolve(self, risk_level: RiskLevel, data_class: DataClass = "public") -> Route:
        return self.matrix[(risk_level, data_class)]

    def summary(self) -> dict[str, Any]:
        """JSON-safe description for the startup audit record."""
        return {
            "source": self.source,
            "routes": {
                name: {"model": route.model or REQUESTED, "tools": route.tools}
                for name, route in self.routes.items()
            },
            "matrix": {
                level: {dc: self.matrix[(level, dc)].name for dc in DATA_CLASSES}
                for level in RISK_LEVELS
            },
        }

    @classmethod
    def legacy(cls, hardened_model: str) -> "RoutingTable":
        """The pre-#140 behavior, expressed as a routing table."""
        routes = {
            "standard": Route(name="standard"),
            "hardened": Route(name="hardened", model=hardened_model),
            "quarantine": Route(name="quarantine", tools="none"),
        }
        by_action = {
            "allow": routes["standard"],
            "route-hardened": routes["hardened"],
            "strip-tools": routes["quarantine"],
            "block": BLOCK_ROUTE,
        }
        matrix = {
            (level, dc): by_action[LEGACY_ACTIONS[level]]
            for level in RISK_LEVELS
            for dc in DATA_CLASSES
        }
        return cls(routes=routes, matrix=matrix, source="legacy")

    @classmethod
    def from_mapping(cls, raw: dict[str, Any], legacy_hardened_model: str) -> "RoutingTable":
        has_routes, has_matrix = "routes" in raw, "matrix" in raw
        if not has_routes and not has_matrix:
            return cls.legacy(legacy_hardened_model)
        if has_routes != has_matrix:
            raise ValueError("Policy must define both 'routes' and 'matrix', or neither")
        routes = _parse_routes(raw["routes"])
        matrix = _parse_matrix(raw["matrix"], routes)
        _check_monotonic(matrix)
        return cls(routes=routes, matrix=matrix, source="policy")


def _parse_routes(raw: Any) -> dict[str, Route]:
    if not isinstance(raw, dict) or not raw:
        raise ValueError("Policy 'routes' must be a non-empty mapping")
    routes: dict[str, Route] = {}
    for name, spec in raw.items():
        if not isinstance(name, str) or not _ROUTE_NAME.match(name):
            raise ValueError(f"Route name {name!r} must match {_ROUTE_NAME.pattern}")
        if name == BLOCK:
            raise ValueError("'block' is a reserved route and cannot be redefined")
        if not isinstance(spec, dict):
            raise ValueError(f"Route {name!r} must be a mapping")
        unknown = set(spec) - _ROUTE_KEYS
        if unknown:
            raise ValueError(f"Route {name!r} has unknown keys: {sorted(unknown)}")
        model = spec.get("model")
        if not isinstance(model, str) or not model.strip():
            raise ValueError(f"Route {name!r} must name a model group, or 'requested'")
        tools = spec.get("tools", "keep")
        if tools not in _TOOLS_MODES:
            raise ValueError(f"Route {name!r} tools must be one of {_TOOLS_MODES}")
        routes[name] = Route(
            name=name,
            model=None if model == REQUESTED else model.strip(),
            tools=tools,
        )
    return routes


def _parse_matrix(raw: Any, routes: dict[str, Route]) -> dict[tuple[RiskLevel, DataClass], Route]:
    if not isinstance(raw, dict):
        raise ValueError("Policy 'matrix' must be a mapping")
    unknown_levels = set(raw) - set(RISK_LEVELS)
    if unknown_levels:
        raise ValueError(f"Matrix has unknown risk levels: {sorted(unknown_levels)}")

    def lookup(name: Any, where: str) -> Route:
        if name == BLOCK:
            return BLOCK_ROUTE
        if not isinstance(name, str) or name not in routes:
            raise ValueError(f"Matrix cell {where} names an undefined route: {name!r}")
        return routes[name]

    matrix: dict[tuple[RiskLevel, DataClass], Route] = {}
    for level in RISK_LEVELS:
        if level not in raw:
            raise ValueError(f"Matrix is missing risk level {level!r}")
        row = raw[level]
        if isinstance(row, str):  # one route for every data class
            for dc in DATA_CLASSES:
                matrix[(level, dc)] = lookup(row, f"{level}")
            continue
        if not isinstance(row, dict):
            raise ValueError(f"Matrix row {level!r} must be a route name or a mapping")
        unknown_classes = set(row) - set(DATA_CLASSES)
        if unknown_classes:
            raise ValueError(
                f"Matrix row {level!r} has unknown data classes: {sorted(unknown_classes)}"
            )
        for dc in DATA_CLASSES:
            if dc not in row:
                raise ValueError(f"Matrix cell {level}/{dc} is missing")
            matrix[(level, dc)] = lookup(row[dc], f"{level}/{dc}")
    return matrix


def _check_monotonic(matrix: dict[tuple[RiskLevel, DataClass], Route]) -> None:
    for dc in DATA_CLASSES:
        if not matrix[("critical", dc)].blocks:
            raise ValueError(f"Matrix cell critical/{dc} must be 'block' (policy floor)")
        for lower, higher in zip(RISK_LEVELS, RISK_LEVELS[1:]):
            a, b = matrix[(lower, dc)], matrix[(higher, dc)]
            if b.rank < a.rank:
                raise ValueError(
                    f"Matrix column {dc!r} becomes less restrictive from {lower!r} "
                    f"({a.name}) to {higher!r} ({b.name})"
                )
