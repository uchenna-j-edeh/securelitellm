"""M4 Policy Engine: feature set → risk score → routing action.

Rules are loaded from a YAML file (POLICY_PATH env var or the bundled default).
Each rule has a `when` block (all conditions ANDed) and a `score` (0–1).
Risk score = max score of all matching rules.  Action is determined by
comparing the risk score against configurable thresholds.

Actions
-------
allow           Pass through unchanged.
route-hardened  Redirect to ROUTER_HARDENED_MODEL (a more restricted model alias).
strip-tools     Remove tool definitions from the request so the LLM cannot call tools.
block           Reject the request entirely (raises PolicyViolation).

Audit mode (ROUTER_ENFORCE=false)
----------------------------------
Computes risk score and action but always passes through.  Lets you collect
ground-truth labels before flipping enforcement on.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Action = Literal["allow", "route-hardened", "strip-tools", "block"]

_BUNDLED_POLICY = Path(__file__).parent.parent / "deploy" / "policy.yaml"
_DEFAULT_THRESHOLDS: dict[str, float] = {
    "route_hardened": 0.4,
    "strip_tools": 0.7,
    "block": 0.9,
}


class PolicyViolation(Exception):
    """Raised when a request is blocked by the policy engine."""

    def __init__(self, risk_score: float, rule_ids: list[str]) -> None:
        self.risk_score = risk_score
        self.rule_ids = rule_ids
        super().__init__(f"Request blocked by policy (score={risk_score:.3f}, rules={rule_ids})")


@dataclass
class PolicyRule:
    id: str
    when: dict[str, Any]  # feature_name → expected value (all ANDed)
    score: float  # 0–1 contribution when this rule matches


@dataclass
class PolicyConfig:
    rules: list[PolicyRule] = field(default_factory=list)
    thresholds: dict[str, float] = field(default_factory=lambda: dict(_DEFAULT_THRESHOLDS))


class PolicyEngine:
    def __init__(self, config: PolicyConfig) -> None:
        self._config = config

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> "PolicyEngine":
        import yaml  # only needed at load time

        resolved = Path(path) if path else Path(os.environ.get("POLICY_PATH", _BUNDLED_POLICY))
        if not resolved.exists():
            return cls(PolicyConfig())  # no rules file → always allow

        with resolved.open() as fh:
            raw = yaml.safe_load(fh) or {}

        rules = [
            PolicyRule(id=r["id"], when=r.get("when", {}), score=float(r["score"]))
            for r in raw.get("rules", [])
        ]
        thresholds = {**_DEFAULT_THRESHOLDS, **raw.get("thresholds", {})}
        return cls(PolicyConfig(rules=rules, thresholds=thresholds))

    def evaluate(self, features: dict[str, Any]) -> tuple[float, Action, list[str]]:
        """Return (risk_score, action, matched_rule_ids)."""
        matched: list[PolicyRule] = []
        for rule in self._config.rules:
            if self._matches(rule.when, features):
                matched.append(rule)

        risk_score = max((r.score for r in matched), default=0.0)
        action = self._score_to_action(risk_score)
        return risk_score, action, [r.id for r in matched]

    def _matches(self, conditions: dict[str, Any], features: dict[str, Any]) -> bool:
        for key, expected in conditions.items():
            actual = features.get(key)
            if actual != expected:
                return False
        return True

    def _score_to_action(self, score: float) -> Action:
        t = self._config.thresholds
        if score >= t.get("block", 0.9):
            return "block"
        if score >= t.get("strip_tools", 0.7):
            return "strip-tools"
        if score >= t.get("route_hardened", 0.4):
            return "route-hardened"
        return "allow"
