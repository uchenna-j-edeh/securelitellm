"""M4 Policy Engine: feature set → risk score → routing action.

Rules are loaded from a YAML file (POLICY_PATH env var or the bundled default).
Each rule has a `when` block (all conditions ANDed) and a `score` (0–1).
Risk score = max score of all matching rules.  The risk level is determined by
comparing the risk score against configurable thresholds; router.routing maps
the level to a route (#140).

Risk levels
-----------
low       score < elevated.
elevated  score >= elevated  (formerly route-hardened).
high      score >= high      (formerly strip-tools).
critical  score >= critical  (formerly block).

Legacy actions
--------------
allow           Pass through unchanged.
route-hardened  Redirect to the `hardened` model group.
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
RiskLevel = Literal["low", "elevated", "high", "critical"]

RISK_LEVELS: tuple[RiskLevel, ...] = ("low", "elevated", "high", "critical")
LEGACY_ACTIONS: dict[RiskLevel, Action] = {
    "low": "allow",
    "elevated": "route-hardened",
    "high": "strip-tools",
    "critical": "block",
}

_BUNDLED_POLICY = Path(__file__).parent.parent / "deploy" / "policy.yaml"
_THRESHOLD_LEVELS: tuple[RiskLevel, ...] = ("elevated", "high", "critical")
_DEFAULT_THRESHOLDS: dict[str, float] = {
    "elevated": 0.4,
    "high": 0.7,
    "critical": 0.9,
}
# Pre-#140 threshold names, still accepted.
_LEGACY_THRESHOLD_KEYS = {
    "route_hardened": "elevated",
    "strip_tools": "high",
    "block": "critical",
}
_ALLOWED_FEATURES = {
    "classifier_error",
    "classifier_injection",
    "legacy_function_calling",
    "malformed_tool_call",
    "sink_requested",
    "streaming_tool_request",
    "tainted_spans_in_sink_args",
    "untrusted_seen",
}


class PolicyViolation(Exception):
    """Raised when a request is blocked by the policy engine."""

    def __init__(self, risk_score: float, rule_ids: list[str]) -> None:
        self.risk_score = risk_score
        self.rule_ids = rule_ids
        super().__init__(f"Request blocked by policy (score={risk_score:.3f}, rules={rule_ids})")


def _normalize_thresholds(raw: dict[str, Any]) -> dict[str, Any]:
    """Map legacy threshold names to risk levels; reject unknown or duplicate keys."""
    normalized: dict[str, Any] = {}
    for key, value in raw.items():
        level = _LEGACY_THRESHOLD_KEYS.get(key, key)
        if level not in _THRESHOLD_LEVELS:
            raise ValueError(f"Unknown policy threshold: {key!r}")
        if level in normalized:
            raise ValueError(f"Policy threshold {level!r} is set more than once")
        normalized[level] = value
    return normalized


@dataclass
class PolicyRule:
    id: str
    when: dict[str, Any]  # feature_name → expected value (all ANDed)
    score: float  # 0–1 contribution when this rule matches


@dataclass
class PolicyConfig:
    rules: list[PolicyRule] = field(default_factory=list)
    thresholds: dict[str, float] = field(default_factory=lambda: dict(_DEFAULT_THRESHOLDS))

    def __post_init__(self) -> None:
        self.thresholds = {**_DEFAULT_THRESHOLDS, **_normalize_thresholds(self.thresholds)}


class PolicyEngine:
    def __init__(self, config: PolicyConfig) -> None:
        self._config = config

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> "PolicyEngine":
        return cls.from_mapping(load_policy_document(path))

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> "PolicyEngine":
        raw_rules = raw.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise ValueError("Policy must define at least one rule")

        rules = []
        seen_ids: set[str] = set()
        for raw_rule in raw_rules:
            if not isinstance(raw_rule, dict):
                raise ValueError("Each policy rule must be a mapping")
            rule_id = str(raw_rule.get("id", "")).strip()
            conditions = raw_rule.get("when")
            score = float(raw_rule.get("score", -1))
            if not rule_id or rule_id in seen_ids:
                raise ValueError(f"Policy rule ids must be unique and non-empty: {rule_id!r}")
            if not isinstance(conditions, dict) or not conditions:
                raise ValueError(f"Policy rule {rule_id!r} must define a non-empty 'when' mapping")
            unknown = set(conditions) - _ALLOWED_FEATURES
            if unknown:
                raise ValueError(
                    f"Policy rule {rule_id!r} uses unknown features: {sorted(unknown)}"
                )
            if not 0.0 <= score <= 1.0:
                raise ValueError(f"Policy rule {rule_id!r} score must be between 0 and 1")
            seen_ids.add(rule_id)
            rules.append(PolicyRule(id=rule_id, when=conditions, score=score))

        raw_thresholds = raw.get("thresholds", {})
        if not isinstance(raw_thresholds, dict):
            raise ValueError("Policy thresholds must be a mapping")
        thresholds = {**_DEFAULT_THRESHOLDS, **_normalize_thresholds(raw_thresholds)}
        values = [thresholds[name] for name in _THRESHOLD_LEVELS]
        if not all(
            isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1
            for value in values
        ):
            raise ValueError("Policy thresholds must be numbers between 0 and 1")
        if values != sorted(values):
            raise ValueError("Policy thresholds must satisfy elevated <= high <= critical")
        return cls(PolicyConfig(rules=rules, thresholds=thresholds))

    def assess(self, features: dict[str, Any]) -> tuple[float, RiskLevel, list[str]]:
        """Return (risk_score, risk_level, matched_rule_ids)."""
        matched: list[PolicyRule] = []
        for rule in self._config.rules:
            if self._matches(rule.when, features):
                matched.append(rule)

        risk_score = max((r.score for r in matched), default=0.0)
        return risk_score, self._score_to_level(risk_score), [r.id for r in matched]

    def evaluate(self, features: dict[str, Any]) -> tuple[float, Action, list[str]]:
        """Return (risk_score, legacy action, matched_rule_ids)."""
        risk_score, level, matched = self.assess(features)
        return risk_score, LEGACY_ACTIONS[level], matched

    def _matches(self, conditions: dict[str, Any], features: dict[str, Any]) -> bool:
        for key, expected in conditions.items():
            actual = features.get(key)
            if actual != expected:
                return False
        return True

    def _score_to_level(self, score: float) -> RiskLevel:
        t = self._config.thresholds
        if score >= t["critical"]:
            return "critical"
        if score >= t["high"]:
            return "high"
        if score >= t["elevated"]:
            return "elevated"
        return "low"


def load_policy_document(path: str | Path | None = None) -> dict[str, Any]:
    """Read the policy YAML once; PolicyEngine and RoutingTable both parse it."""
    import yaml  # only needed at load time

    resolved = Path(path) if path else Path(os.environ.get("POLICY_PATH", _BUNDLED_POLICY))
    if not resolved.exists():
        raise FileNotFoundError(f"Policy file does not exist: {resolved}")

    with resolved.open() as fh:
        raw = yaml.safe_load(fh) or {}

    if not isinstance(raw, dict):
        raise ValueError("Policy root must be a mapping")
    unknown = set(raw) - _POLICY_SECTIONS
    if unknown:
        raise ValueError(f"Unknown policy sections: {sorted(unknown)}")
    return raw


_POLICY_SECTIONS = {"thresholds", "rules", "routes", "matrix"}
