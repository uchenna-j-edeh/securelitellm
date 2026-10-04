"""Tests for M4 policy engine."""

import pytest

from router.policy import PolicyConfig, PolicyEngine, PolicyRule, PolicyViolation


def _engine(rules: list[dict], thresholds: dict | None = None) -> PolicyEngine:
    parsed = [PolicyRule(id=r["id"], when=r["when"], score=r["score"]) for r in rules]
    cfg = PolicyConfig(rules=parsed, thresholds=thresholds or {})
    return PolicyEngine(cfg)


# ---------------------------------------------------------------------------
# Rule matching
# ---------------------------------------------------------------------------


def test_no_rules_returns_allow():
    engine = _engine([])
    score, action, matched = engine.evaluate({"untrusted_seen": True})
    assert score == 0.0
    assert action == "allow"
    assert matched == []


def test_single_rule_not_matching():
    engine = _engine([{"id": "r1", "when": {"untrusted_seen": True}, "score": 0.6}])
    score, action, _ = engine.evaluate({"untrusted_seen": False})
    assert score == 0.0
    assert action == "allow"


def test_single_rule_matching():
    engine = _engine([{"id": "r1", "when": {"untrusted_seen": True}, "score": 0.6}])
    score, action, matched = engine.evaluate({"untrusted_seen": True})
    assert score == 0.6
    assert matched == ["r1"]


def test_multi_condition_rule_requires_all():
    engine = _engine(
        [
            {
                "id": "r1",
                "when": {"untrusted_seen": True, "sink_requested": True},
                "score": 0.5,
            }
        ]
    )
    # Only one condition true → no match
    score, _, _ = engine.evaluate({"untrusted_seen": True, "sink_requested": False})
    assert score == 0.0

    # Both true → match
    score, _, _ = engine.evaluate({"untrusted_seen": True, "sink_requested": True})
    assert score == 0.5


def test_risk_score_is_max_not_sum():
    engine = _engine(
        [
            {"id": "r1", "when": {"untrusted_seen": True}, "score": 0.5},
            {"id": "r2", "when": {"sink_requested": True}, "score": 0.6},
        ]
    )
    score, _, matched = engine.evaluate({"untrusted_seen": True, "sink_requested": True})
    assert score == 0.6  # max, not 1.1
    assert set(matched) == {"r1", "r2"}


# ---------------------------------------------------------------------------
# Action thresholds
# ---------------------------------------------------------------------------


def test_action_allow_below_route_hardened():
    engine = PolicyEngine(
        PolicyConfig(
            rules=[PolicyRule("r", {}, 0.3)],
            thresholds={"route_hardened": 0.4, "strip_tools": 0.7, "block": 0.9},
        )
    )
    _, action, _ = engine.evaluate({})
    assert action == "allow"


def test_action_route_hardened():
    engine = PolicyEngine(
        PolicyConfig(
            rules=[PolicyRule("r", {}, 0.5)],
            thresholds={"route_hardened": 0.4, "strip_tools": 0.7, "block": 0.9},
        )
    )
    _, action, _ = engine.evaluate({})
    assert action == "route-hardened"


def test_action_strip_tools():
    engine = PolicyEngine(
        PolicyConfig(
            rules=[PolicyRule("r", {}, 0.75)],
            thresholds={"route_hardened": 0.4, "strip_tools": 0.7, "block": 0.9},
        )
    )
    _, action, _ = engine.evaluate({})
    assert action == "strip-tools"


def test_action_block():
    engine = PolicyEngine(
        PolicyConfig(
            rules=[PolicyRule("r", {}, 1.0)],
            thresholds={"route_hardened": 0.4, "strip_tools": 0.7, "block": 0.9},
        )
    )
    _, action, _ = engine.evaluate({})
    assert action == "block"


# ---------------------------------------------------------------------------
# PolicyViolation
# ---------------------------------------------------------------------------


def test_policy_violation_carries_score_and_rules():
    exc = PolicyViolation(0.95, ["tainted_in_sink_args"])
    assert exc.risk_score == 0.95
    assert exc.rule_ids == ["tainted_in_sink_args"]
    assert "blocked" in str(exc).lower()


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


def test_from_yaml_loads_bundled_policy(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """
thresholds:
  route_hardened: 0.4
  strip_tools: 0.7
  block: 0.9
rules:
  - id: test_rule
    when:
      untrusted_seen: true
      sink_requested: true
    score: 0.5
"""
    )
    engine = PolicyEngine.from_yaml(policy_file)
    score, action, matched = engine.evaluate({"untrusted_seen": True, "sink_requested": True})
    assert score == 0.5
    assert action == "route-hardened"
    assert matched == ["test_rule"]


def test_from_yaml_missing_file_fails_closed(tmp_path):
    with pytest.raises(FileNotFoundError):
        PolicyEngine.from_yaml(tmp_path / "nonexistent.yaml")


@pytest.mark.parametrize(
    "body, error",
    [
        ("rules: []", "at least one rule"),
        (
            "rules:\n  - id: bad\n    when: {made_up_feature: true}\n    score: 0.5",
            "unknown features",
        ),
        (
            "thresholds: {route_hardened: 0.8, strip_tools: 0.4, block: 0.9}\n"
            "rules:\n  - id: ok\n    when: {untrusted_seen: true}\n    score: 0.5",
            "must satisfy",
        ),
    ],
)
def test_from_yaml_rejects_unsafe_configuration(tmp_path, body, error):
    policy_file = tmp_path / "bad-policy.yaml"
    policy_file.write_text(body)
    with pytest.raises(ValueError, match=error):
        PolicyEngine.from_yaml(policy_file)


# ---------------------------------------------------------------------------
# Bundled deploy/policy.yaml sanity check
# ---------------------------------------------------------------------------


def test_bundled_policy_blocks_tainted_sink():
    engine = PolicyEngine.from_yaml()  # uses bundled policy.yaml
    score, action, matched = engine.evaluate({"tainted_spans_in_sink_args": True})
    assert score == 1.0
    assert action == "block"
    assert "tainted_in_sink_args" in matched


def test_bundled_policy_strips_tools_on_injection():
    engine = PolicyEngine.from_yaml()
    score, action, _ = engine.evaluate({"classifier_injection": True})
    assert action == "strip-tools"


def test_bundled_policy_routes_hardened_on_untrusted_and_sink():
    engine = PolicyEngine.from_yaml()
    score, action, _ = engine.evaluate({"untrusted_seen": True, "sink_requested": True})
    assert action == "route-hardened"


def test_bundled_policy_allows_clean_request():
    engine = PolicyEngine.from_yaml()
    score, action, _ = engine.evaluate({"untrusted_seen": False, "sink_requested": False})
    assert action == "allow"
