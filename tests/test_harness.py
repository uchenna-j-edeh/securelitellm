"""Unit tests for the evaluation harness (no proxy required).

Tests cover:
  - TurnResult dataclass defaults
  - _messages_to_api conversion (tool_calls, tool role)
  - classify_row logic (TP/FN/TN/FP/SKIP)
  - wilson_ci edge cases
  - build_counters + compute_metrics on synthetic data
  - dry-run matrix smoke test (no Docker)
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from corpus.validate import Message, ToolCall, ToolFunction
from harness.runner import TurnResult, _messages_to_api

# ── runner ──────────────────────────────────────────────────────────────────


def _msg(role, content=None, tool_call_id=None, tool_calls=None):
    return Message(role=role, content=content, tool_call_id=tool_call_id, tool_calls=tool_calls)


def test_messages_to_api_user():
    msgs = [_msg("user", content="hello")]
    out = _messages_to_api(msgs)
    assert out == [{"role": "user", "content": "hello"}]


def test_messages_to_api_tool_role():
    msgs = [_msg("tool", content="result", tool_call_id="tc-1")]
    out = _messages_to_api(msgs)
    assert out[0]["tool_call_id"] == "tc-1"
    assert "content" in out[0]


def test_messages_to_api_assistant_with_tool_calls():
    tc = ToolCall(
        id="tc-2", type="function", function=ToolFunction(name="send_email", arguments='{"to":"x"}')
    )
    msgs = [_msg("assistant", tool_calls=[tc])]
    out = _messages_to_api(msgs)
    assert out[0]["tool_calls"][0]["function"]["name"] == "send_email"
    assert "content" not in out[0]  # content=None → omitted


def test_turn_result_defaults():
    tr = TurnResult(
        scenario_id="sc-001",
        scenario_label="attack",
        scenario_class="direct_exfil",
        turn_name="exfil",
        turn_index=0,
        is_attack_turn=True,
        session_id="sc-001-s0",
        seed=0,
    )
    assert tr.action == "unknown"
    assert tr.risk_score == 0.0
    assert tr.proxy_ok is True


# ── metrics ──────────────────────────────────────────────────────────────────

from eval.metrics import build_counters, classify_row, compute_metrics, wilson_ci  # noqa: E402


@pytest.mark.parametrize(
    "row,expected",
    [
        ({"scenario_label": "attack", "is_attack_turn": "True", "action": "block"}, "TP"),
        ({"scenario_label": "attack", "is_attack_turn": "True", "action": "route-hardened"}, "TP"),
        ({"scenario_label": "attack", "is_attack_turn": "True", "action": "allow"}, "FN"),
        ({"scenario_label": "benign", "is_attack_turn": "False", "action": "allow"}, "TN"),
        ({"scenario_label": "benign", "is_attack_turn": "False", "action": "strip-tools"}, "FP"),
        ({"scenario_label": "attack", "is_attack_turn": "False", "action": "block"}, "SKIP"),
    ],
)
def test_classify_row(row, expected):
    assert classify_row(row) == expected


def test_wilson_ci_zero():
    lo, hi = wilson_ci(0, 0)
    assert lo == 0.0 and hi == 0.0


def test_wilson_ci_perfect():
    lo, hi = wilson_ci(10, 10)
    assert lo > 0.7 and hi == 1.0


def test_wilson_ci_half():
    lo, hi = wilson_ci(5, 10)
    assert lo < 0.5 < hi


def _make_row(mode, level, cls, label, is_attack, action):
    return {
        "mode": mode,
        "level": level,
        "scenario_class": cls,
        "scenario_label": label,
        "is_attack_turn": str(is_attack),
        "action": action,
        "latency_ms": "5.0",
    }


def test_build_counters_and_metrics():
    rows = [
        # session L0 direct_exfil: 2 TPs, 1 FN
        _make_row("session", "L0", "direct_exfil", "attack", True, "block"),
        _make_row("session", "L0", "direct_exfil", "attack", True, "route-hardened"),
        _make_row("session", "L0", "direct_exfil", "attack", True, "allow"),
        # session L0 direct_exfil: 1 TN, 1 FP
        _make_row("session", "L0", "direct_exfil", "benign", False, "allow"),
        _make_row("session", "L0", "direct_exfil", "benign", False, "block"),
    ]
    counters = build_counters(rows)
    assert counters["session"]["L0"]["direct_exfil"]["TP"] == 2
    assert counters["session"]["L0"]["direct_exfil"]["FN"] == 1
    assert counters["session"]["L0"]["direct_exfil"]["FP"] == 1
    assert counters["session"]["L0"]["direct_exfil"]["TN"] == 1

    metrics = compute_metrics(counters)
    row = next(
        r
        for r in metrics
        if r["mode"] == "session" and r["level"] == "L0" and r["class"] == "direct_exfil"
    )
    assert math.isclose(row["DR"], 2 / 3, rel_tol=1e-4)
    assert math.isclose(row["FPR"], 1 / 2, rel_tol=1e-4)


# ── dry-run matrix smoke test ─────────────────────────────────────────────────


def test_matrix_dry_run(tmp_path, monkeypatch):
    """Dry-run enumerates all (mode, level, scenario, seed) combos without Docker."""
    from harness import matrix as mat

    monkeypatch.setattr(mat, "RESULTS_CSV", tmp_path / "results.csv")
    mat.run_matrix(n_seeds=1, dry_run=True)
    # CSV should have header only (dry-run writes no data rows)
    lines = (tmp_path / "results.csv").read_text().splitlines()
    assert lines[0].startswith("mode,")
    assert len(lines) == 1  # header only


# ── corpus-schema round-trip ──────────────────────────────────────────────────

SCENARIOS_DIR = Path(__file__).parent.parent / "corpus" / "scenarios"


@pytest.mark.parametrize("path", sorted(SCENARIOS_DIR.glob("*.yaml")))
def test_scenario_loads_for_runner(path):
    """Every scenario file can be loaded by the harness runner."""
    from harness.runner import load_scenario

    sc = load_scenario(path)
    assert sc.id
    assert sc.turns
