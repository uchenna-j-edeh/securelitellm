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
    assert (tr.risk_level, tr.route) == ("", "")


def test_opening_messages_keeps_leading_user_turns_only():
    from harness.runner import _opening_messages

    turn = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "do it"},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "c1"}]},
        {"role": "tool", "tool_call_id": "c1", "content": "evil"},
        {"role": "user", "content": "later"},
    ]
    assert _opening_messages(turn) == turn[:2]
    assert _opening_messages([turn[3]]) == [{"role": "user", "content": "start"}]


def test_replay_opens_session_then_sends_issued_id(monkeypatch):
    """Replay opens a session first and sends the proxy-issued id with every turn."""
    from harness import runner
    from router.session import session_ref

    sc = runner.load_scenario(Path("corpus/scenarios/sc-010.yaml"))
    calls: list[tuple[list[dict], str | None]] = []
    issued = "A" * 43

    def fake_post(messages, session_id=None, extra=None):
        calls.append((messages, session_id))
        return True, 1.0, None if session_id else issued, None

    seen_refs = []
    monkeypatch.setattr(runner, "_post_turn", fake_post)
    monkeypatch.setattr(runner, "current_log_size", lambda: 0)
    monkeypatch.setattr(
        runner,
        "wait_for_decision",
        lambda ref, after_byte, **_: (
            seen_refs.append(ref) or {"action": "allow", "risk_score": 0.0}
        ),
    )

    results = runner.replay_scenario(sc, seed=0)

    opening, *turns = calls
    assert opening[1] is None
    assert all(m["role"] in ("system", "user") for m in opening[0])
    assert [sid for _, sid in turns] == [issued] * len(sc.turns)
    assert seen_refs == [session_ref(issued)] * len(sc.turns)
    assert [r.session_id for r in results] == ["sc-010-s0-incremental"] * len(sc.turns)


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
        ({"scenario_label": "attack", "is_attack_turn": "True", "action": "unknown"}, "FN"),
    ],
)
def test_classify_row(row, expected):
    assert classify_row(row) == expected


@pytest.mark.parametrize(
    "risk_level, action, expected",
    [
        ("elevated", "route-hardened", "TP"),
        ("high", "strip-tools", "TP"),
        ("low", "allow", "FN"),
        ("", "block", "TP"),  # a record without a level (session violation) blocks
        ("", "unknown", "FN"),  # no decision from the proxy
    ],
)
def test_classify_row_uses_risk_level(risk_level, action, expected):
    row = {
        "scenario_label": "attack",
        "is_attack_turn": "True",
        "action": action,
        "risk_level": risk_level,
    }
    assert classify_row(row) == expected


def test_risk_level_decides_over_the_action_name():
    """Detection follows the risk level, so renaming actions cannot change metrics."""
    row = {"scenario_label": "benign", "is_attack_turn": "False", "action": "renamed"}
    assert classify_row({**row, "risk_level": "low"}) == "TN"
    assert classify_row({**row, "risk_level": "elevated"}) == "FP"


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

    results = tmp_path / "results.csv"
    results.write_text("mode,level\nsession,L3\n")  # the last real run
    monkeypatch.setattr(mat, "RESULTS_CSV", results)
    mat.run_matrix(n_seeds=1, dry_run=True)
    assert results.read_text() == "mode,level\nsession,L3\n"  # left untouched


# ── corpus-schema round-trip ──────────────────────────────────────────────────

SCENARIOS_DIR = Path(__file__).parent.parent / "corpus" / "scenarios"


@pytest.mark.parametrize("path", sorted(SCENARIOS_DIR.glob("*.yaml")))
def test_scenario_loads_for_runner(path):
    """Every scenario file can be loaded by the harness runner."""
    from harness.runner import load_scenario

    sc = load_scenario(path)
    assert sc.id
    assert sc.turns


def test_sensitive_route_is_not_a_detection():
    """#181: a low-risk request routed to the sensitive model is not a false positive."""
    row = {
        **_make_row("session", "L0", "direct_exfil", "benign", False, "allow"),
        "risk_level": "low",
        "route": "sensitive",
        "data_class": "sensitive",
    }
    assert classify_row(row) == "TN"


# ── scripted model replies and post-call outcomes (#177) ─────────────────────


def _scripted_turn(tool_calls=True):
    from corpus.validate import Turn

    reply = (
        {"tool_calls": [{"id": "c1", "function": {"name": "send_email", "arguments": "{}"}}]}
        if tool_calls
        else {"content": "hi"}
    )
    return Turn.model_validate(
        {"name": "t", "messages": [{"role": "user", "content": "go"}], "model_response": reply}
    )


def _body(tool_calls=None, finish_reason="stop", content=None):
    message = {"role": "assistant", "content": content, "tool_calls": tool_calls}
    return {"choices": [{"message": message, "finish_reason": finish_reason}]}


def test_scripted_fields_send_the_reply_and_its_tool_definitions():
    from harness.runner import MOCK_REPLY_KEY, _scripted_fields

    fields = _scripted_fields(_scripted_turn().model_response)
    assert fields[MOCK_REPLY_KEY]["tool_calls"][0]["function"]["name"] == "send_email"
    assert [t["function"]["name"] for t in fields["tools"]] == ["send_email"]
    assert "tools" not in _scripted_fields(_scripted_turn(tool_calls=False).model_response)
    assert _scripted_fields(None) == {}


@pytest.mark.parametrize(
    "body,pre,post,expected",
    [
        (None, "block", "", "blocked"),
        (None, "allow", "block", "blocked"),
        (_body(finish_reason="content_filter", content="held"), "route-hardened", "hold", "held"),
        (
            _body(tool_calls=[{"id": "c1"}], finish_reason="tool_calls"),
            "allow",
            "execute",
            "executed",
        ),
        (_body(content="[mock] no tools available"), "strip-tools", "", "tools_removed"),
    ],
)
def test_outcome_of_a_scripted_tool_call(body, pre, post, expected):
    from harness.runner import _expects_post_call, _outcome

    turn = _scripted_turn()
    assert _outcome(turn, body, pre, post) == expected
    # A post-call record exists exactly when the model generated tool calls.
    assert _expects_post_call(turn, body, pre) == (expected != "tools_removed" and pre != "block")


def test_unscripted_turn_has_no_outcome():
    from harness.runner import _expects_post_call, _outcome

    turn = _scripted_turn(tool_calls=False)
    assert _outcome(turn, _body(content="hi"), "allow", "") == ""
    assert not _expects_post_call(turn, _body(content="hi"), "allow")


def test_replay_records_the_post_call_decision(monkeypatch):
    from harness import runner

    sc = runner.load_scenario(Path("corpus/scenarios/sc-014.yaml"))
    sent: list[dict | None] = []

    def fake_post(messages, session_id=None, extra=None):
        sent.append(extra)
        if extra:  # the scripted turn: post-call held the generated call
            return True, 1.0, None, _body(finish_reason="content_filter", content="held")
        return True, 1.0, None if session_id else "A" * 43, _body(content="ok")

    def fake_wait(ref, after_byte, phase=None, request_id=None, **_):
        if phase == "post_call":
            assert request_id == "req-2"
            return {"action": "hold", "risk_level": "elevated", "route": "hardened"}
        return {"action": "allow", "risk_level": "low", "route": "standard", "request_id": "req-2"}

    monkeypatch.setattr(runner, "_post_turn", fake_post)
    monkeypatch.setattr(runner, "current_log_size", lambda: 0)
    monkeypatch.setattr(runner, "wait_for_decision", fake_wait)

    first, second = runner.replay_scenario(sc, seed=0)

    assert sent[1] == {}  # unscripted turn: request unchanged
    assert runner.MOCK_REPLY_KEY in sent[2]
    assert (first.outcome, first.post_action, first.scripted_tool_calls) == ("", "", [])
    assert second.scripted_tool_calls == ["send_email"]
    assert (second.action, second.post_action, second.post_route) == ("allow", "hold", "hardened")
    assert second.outcome == "held"


def test_wait_for_decision_filters_by_phase_and_request(tmp_path, monkeypatch):
    import json

    from harness import decisions

    log = tmp_path / "decisions.jsonl"
    records = [
        {"session_id": "s", "phase": "pre_call", "request_id": "r1"},
        {"session_id": "s", "phase": "post_call", "request_id": "r0"},
        {"session_id": "s", "phase": "post_call", "request_id": "r1", "action": "hold"},
    ]
    log.write_text("".join(json.dumps(r) + "\n" for r in records))
    monkeypatch.setattr(decisions, "DECISIONS_LOG", log)

    assert decisions.wait_for_decision("s", 0)["phase"] == "pre_call"
    post = decisions.wait_for_decision("s", 0, phase="post_call", request_id="r1")
    assert post["action"] == "hold"
    assert decisions.wait_for_decision("s", 0, timeout=0.1, request_id="r9") is None


from eval.metrics import classify_post_call  # noqa: E402


def _scripted_row(label, outcome, action="allow"):
    return {
        **_make_row("session", "L0", "delayed_exfil", label, label == "attack", action),
        "scripted_tool_calls": "send_email",
        "outcome": outcome,
    }


@pytest.mark.parametrize(
    "label,outcome,expected",
    [
        ("attack", "blocked", "PREVENTED"),
        ("attack", "held", "PREVENTED"),
        ("attack", "tools_removed", "PREVENTED"),
        ("attack", "executed", "MISSED"),
        ("attack", "", "MISSED"),  # no decision counts as not prevented
        ("benign", "executed", "POST_TN"),
        ("benign", "held", "POST_FP"),
        ("benign", "tools_removed", "POST_FP"),
    ],
)
def test_classify_post_call(label, outcome, expected):
    row = _scripted_row(label, outcome)
    assert classify_post_call(row) == expected
    assert classify_row(row) == "SKIP"  # scored on the outcome, not DR/FPR


def test_unscripted_rows_are_not_post_call_scored():
    row = _make_row("session", "L0", "direct_exfil", "attack", True, "block")
    assert classify_post_call(row) == "SKIP"
    assert classify_post_call({**row, "scripted_tool_calls": ""}) == "SKIP"


def test_prevention_metrics_leave_dr_fpr_and_br_unchanged():
    base = [
        _make_row("session", "L0", "delayed_exfil", "attack", True, "block"),
        _make_row("session", "L0", "delayed_exfil", "benign", False, "allow"),
    ]
    scripted = [
        _scripted_row("attack", "held", action="block"),
        _scripted_row("attack", "executed"),
        _scripted_row("benign", "executed"),
        _scripted_row("benign", "held"),
    ]

    def cell(rows):
        metrics = compute_metrics(build_counters(rows))
        return next(
            r
            for r in metrics
            if r["mode"] == "session" and r["level"] == "L0" and r["class"] == "delayed_exfil"
        )

    before, after = cell(base), cell(base + scripted)
    for key in ("DR", "FPR", "BR", "n_attack", "n_benign"):
        assert after[key] == before[key], key
    assert (before["PR"], before["post_FPR"]) == (None, None)
    assert (after["n_post_attack"], after["PR"]) == (2, 0.5)
    assert (after["n_post_benign"], after["post_FPR"]) == (2, 0.5)


# ── combinations of protection switches (#196) ───────────────────────────────


def test_conditions_cover_every_combination_of_the_switches():
    from harness.matrix import CONDITIONS, conditions_csv

    assert {c.label() for c in CONDITIONS} == {
        "classifier=on,allowlist=off",
        "classifier=on,allowlist=on",
        "classifier=off,allowlist=off",
        "classifier=off,allowlist=on",
    }
    names = {conditions_csv(c).name for c in CONDITIONS}
    assert "results_classifier-off_allowlist-off.csv" in names
    assert len(names) == 4  # one file each


def test_run_conditions_runs_every_combination(monkeypatch, tmp_path):
    from harness import matrix

    ran: list[tuple[str, str]] = []
    monkeypatch.setattr(matrix, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(
        matrix, "run_matrix", lambda n, dry, controls, out: ran.append((controls, out.name))
    )
    written = matrix.run_conditions(n_seeds=1, dry_run=True)

    assert len(ran) == 4
    assert [p.name for p in written] == [name for _, name in ran]


def test_run_conditions_skips_combinations_the_router_refuses(monkeypatch, tmp_path):
    from harness import matrix

    ran: list[str] = []
    monkeypatch.setattr(matrix, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(matrix, "load_policy_document", lambda path=None: {})  # no allowlist
    monkeypatch.setattr(matrix, "run_matrix", lambda n, dry, controls, out: ran.append(controls))
    matrix.run_conditions(n_seeds=1, dry_run=True)

    assert ran == ["classifier=on,allowlist=off", "classifier=off,allowlist=off"]


def test_rows_record_the_controls(monkeypatch):
    from harness.matrix import CSV_FIELDS, _row

    tr = TurnResult(
        scenario_id="sc-001",
        scenario_label="attack",
        scenario_class="direct_exfil",
        turn_name="t",
        turn_index=0,
        is_attack_turn=True,
        session_id="s",
        seed=0,
        action="block",
        risk_score=1.0,
        matched_rules=[],
        latency_ms=1.0,
        proxy_ok=True,
    )
    row = _row("session", "L3", "incremental", tr, "classifier=off,allowlist=off")
    assert row["controls"] == "classifier=off,allowlist=off"
    assert set(row) == set(CSV_FIELDS)


def test_summary_prints_one_row_per_condition_and_memory(tmp_path, capsys):
    import csv as _csv

    from eval.metrics import print_summary

    path = tmp_path / "results_classifier-off_allowlist-off.csv"
    memories = (("stateless", "incremental"), ("stateless", "full"), ("session", "incremental"))
    rows = [
        {
            **_make_row(mode, "L3", "direct_exfil", label, label == "attack", action),
            "history_mode": history,
            "controls": "classifier=off,allowlist=off",
        }
        for mode, history in memories
        for label, action in (("attack", "block"), ("attack", "allow"), ("benign", "allow"))
    ]
    with path.open("w", newline="") as fh:
        writer = _csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print_summary([path])
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("classifier=")]
    assert [ln.split()[1:3] for ln in lines] == [
        ["stateless,", "full"],
        ["stateless,", "incremental"],
        ["session,", "incremental"],
    ]
    assert all("50.0%" in ln and "1/2" in ln and "0/1" in ln for ln in lines)  # L3 counts


def test_run_matrix_writes_the_controls_on_every_row(monkeypatch, tmp_path):
    import csv as _csv

    from harness import matrix

    def fake_replay(scenario, seed, history_mode):
        return [
            TurnResult(
                scenario_id=scenario.id,
                scenario_label=scenario.label,
                scenario_class=scenario.scenario_class,
                turn_name="t",
                turn_index=0,
                is_attack_turn=False,
                session_id="s",
                seed=seed,
                action="allow",
                risk_score=0.0,
                matched_rules=[],
                latency_ms=1.0,
                proxy_ok=True,
            )
        ]

    started: list[str] = []
    monkeypatch.setattr(matrix, "RESULTS_DIR", tmp_path)
    one = matrix.load_corpus()[:1]
    monkeypatch.setattr(matrix, "load_corpus", lambda: one)
    monkeypatch.setattr(matrix, "clear_log", lambda: None)
    monkeypatch.setattr(matrix, "start_proxy", lambda m, lvl, c: started.append(c))
    monkeypatch.setattr(matrix, "wait_healthy", lambda timeout: None)
    monkeypatch.setattr(matrix, "stop_proxy", lambda: None)
    monkeypatch.setattr(matrix.time, "sleep", lambda s: None)
    monkeypatch.setattr(matrix, "replay_scenario", fake_replay)

    out = tmp_path / "r.csv"
    matrix.run_matrix(n_seeds=1, controls="classifier=off", out=out)

    rows = list(_csv.DictReader(out.open()))
    assert rows and {r["controls"] for r in rows} == {"classifier=off,allowlist=off"}
    assert set(started) == {"classifier=off"}  # passed to every proxy start
