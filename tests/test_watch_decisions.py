"""scripts/watch_decisions.py: one short line per decision record."""

import importlib.util
import io
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "watch_decisions", Path(__file__).resolve().parents[1] / "scripts" / "watch_decisions.py"
)
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)

POST_CALL = {
    "ts": "2026-11-19T21:00:00+00:00",
    "phase": "post_call",
    "agent": "demo-jasmine",
    "action": "hold",
    "features": {"classifier_verdicts": [{"label": "INJECTION"}], "classifier_injection": True},
    "tool_context": {"generated_tool_calls": [{"name": "send_email"}, {"name": "fetch_url"}]},
}


def test_post_call_shows_agent_classifier_action_and_tools():
    line = watch.format_record(POST_CALL, color=False)
    for part in ("demo-jasmine", "post_call", "injection", "hold", "send_email, fetch_url"):
        assert part in line


def test_classifier_verdicts():
    assert watch.classifier_verdict({}) == "-"
    assert (
        watch.classifier_verdict({"features": {"classifier_verdicts": [{"label": "SAFE"}]}})
        == "clean"
    )
    assert (
        watch.classifier_verdict(
            {"features": {"classifier_verdicts": [{}], "classifier_error": True}}
        )
        == "error"
    )


def test_pre_call_does_not_repeat_conversation_history_tools():
    record = {
        "phase": "pre_call",
        "action": "allow",
        "tool_context": {"tool_calls": [{"name": "send_email"}]},
    }
    assert watch.tool_calls(record) == "-"


def test_approved_is_green_and_denied_is_red():
    approved = {"phase": "approval", "action": "approved", "approval_ref": "ap-1", "agent": "a"}
    denied = {**approved, "action": "denied"}
    assert watch.format_record(approved, color=True).startswith(watch.GREEN)
    assert watch.format_record(denied, color=True).startswith(watch.RED)
    assert "ap-1" in watch.format_record(approved, color=False)
    assert "\033[" not in watch.format_record(approved, color=False)
    assert "\033[" not in watch.format_record(POST_CALL, color=True)


def test_run_skips_non_decision_lines():
    lines = [
        "INFO: litellm started\n",
        json.dumps(POST_CALL) + "\n",
        '{"other": 1}\n',
        "not json {\n",
    ]
    out = io.StringIO()
    watch.run(lines, color=False, out=out)
    assert out.getvalue().count("\n") == 1


def test_since_parsing():
    assert watch.since_ms("5m", now=1000.0) == 700_000


def test_read_only_calls_show_once_from_the_next_pre_call():
    def pre(calls):
        return {
            "phase": "pre_call",
            "session_id": "s1",
            "action": "allow",
            "tool_context": {"tool_calls": [{"id": i, "name": n} for i, n in calls]},
        }

    post = {
        "phase": "post_call",
        "session_id": "s1",
        "action": "execute",
        "tool_context": {"generated_tool_calls": [{"id": "c2", "name": "send_email"}]},
    }
    seen = {}
    assert watch.tool_calls(pre([]), seen) == "-"
    assert watch.tool_calls(pre([("c1", "read_file")]), seen) == "read_file"
    assert watch.tool_calls(post, seen) == "send_email"
    # send_email was already shown from its post_call; read_file from before
    assert watch.tool_calls(pre([("c1", "read_file"), ("c2", "send_email")]), seen) == "-"
    # an approved call runs later under the same id: its post_call still names it
    assert watch.tool_calls(post, seen) == "send_email"
    other = {**pre([("c1", "read_file")]), "session_id": "s2"}
    assert watch.tool_calls(other, seen) == "read_file"
