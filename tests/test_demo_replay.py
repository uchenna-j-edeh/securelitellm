"""The demo replay (scripts/demo_replay.py) reads decisions from `docker logs`."""

import importlib.util
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT = Path(__file__).parent.parent / "scripts" / "demo_replay.py"
_spec = importlib.util.spec_from_file_location("demo_replay", _SCRIPT)
demo_replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo_replay)

_SINCE = datetime(2026, 10, 28, tzinfo=timezone.utc)


def _logs(monkeypatch, *lines):
    out = subprocess.CompletedProcess([], 0, stdout="\n".join(lines), stderr="")
    monkeypatch.setattr(demo_replay.subprocess, "run", lambda *a, **k: out)


def _record(**fields):
    return json.dumps({"phase": "pre_call", "session_id": "s1", "request_id": "r1", **fields})


def test_records_skip_proxy_noise(monkeypatch):
    _logs(
        monkeypatch,
        "21:24:24 - LiteLLM Proxy:ERROR: something {not json",
        json.dumps({"event": "startup", "controls": {}}),  # no phase: not a decision
        "INFO: " + _record(action="allow"),
    )
    assert [r["action"] for r in demo_replay._records("c", _SINCE)] == ["allow"]


def test_wait_matches_session_phase_and_request(monkeypatch):
    _logs(
        monkeypatch,
        _record(session_id="other", action="block"),
        _record(action="allow"),
        _record(phase="post_call", request_id="r2", action="execute"),
        _record(phase="post_call", action="hold"),
    )
    wait = demo_replay._docker_wait("c")
    assert wait("s1", _SINCE)["action"] == "allow"
    assert wait("s1", _SINCE, phase="post_call", request_id="r1")["action"] == "hold"
    assert wait("s1", _SINCE, timeout=0.01, phase="post_call", request_id="r9") is None
