"""Session-scoped decision evidence and delayed CloudWatch delivery."""

import json
import subprocess

import pytest
from fastapi.testclient import TestClient

from demo import decisions


def record(**changes):
    return {
        "agent": "demo-yin",
        "session_id": "fingerprint",
        "mode": "session",
        "phase": "pre_call",
        "request_id": "req-1",
        "ts": "2026-11-19T00:32:00Z",
        "risk_score": 0.75,
        "risk_level": "high",
        "route": "quarantine",
        "action": "strip-tools",
        "enforce": True,
        "matched_rules": ["classifier_injection"],
        **changes,
    }


def result(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_cloudwatch_paginates_scopes_and_deduplicates(monkeypatch):
    monkeypatch.setenv("DEMO_DECISION_SOURCE", "cloudwatch")
    monkeypatch.setenv("DEMO_CLOUDWATCH_PROFILE", "demo-reader")
    pages = [
        {
            "events": [
                {"message": json.dumps(r)}
                for r in [
                    record(),
                    record(agent="someone-else"),
                    record(session_id="other-session"),
                    record(mode="stateless"),
                ]
            ],
            "nextToken": "page-2",
        },
        {"events": [{"message": json.dumps(record())}, {"message": "not a decision"}]},
    ]
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return result(json.dumps(pages.pop(0)))

    monkeypatch.setattr(decisions.subprocess, "run", run)
    batch = decisions.read_decisions("fingerprint", agent="demo-yin", since_ms=123)
    assert batch.status == "ready" and batch.records == [record()]
    assert commands[0][commands[0].index("--profile") + 1] == "demo-reader"
    assert '"demo-yin"' in commands[0][commands[0].index("--filter-pattern") + 1]
    assert commands[0][commands[0].index("--start-time") + 1] == "123"
    assert commands[1][-2:] == ["--next-token", "page-2"]


@pytest.mark.parametrize("failure", ["permission", "missing", "timeout", "bad-json"])
def test_unavailable_logs_are_never_reported_as_allow(monkeypatch, failure):
    monkeypatch.setenv("DEMO_DECISION_SOURCE", "cloudwatch")

    def run(*args, **kwargs):
        if failure == "missing":
            raise FileNotFoundError
        if failure == "timeout":
            raise subprocess.TimeoutExpired("aws", 10)
        if failure == "bad-json":
            return result("bad json")
        return result(returncode=1, stderr="PRIVATE_AWS_CONFIG")

    monkeypatch.setattr(decisions.subprocess, "run", run)
    batch = decisions.read_decisions("fingerprint")
    assert batch.status == "error" and batch.records == []
    assert "PRIVATE_AWS_CONFIG" not in batch.message


def test_docker_reads_only_audit_records_and_preserves_zero_risk(monkeypatch):
    monkeypatch.setenv("DEMO_DECISION_SOURCE", "docker")
    clean = record(risk_score=0, risk_level="low", route="standard", action="allow")
    monkeypatch.setattr(
        decisions.subprocess,
        "run",
        lambda *a, **kw: result(json.dumps(clean) + "\n" + json.dumps(record(session_id="other"))),
    )
    batch = decisions.read_decisions("fingerprint", agent="demo-yin")
    assert batch.records == [clean] and batch.records[0]["risk_score"] == 0


def test_remote_source_does_not_silently_try_local_docker(monkeypatch):
    monkeypatch.delenv("DEMO_DECISION_SOURCE", raising=False)
    monkeypatch.setenv("DEMO_REMOTE", "1")
    assert decisions.source_name() == "cloudwatch"


def test_ui_endpoint_uses_its_server_owned_fingerprint_and_retains_late_records(monkeypatch):
    from demo import server

    monkeypatch.setattr(
        server,
        "_sessions",
        {"browser-handle": {"proxy_id": "DO-NOT-DISCLOSE", "created_at": 100, "mode": "session"}},
    )
    monkeypatch.setattr(server, "AGENT_ID", "demo-yin")
    calls = []
    pages = [[], [record()], []]

    def read(ref, **kwargs):
        calls.append((ref, kwargs))
        rows = pages.pop(0)
        return decisions.DecisionBatch("cloudwatch", "ready" if rows else "waiting", records=rows)

    monkeypatch.setattr(server, "read_decisions", read)
    client = TestClient(server.app)
    assert client.get("/decisions?session_id=fingerprint").json()["records"] == []
    assert calls == []  # The browser cannot ask for someone else's audit fingerprint.
    assert client.get("/decisions?session_id=browser-handle&mode=stateless").json()["records"] == []
    first = client.get("/decisions?session_id=browser-handle").json()
    assert first["records"] == [] and "DO-NOT-DISCLOSE" not in json.dumps(first)
    for expected in [[record()], [record()]]:
        server._sessions["browser-handle"]["decision_fetched_at"] = -100
        assert client.get("/decisions?session_id=browser-handle").json()["records"] == expected
    assert calls[0][0] == server.session_ref("DO-NOT-DISCLOSE")
    assert calls[0][1]["agent"] == "demo-yin" and calls[0][1]["since_ms"] == 70000


def test_chat_stream_includes_real_decisions_and_source_status(monkeypatch):
    from demo import server

    monkeypatch.setattr(server, "_sessions", {})
    monkeypatch.setattr(
        server,
        "run_chat",
        lambda **kw: iter(
            [
                {"kind": "proxy_session", "session_id": "RAW-SECRET", "session_ref": "fingerprint"},
                {"kind": "assistant_message", "content": "A text reply."},
            ]
        ),
    )
    monkeypatch.setattr(
        server,
        "read_decisions",
        lambda *a, **kw: decisions.DecisionBatch("cloudwatch", "ready", records=[record()]),
    )
    response = TestClient(server.app).post("/chat", json={"session_id": "ui", "message": "read"})
    events = [
        json.loads(line[5:]) for line in response.text.splitlines() if line.startswith("data:")
    ]
    assert [e["record"] for e in events if e["kind"] == "decision"] == [record()]
    assert any(e["kind"] == "decision_status" and e["source"] == "cloudwatch" for e in events)
    assert "RAW-SECRET" not in response.text
