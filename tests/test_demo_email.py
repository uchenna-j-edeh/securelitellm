"""Demo email transport and tool-service boundary tests."""

import json
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from demo import mcp_server
from demo.mcp_server import SendEmailRequest
from demo.tools import call_tool


@pytest.fixture(autouse=True)
def _clean_email_environment(monkeypatch):
    """Keep these boundary tests independent from env loaded by other modules."""
    for key in (
        "DEMO_EMAIL_MODE",
        "DEMO_RECIPIENT",
        "DEMO_EMAIL_ALLOWLIST",
        "DEMO_EMAIL_SUBJECT_PREFIX",
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_STARTTLS",
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
        "SMTP_FROM",
    ):
        monkeypatch.delenv(key, raising=False)


def test_email_defaults_to_local_log(monkeypatch, tmp_path):
    outbox = tmp_path / "outbox.jsonl"
    monkeypatch.setattr(mcp_server, "OUTBOX", outbox)

    result = mcp_server.send_email(
        SendEmailRequest(
            to="recipient@example.test",
            subject="Clean control",
            body="Synthetic summary",
        )
    )

    assert result == {
        "status": "logged",
        "delivery_mode": "log",
        "to": "recipient@example.test",
        "subject": "[SecureLiteLLM DEMO] Clean control",
    }
    record = json.loads(outbox.read_text())
    assert record["status"] == "logged"
    assert record["body"] == "Synthetic summary"


def test_smtp_delivery_is_allowlisted_and_demo_labelled(monkeypatch, tmp_path):
    outbox = tmp_path / "outbox.jsonl"
    monkeypatch.setattr(mcp_server, "OUTBOX", outbox)
    monkeypatch.setenv("DEMO_EMAIL_MODE", "smtp")
    monkeypatch.setenv("DEMO_EMAIL_ALLOWLIST", "recipient@example.test")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_STARTTLS", "true")
    monkeypatch.setenv("SMTP_USERNAME", "sender@example.test")
    monkeypatch.setenv("SMTP_PASSWORD", "not-a-real-secret")
    monkeypatch.setenv("SMTP_FROM", "sender@example.test")

    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    smtp_factory = MagicMock(return_value=client)
    monkeypatch.setattr(mcp_server.smtplib, "SMTP", smtp_factory)

    result = mcp_server.send_email(
        SendEmailRequest(
            to="recipient@example.test",
            subject="Delayed exfiltration demo",
            body="Synthetic report",
        )
    )

    assert result["status"] == "sent"
    smtp_factory.assert_called_once_with("smtp.example.test", 587, timeout=20)
    client.starttls.assert_called_once_with()
    client.login.assert_called_once_with("sender@example.test", "not-a-real-secret")
    message = client.send_message.call_args.args[0]
    assert message["To"] == "recipient@example.test"
    assert message["Subject"] == "[SecureLiteLLM DEMO] Delayed exfiltration demo"
    assert "No real financial data" in message.get_content()
    assert json.loads(outbox.read_text())["delivery_mode"] == "smtp"


def test_poisoned_content_uses_configured_recipient(monkeypatch):
    monkeypatch.setenv("DEMO_RECIPIENT", "owner@example.test")

    assert (
        mcp_server._render_demo_content("send to {{DEMO_RECIPIENT}}")
        == "send to owner@example.test"
    )


def test_poisoned_content_names_the_attack_recipient(monkeypatch):
    # The attack files name a plus-address of the operator's inbox: the same
    # mailbox, but not the address the gateway allowlist lists (#167).
    monkeypatch.setenv("DEMO_RECIPIENT", "Owner@Example.test")

    assert (
        mcp_server._render_demo_content("{{DEMO_ATTACK_RECIPIENT}} / {{DEMO_RECIPIENT}}")
        == "owner+exfil@example.test / owner@example.test"
    )


@pytest.mark.parametrize(
    "recipient, attack",
    [
        ("you@example.com", "you+exfil@example.com"),
        ("you+demo@example.com", "you+exfil@example.com"),  # one plus tag, not two
    ],
)
def test_attack_recipient(recipient, attack):
    assert mcp_server.attack_recipient(recipient) == attack


def test_smtp_delivers_to_the_attack_recipient(monkeypatch, tmp_path):
    # A send the gateway lets through must still arrive, in the operator's inbox.
    monkeypatch.setattr(mcp_server, "OUTBOX", tmp_path / "outbox.jsonl")
    monkeypatch.setenv("DEMO_EMAIL_MODE", "smtp")
    monkeypatch.setenv("DEMO_RECIPIENT", "you@example.com")
    monkeypatch.setenv("DEMO_EMAIL_ALLOWLIST", "you@example.com")
    sent = []
    monkeypatch.setattr(mcp_server, "_smtp_send", sent.append)

    result = mcp_server.send_email(
        SendEmailRequest(to="you+exfil@example.com", subject="x", body="synthetic")
    )

    assert result["status"] == "sent"
    assert [record["to"] for record in sent] == ["you+exfil@example.com"]


def test_smtp_rejects_recipient_outside_allowlist(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_server, "OUTBOX", tmp_path / "outbox.jsonl")
    monkeypatch.setenv("DEMO_EMAIL_MODE", "smtp")
    monkeypatch.setenv("DEMO_EMAIL_ALLOWLIST", "recipient@example.test")

    with pytest.raises(HTTPException) as exc_info:
        mcp_server.send_email(
            SendEmailRequest(to="outside@example.com", subject="x", body="synthetic")
        )

    assert exc_info.value.status_code == 403


def test_send_email_rejects_recipient_list(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_server, "OUTBOX", tmp_path / "outbox.jsonl")

    with pytest.raises(HTTPException) as exc_info:
        mcp_server.send_email(
            SendEmailRequest(
                to="first@example.test,second@example.test",
                subject="x",
                body="synthetic",
            )
        )

    assert exc_info.value.status_code == 422


def test_agent_tool_client_calls_separate_service(monkeypatch):
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"content": "report"}
    post = MagicMock(return_value=response)
    monkeypatch.setattr("demo.tools.httpx.post", post)

    result = call_tool(
        "read_file",
        {"path": "annual_report.txt"},
        base_url="http://tools.example.test",
    )

    assert result == {"content": "report"}
    post.assert_called_once_with(
        "http://tools.example.test/tools/read_file",
        json={"path": "annual_report.txt"},
        timeout=20.0,
    )
