"""Demo Gmail tools: single-scope tokens, one label, send-only delivery."""

import base64
import json

import httpx
import pytest
from fastapi import HTTPException

from demo import google_mail, mcp_server
from demo.mcp_server import ListEmailsRequest, ReadEmailRequest, SendEmailRequest

LABEL_ID = "Label_7"


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    for key in (
        "DEMO_EMAIL_MODE",
        "DEMO_RECIPIENT",
        "DEMO_EMAIL_ALLOWLIST",
        "DEMO_GMAIL_LABEL",
        "DEMO_GMAIL_READ_TOKEN",
        "DEMO_GMAIL_SEND_TOKEN",
    ):
        monkeypatch.delenv(key, raising=False)


def _token_file(tmp_path, name, scopes):
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "token": "access-token",
                "refresh_token": "refresh-token",
                "client_id": "client-id",
                "client_secret": "client-secret",
                "scopes": scopes,
                "expiry": "2099-01-01T00:00:00Z",  # valid: no refresh, no network
            }
        )
    )
    return path


def _b64(text):
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _message(message_id, labels, body_parts):
    return {
        "id": message_id,
        "labelIds": labels,
        "snippet": "snippet",
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": [
                {"name": "From", "value": "Vendor <vendor@example.test>"},
                {"name": "To", "value": "demo@example.test"},
                {"name": "Subject", "value": "Invoice 4471"},
                {"name": "Date", "value": "Wed, 28 Oct 2026 10:00:00 +0000"},
                {"name": "Received", "value": "not returned"},
            ],
            "parts": body_parts,
        },
    }


class _FakeGmail:
    """Stands in for httpx.get/post against the Gmail API."""

    def __init__(self, messages):
        self.messages = {m["id"]: m for m in messages}
        self.calls = []
        self.sent = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, params, headers))
        path = url.removeprefix(google_mail.GMAIL_API + "/")
        if path == "labels":
            body = {"labels": [{"id": LABEL_ID, "name": "securelitellm-demo"}]}
        elif path == "messages":
            body = {"messages": [{"id": i} for i in self.messages]}
        else:
            body = self.messages[path.removeprefix("messages/")]
        return httpx.Response(200, json=body)

    def post(self, url, json=None, headers=None, timeout=None):
        self.sent.append((url, json, headers))
        return httpx.Response(200, json={"id": "sent-1"})


@pytest.fixture
def gmail(monkeypatch, tmp_path):
    read = _token_file(tmp_path, "read.json", [google_mail.READ_SCOPE])
    send = _token_file(tmp_path, "send.json", [google_mail.SEND_SCOPE])
    monkeypatch.setenv("DEMO_GMAIL_READ_TOKEN", str(read))
    monkeypatch.setenv("DEMO_GMAIL_SEND_TOKEN", str(send))
    fake = _FakeGmail(
        [
            _message(
                "m1",
                [LABEL_ID, "INBOX"],
                [
                    {"mimeType": "text/plain", "body": {"data": _b64("Please pay invoice 4471.")}},
                    {"mimeType": "text/html", "body": {"data": _b64("<p>html</p>")}},
                ],
            ),
            _message(
                "m2",
                ["INBOX"],
                [{"mimeType": "text/plain", "body": {"data": _b64("personal mail")}}],
            ),
            _message(
                "m3",
                [LABEL_ID],
                [{"mimeType": "text/html", "body": {"data": _b64("<p>Only <b>HTML</b></p>")}}],
            ),
        ]
    )
    monkeypatch.setattr(google_mail.httpx, "get", fake.get)
    monkeypatch.setattr(google_mail.httpx, "post", fake.post)
    return fake


def test_list_emails_is_limited_to_the_demo_label(gmail):
    result = mcp_server.list_emails(ListEmailsRequest(query="invoice", max_results=99))

    assert result["label"] == "securelitellm-demo"
    url, params, headers = gmail.calls[1]
    assert url.endswith("/messages")
    assert params == {"labelIds": LABEL_ID, "maxResults": 25, "q": "invoice"}
    assert headers == {"Authorization": "Bearer access-token"}
    assert result["messages"][0] == {
        "id": "m1",
        "from": "Vendor <vendor@example.test>",
        "subject": "Invoice 4471",
        "date": "Wed, 28 Oct 2026 10:00:00 +0000",
        "snippet": "snippet",
    }


def test_read_email_returns_the_plain_text_body(gmail):
    result = mcp_server.read_email(ReadEmailRequest(message_id="m1"))

    assert result["content"] == "Please pay invoice 4471."
    assert result["subject"] == "Invoice 4471"
    assert result["truncated"] is False
    assert "body_html" not in result and "body_text" not in result


def test_read_email_falls_back_to_html_as_text(gmail):
    assert mcp_server.read_email(ReadEmailRequest(message_id="m3"))["content"] == "Only HTML"


def test_read_email_refuses_messages_outside_the_label(gmail):
    result = mcp_server.read_email(ReadEmailRequest(message_id="m2"))

    assert "not in the 'securelitellm-demo' label" in result["error"]
    assert "content" not in result


def test_refresh_failure_is_a_tool_error(monkeypatch, tmp_path, gmail):
    from google.auth import exceptions
    from google.oauth2.credentials import Credentials

    expired = _token_file(tmp_path, "expired.json", [google_mail.READ_SCOPE])
    data = json.loads(expired.read_text())
    expired.write_text(json.dumps({**data, "expiry": "2000-01-01T00:00:00Z"}))
    monkeypatch.setenv("DEMO_GMAIL_READ_TOKEN", str(expired))

    def revoked(self, request):
        raise exceptions.RefreshError("invalid_grant: Token has been expired or revoked.")

    monkeypatch.setattr(Credentials, "refresh", revoked)

    result = mcp_server.list_emails(ListEmailsRequest())

    assert result["error"].startswith("Gmail sign-in expired or was revoked")
    assert gmail.calls == []


def test_unconfigured_gmail_is_a_tool_error(monkeypatch, tmp_path):
    monkeypatch.setenv("DEMO_GMAIL_READ_TOKEN", str(tmp_path / "missing.json"))

    result = mcp_server.list_emails(ListEmailsRequest())

    assert result == {"error": "Gmail is not configured: run 'make gmail-auth SCOPE=read'"}


@pytest.mark.parametrize(
    "scopes",
    [
        [google_mail.READ_SCOPE, google_mail.SEND_SCOPE],
        ["https://www.googleapis.com/auth/gmail.modify"],
        [],
    ],
)
def test_read_token_must_grant_only_readonly(monkeypatch, tmp_path, gmail, scopes):
    monkeypatch.setenv("DEMO_GMAIL_READ_TOKEN", str(_token_file(tmp_path, "wide.json", scopes)))

    result = mcp_server.list_emails(ListEmailsRequest())

    assert "must grant only" in result["error"]
    assert gmail.calls == []


def test_gmail_mode_sends_with_the_send_only_token(monkeypatch, tmp_path, gmail):
    monkeypatch.setattr(mcp_server, "OUTBOX", tmp_path / "outbox.jsonl")
    monkeypatch.setenv("DEMO_EMAIL_MODE", "gmail")
    monkeypatch.setenv("DEMO_EMAIL_ALLOWLIST", "recipient@example.test")

    result = mcp_server.send_email(
        SendEmailRequest(to="recipient@example.test", subject="Summary", body="Q3 is up.")
    )

    assert result["status"] == "sent" and result["delivery_mode"] == "gmail"
    url, payload, headers = gmail.sent[0]
    assert url.endswith("/messages/send")
    raw = base64.urlsafe_b64decode(payload["raw"]).decode()
    assert "To: recipient@example.test" in raw
    assert "Subject: [SecureLiteLLM DEMO] Summary" in raw
    assert "From:" not in raw  # Gmail sets the sender
    record = json.loads((tmp_path / "outbox.jsonl").read_text())
    assert record["gmail_id"] == "sent-1"


def test_gmail_mode_keeps_the_transport_allowlist(monkeypatch, tmp_path, gmail):
    monkeypatch.setattr(mcp_server, "OUTBOX", tmp_path / "outbox.jsonl")
    monkeypatch.setenv("DEMO_EMAIL_MODE", "gmail")
    monkeypatch.setenv("DEMO_EMAIL_ALLOWLIST", "recipient@example.test")

    with pytest.raises(HTTPException) as exc:
        mcp_server.send_email(SendEmailRequest(to="other@example.test", body="x"))

    assert exc.value.status_code == 403
    assert gmail.sent == []


def test_send_token_must_grant_only_send(monkeypatch, tmp_path, gmail):
    wide = _token_file(tmp_path, "wide.json", [google_mail.SEND_SCOPE, google_mail.READ_SCOPE])
    monkeypatch.setenv("DEMO_GMAIL_SEND_TOKEN", str(wide))
    monkeypatch.setattr(mcp_server, "OUTBOX", tmp_path / "outbox.jsonl")
    monkeypatch.setenv("DEMO_EMAIL_MODE", "gmail")
    monkeypatch.setenv("DEMO_EMAIL_ALLOWLIST", "recipient@example.test")

    with pytest.raises(HTTPException) as exc:
        mcp_server.send_email(SendEmailRequest(to="recipient@example.test", body="x"))

    assert exc.value.status_code == 502
    assert "must grant only" in exc.value.detail
    assert gmail.sent == []
