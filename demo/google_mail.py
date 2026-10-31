"""Gmail for the demo tool service: read one label, send with a send-only token.

Two OAuth tokens, each with exactly one scope, written by `make gmail-auth`:

    deploy/gmail_read_token.json   gmail.readonly   list and read messages
    deploy/gmail_send_token.json   gmail.send       send messages, nothing else

A token carrying any other scope is refused, so the read token can never send
and the send token can never read. Reads are further limited to one label
(DEMO_GMAIL_LABEL, default "securelitellm-demo"): the agent sees only the
messages the operator filed there, not the whole inbox.

Use a dedicated demo account. Message bodies are tool results: they go to the
model through SecureLiteLLM, which treats them as untrusted.
"""

from __future__ import annotations

import base64
import os
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me"
READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"
DEFAULT_READ_TOKEN = REPO_ROOT / "deploy" / "gmail_read_token.json"
DEFAULT_SEND_TOKEN = REPO_ROOT / "deploy" / "gmail_send_token.json"
DEFAULT_LABEL = "securelitellm-demo"
TIMEOUT_SECONDS = 20


class GmailError(RuntimeError):
    """Gmail is not configured, refused the request, or the message is out of scope."""


def demo_label() -> str:
    return os.environ.get("DEMO_GMAIL_LABEL", DEFAULT_LABEL).strip()


def read_token_path() -> Path:
    return Path(os.environ.get("DEMO_GMAIL_READ_TOKEN", DEFAULT_READ_TOKEN))


def send_token_path() -> Path:
    return Path(os.environ.get("DEMO_GMAIL_SEND_TOKEN", DEFAULT_SEND_TOKEN))


def access_token(path: Path, scope: str) -> str:
    """A current access token from a token file that grants `scope` and nothing else."""
    kind = "read" if scope == READ_SCOPE else "send"
    if not path.exists():
        raise GmailError(f"Gmail is not configured: run 'make gmail-auth SCOPE={kind}'")
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials

    credentials = Credentials.from_authorized_user_file(str(path))
    granted = set(credentials.scopes or [])
    if granted != {scope}:
        raise GmailError(
            f"{path.name} must grant only {scope}; it grants {sorted(granted) or 'nothing'}"
        )
    if not credentials.valid:
        from google.auth.exceptions import RefreshError

        try:
            credentials.refresh(Request())
        except RefreshError as exc:
            raise GmailError(
                f"Gmail sign-in expired or was revoked ({exc}); "
                f"run 'make gmail-auth SCOPE={kind}' again"
            ) from exc
        path.write_text(credentials.to_json())
    return credentials.token


def _get(path: str, token: str, params: dict[str, Any] | None = None) -> dict:
    response = httpx.get(
        f"{GMAIL_API}/{path}",
        params=params,
        headers={"Authorization": f"Bearer {token}"},
        timeout=TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        raise GmailError(f"Gmail API returned HTTP {response.status_code}")
    return response.json()


def validate_token(path: Path, scope: str) -> None:
    """Validate the current token and its granted scope without sending mail."""
    token = access_token(path, scope)
    response = httpx.get(
        "https://oauth2.googleapis.com/tokeninfo",
        params={"access_token": token},
        timeout=TIMEOUT_SECONDS,
    )
    if response.status_code != 200:
        raise GmailError("Gmail token is expired, revoked or invalid; sign in again")
    if set(response.json().get("scope", "").split()) != {scope}:
        raise GmailError("Gmail granted scopes differ from the required single permission")


def _label_id(token: str, name: str) -> str:
    for label in _get("labels", token).get("labels", []):
        if label.get("name") == name:
            return label["id"]
    raise GmailError(f"Gmail label not found: {name!r}; create it and file demo mail there")


def _headers(payload: dict) -> dict[str, str]:
    wanted = {"from", "to", "subject", "date"}
    return {
        header["name"].lower(): header.get("value", "")
        for header in payload.get("headers", [])
        if header.get("name", "").lower() in wanted
    }


def _decode(data: str) -> str:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")


def _bodies(part: dict) -> tuple[str, str]:
    """The first text/plain and text/html bodies in a message part tree."""
    plain = html = ""
    stack = [part]
    while stack:
        current = stack.pop(0)
        data = (current.get("body") or {}).get("data")
        mime = current.get("mimeType", "")
        if data and mime == "text/plain" and not plain:
            plain = _decode(data)
        elif data and mime == "text/html" and not html:
            html = _decode(data)
        stack.extend(current.get("parts") or [])
    return plain, html


def list_messages(query: str = "", max_results: int = 10) -> list[dict[str, str]]:
    """Messages in the demo label matching a Gmail search query, newest first."""
    token = access_token(read_token_path(), READ_SCOPE)
    label_id = _label_id(token, demo_label())
    params = {"labelIds": label_id, "maxResults": max(1, min(max_results, 25))}
    if query.strip():
        params["q"] = query.strip()
    listed = _get("messages", token, params).get("messages", [])
    messages = []
    for item in listed:
        message = _get(
            f"messages/{item['id']}",
            token,
            {"format": "metadata", "metadataHeaders": ["From", "Subject", "Date"]},
        )
        headers = _headers(message.get("payload", {}))
        messages.append(
            {
                "id": message["id"],
                "from": headers.get("from", ""),
                "subject": headers.get("subject", ""),
                "date": headers.get("date", ""),
                "snippet": message.get("snippet", ""),
            }
        )
    return messages


def read_message(message_id: str) -> dict[str, str]:
    """One message from the demo label: headers plus its text and HTML bodies."""
    token = access_token(read_token_path(), READ_SCOPE)
    label_id = _label_id(token, demo_label())
    message = _get(f"messages/{message_id}", token, {"format": "full"})
    if label_id not in message.get("labelIds", []):
        raise GmailError(f"message {message_id} is not in the {demo_label()!r} label")
    payload = message.get("payload", {})
    headers = _headers(payload)
    plain, html = _bodies(payload)
    return {
        "id": message["id"],
        "from": headers.get("from", ""),
        "to": headers.get("to", ""),
        "subject": headers.get("subject", ""),
        "date": headers.get("date", ""),
        "body_text": plain,
        "body_html": html,
    }


def send_message(message: EmailMessage) -> str:
    """Send with the send-only token; returns the Gmail message id."""
    token = access_token(send_token_path(), SEND_SCOPE)
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")
    response = httpx.post(
        f"{GMAIL_API}/messages/send",
        json={"raw": raw},
        headers={"Authorization": f"Bearer {token}"},
        timeout=TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        raise GmailError(f"Gmail send returned HTTP {response.status_code}")
    return response.json().get("id", "")
