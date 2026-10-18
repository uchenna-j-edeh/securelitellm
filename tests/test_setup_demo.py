"""Tests for secure, repeatable demo credential setup."""

import json
import stat
from types import SimpleNamespace

import pytest

from scripts import setup_demo

GROQ_KEY = "gsk_abcdefghijklmnopqrstuvwxyz123456"
APP_PASSWORD = "abcdefghijklmnop"
RECIPIENT = "recipient@example.test"
SENDER = "sender@example.test"


def _smtp_config() -> dict:
    return {
        "demo_recipient": RECIPIENT,
        "smtp_host": "smtp.example.test",
        "smtp_port": 587,
        "smtp_starttls": True,
        "smtp_username": SENDER,
        "smtp_password": APP_PASSWORD,
        "smtp_from": SENDER,
    }


def test_render_log_mode_uses_unique_local_key_and_no_smtp_secret():
    first = setup_demo.render_config(groq_key=GROQ_KEY, email_mode="log")
    second = setup_demo.render_config(groq_key=GROQ_KEY, email_mode="log")

    first_values = _parse_text(tmp_path=None, contents=first)
    second_values = _parse_text(tmp_path=None, contents=second)
    assert first_values["LITELLM_MASTER_KEY"].startswith("sk-local-")
    assert first_values["LITELLM_MASTER_KEY"] != second_values["LITELLM_MASTER_KEY"]
    assert first_values["DEMO_EMAIL_MODE"] == "log"
    assert first_values["DEMO_RECIPIENT"] == setup_demo.DEFAULT_DEMO_RECIPIENT
    assert first_values["DEMO_EMAIL_ALLOWLIST"] == setup_demo.DEFAULT_DEMO_RECIPIENT
    assert first_values["SMTP_PASSWORD"] == ""


def test_private_config_is_mode_600_and_valid(tmp_path):
    target = tmp_path / "deploy" / ".env"
    contents = setup_demo.render_config(
        groq_key=GROQ_KEY,
        email_mode="smtp",
        **_smtp_config(),
    )

    setup_demo.write_private_file(target, contents)

    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert setup_demo.check_config(target) == [
        "private file permissions",
        "local proxy credential",
        "Groq credential format",
        "SMTP credential presence",
        "single-recipient allowlist",
    ]


def test_existing_config_is_not_replaced_without_force(tmp_path):
    target = tmp_path / ".env"
    target.write_text("keep-me")

    with pytest.raises(setup_demo.SetupError, match="left unchanged"):
        setup_demo.write_private_file(target, "replacement")

    assert target.read_text() == "keep-me"


def test_rotate_local_key_preserves_provider_secrets(tmp_path):
    target = tmp_path / ".env"
    original = setup_demo.render_config(
        groq_key=GROQ_KEY,
        email_mode="smtp",
        **_smtp_config(),
    )
    setup_demo.write_private_file(target, original)
    before = setup_demo.parse_env(target)

    setup_demo.rotate_local_key(target)

    after = setup_demo.parse_env(target)
    assert after["LITELLM_MASTER_KEY"] != before["LITELLM_MASTER_KEY"]
    assert after["GROQ_API_KEY"] == before["GROQ_API_KEY"]
    assert after["SMTP_PASSWORD"] == before["SMTP_PASSWORD"]
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_check_rejects_overly_open_permissions(tmp_path):
    target = tmp_path / ".env"
    target.write_text(setup_demo.render_config(groq_key=GROQ_KEY, email_mode="log"))
    target.chmod(0o644)

    with pytest.raises(setup_demo.SetupError, match="chmod 600"):
        setup_demo.check_config(target)


def test_check_rejects_additional_live_recipient(tmp_path):
    target = tmp_path / ".env"
    contents = setup_demo.render_config(
        groq_key=GROQ_KEY,
        email_mode="smtp",
        **_smtp_config(),
    ).replace(
        f"DEMO_EMAIL_ALLOWLIST={RECIPIENT}",
        f"DEMO_EMAIL_ALLOWLIST={RECIPIENT},teammate@example.test",
    )
    setup_demo.write_private_file(target, contents)

    with pytest.raises(setup_demo.SetupError, match="only DEMO_RECIPIENT"):
        setup_demo.check_config(target)


def test_online_check_authenticates_without_sending_email(monkeypatch, tmp_path):
    target = tmp_path / ".env"
    setup_demo.write_private_file(
        target,
        setup_demo.render_config(
            groq_key=GROQ_KEY,
            email_mode="smtp",
            **_smtp_config(),
        ),
    )
    calls = []
    monkeypatch.setattr(setup_demo, "validate_groq", lambda key: calls.append(("groq", key)))
    monkeypatch.setattr(
        setup_demo,
        "validate_smtp",
        lambda **kwargs: calls.append(("smtp", kwargs)),
    )

    checks = setup_demo.check_online(target)

    assert calls[0] == ("groq", GROQ_KEY)
    assert calls[1] == (
        "smtp",
        {
            "host": "smtp.example.test",
            "port": 587,
            "starttls": True,
            "username": SENDER,
            "password": APP_PASSWORD,
        },
    )
    assert checks[-2:] == ["live Groq access", "live SMTP login (no email sent)"]


def test_groq_validation_keeps_key_out_of_process_arguments(monkeypatch):
    observed = {}

    def fake_run(args, **kwargs):
        observed["args"] = args
        observed["input"] = kwargs["input"]
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"data": [{"id": setup_demo.REQUIRED_GROQ_MODEL}]}),
        )

    monkeypatch.setattr(setup_demo.shutil, "which", lambda name: "/usr/bin/curl")
    monkeypatch.setattr(setup_demo.subprocess, "run", fake_run)

    setup_demo.validate_groq(GROQ_KEY)

    assert GROQ_KEY not in " ".join(observed["args"])
    assert GROQ_KEY in observed["input"]


def test_smtp_validation_keeps_password_out_of_process_arguments(monkeypatch):
    observed = {}

    def fake_run(args, **kwargs):
        observed["args"] = args
        observed["input"] = kwargs["input"]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup_demo.shutil, "which", lambda name: "/usr/bin/curl")
    monkeypatch.setattr(setup_demo.subprocess, "run", fake_run)

    setup_demo.validate_smtp(
        host="smtp.example.test",
        port=587,
        starttls=True,
        username=SENDER,
        password=APP_PASSWORD,
    )

    assert APP_PASSWORD not in " ".join(observed["args"])
    assert APP_PASSWORD in observed["input"]
    assert 'request = "NOOP"' in observed["input"]


def test_render_rejects_invalid_credentials():
    with pytest.raises(setup_demo.SetupError, match="Groq key"):
        setup_demo.render_config(groq_key="not-a-key", email_mode="log")
    with pytest.raises(setup_demo.SetupError, match="SMTP password"):
        setup_demo.render_config(
            groq_key=GROQ_KEY,
            email_mode="smtp",
            demo_recipient=RECIPIENT,
            smtp_host="smtp.example.test",
            smtp_username=SENDER,
            smtp_password="",
            smtp_from=SENDER,
        )


def _parse_text(tmp_path, contents: str) -> dict[str, str]:
    del tmp_path
    values = {}
    for line in contents.splitlines():
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip("'")
    return values
