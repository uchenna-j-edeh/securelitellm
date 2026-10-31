#!/usr/bin/env python3
"""Create and validate the private local configuration for the live demo.

Secrets are accepted only through hidden interactive prompts. They are never
passed on the command line or printed, and the generated file is mode 0600 on
POSIX systems.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import shutil
import smtplib
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from contextlib import contextmanager
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_OUTPUT = Path("deploy/.env")
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
DEFAULT_DEMO_RECIPIENT = "demo-recipient@example.test"
DEFAULT_SMTP_HOST = "smtp.gmail.com"
DEFAULT_SMTP_PORT = 587
GROQ_MODELS_URL = "https://api.groq.com/openai/v1/models"
REQUIRED_GROQ_MODEL = "openai/gpt-oss-120b"


class SetupError(RuntimeError):
    """A safe, user-facing setup failure."""


def _validate_work_settings(values: dict[str, str]) -> None:
    jira_keys = ("JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY")
    if any(values.get(key) for key in (*jira_keys, "JIRA_CLOUD_ID")):
        if not all(values.get(key) for key in jira_keys):
            raise SetupError(
                "Jira needs JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN and JIRA_PROJECT_KEY."
            )
        url = urlparse(values["JIRA_BASE_URL"])
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.path not in {"", "/"}
        ):
            raise SetupError("JIRA_BASE_URL must be an HTTPS site origin without credentials.")
        _email_address(values["JIRA_EMAIL"], field="JIRA_EMAIL")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", values["JIRA_PROJECT_KEY"]):
            raise SetupError("JIRA_PROJECT_KEY must be a Jira project key, e.g. DEMO.")
        cloud_id = values.get("JIRA_CLOUD_ID", "")
        if cloud_id and not re.fullmatch(
            r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", cloud_id
        ):
            raise SetupError("JIRA_CLOUD_ID must be a site UUID.")
    repo = values.get("GITHUB_ISSUES_REPO", "")
    if repo and not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+", repo):
        raise SetupError("GITHUB_ISSUES_REPO must be owner/name.")
    if values.get("GITHUB_ISSUES_TOKEN") and not repo:
        raise SetupError("GITHUB_ISSUES_TOKEN needs GITHUB_ISSUES_REPO.")
    if values.get("DEMO_GMAIL_READ_ENABLED", "false").lower() not in {"true", "false"}:
        raise SetupError("DEMO_GMAIL_READ_ENABLED must be true or false.")
    if (
        values.get("DEMO_GMAIL_READ_ENABLED", "false").lower() == "true"
        and not values.get("DEMO_GMAIL_LABEL", "securelitellm-demo").strip()
    ):
        raise SetupError("DEMO_GMAIL_LABEL cannot be empty when Gmail reads are enabled.")


@contextmanager
def _work_environment(values: dict[str, str]):
    """CLI-only temporary environment, restored even if a provider fails."""
    prefixes = ("DEMO_GMAIL_", "JIRA_", "GITHUB_ISSUES_")
    keys = {key for key in os.environ if key.startswith(prefixes)} | {
        key for key in values if key.startswith(prefixes)
    }
    previous = {key: os.environ.get(key) for key in keys}
    try:
        for key in keys:
            os.environ.pop(key, None)
        os.environ.update({key: values[key] for key in keys if key in values})
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def check_work_tools(
    values: dict[str, str], *, online: bool, base: Path | None = None
) -> list[str]:
    """Check only configured services; online checks never send a message."""
    _validate_work_settings(values)
    base = base or REPO_ROOT / "deploy"
    checks = []
    read_path = Path(values.get("DEMO_GMAIL_READ_TOKEN") or base / "gmail_read_token.json")
    send_path = Path(values.get("DEMO_GMAIL_SEND_TOKEN") or base / "gmail_send_token.json")
    read_enabled = (
        values.get("DEMO_GMAIL_READ_ENABLED", "false").lower() == "true" or read_path.exists()
    )
    send_enabled = values.get("DEMO_EMAIL_MODE", "log").lower() == "gmail"
    for enabled, path, kind in [
        (read_enabled, read_path, "read"),
        (send_enabled, send_path, "send"),
    ]:
        if not enabled:
            continue
        scope = f"https://www.googleapis.com/auth/gmail.{'readonly' if kind == 'read' else 'send'}"
        try:
            token = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            raise SetupError(
                f"Gmail {kind} token is missing or invalid; run make gmail-auth SCOPE={kind}."
            ) from exc
        scopes = token.get("scopes", []) if isinstance(token, dict) else []
        if isinstance(scopes, str):
            scopes = scopes.split()
        if (
            not isinstance(scopes, list)
            or any(not isinstance(item, str) for item in scopes)
            or set(scopes) != {scope}
        ):
            raise SetupError(f"Gmail {kind} token must grant only {scope}.")
        if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise SetupError(f"Gmail {kind} token must be private: chmod 600 {path}")
        checks.append(f"Gmail {kind} single-permission token")
    if values.get("JIRA_BASE_URL"):
        checks.append("single Jira project configuration")
    if values.get("GITHUB_ISSUES_REPO"):
        checks.append("single GitHub repository configuration")
    if not online:
        return checks

    from demo import github_issues, google_mail, jira

    configured = {
        **values,
        "DEMO_GMAIL_READ_TOKEN": str(read_path),
        "DEMO_GMAIL_SEND_TOKEN": str(send_path),
    }
    service = "Configured work tool"
    try:
        with _work_environment(configured):
            if read_enabled:
                service = "Gmail read access"
                google_mail.validate_token(read_path, google_mail.READ_SCOPE)
                google_mail.list_messages(max_results=1)
                checks.append("live Gmail read access and demo label")
            if send_enabled:
                service = "Gmail send authorization"
                google_mail.validate_token(send_path, google_mail.SEND_SCOPE)
                checks.append("live Gmail send token (no email sent)")
            if values.get("JIRA_BASE_URL"):
                service = "Jira project access"
                jira.check_project()
                checks.append("live Jira project access")
            if values.get("GITHUB_ISSUES_REPO"):
                service = "GitHub repository access"
                github_issues.check_repository()
                checks.append("live GitHub repository access")
    except Exception as exc:
        # Provider exceptions may contain credentials or response bodies.
        raise SetupError(
            f"{service} check failed; verify its sign-in, scope and selected label/project/repository."
        ) from exc
    return checks


def _dotenv_value(value: str) -> str:
    if any(char in value for char in "\r\n\x00"):
        raise SetupError("Configuration values cannot contain line breaks or NUL bytes.")
    if re.fullmatch(r"[A-Za-z0-9_./:@,-]+", value):
        return value
    if "'" in value:
        raise SetupError("Configuration values cannot contain a single quote.")
    return f"'{value}'"


def _email_address(value: str, *, field: str) -> str:
    raw = value.strip()
    display_name, address = parseaddr(raw)
    normalized = address.lower()
    if (
        display_name
        or normalized != raw.lower()
        or normalized.count("@") != 1
        or any(char in raw for char in ",;\n\r")
    ):
        raise SetupError(f"{field} must be one plain email address.")
    return normalized


def render_config(
    *,
    groq_key: str,
    email_mode: str,
    demo_recipient: str = DEFAULT_DEMO_RECIPIENT,
    smtp_host: str = "",
    smtp_port: int = DEFAULT_SMTP_PORT,
    smtp_starttls: bool = True,
    smtp_username: str = "",
    smtp_password: str = "",
    smtp_from: str = "",
    gmail_read: bool = False,
    gmail_label: str = "securelitellm-demo",
    jira_base_url: str = "",
    jira_email: str = "",
    jira_api_token: str = "",
    jira_project_key: str = "",
    jira_cloud_id: str = "",
    github_repo: str = "",
    github_token: str = "",
) -> str:
    """Return a minimal demo configuration without exposing secrets elsewhere."""
    if not re.fullmatch(r"gsk_[A-Za-z0-9_-]{20,}", groq_key):
        raise SetupError("The Groq key does not look like a current gsk_ API key.")
    if email_mode not in {"log", "smtp", "gmail"}:
        raise SetupError("Email mode must be log, smtp or gmail.")
    recipient = _email_address(demo_recipient, field="Demo recipient")

    if email_mode == "smtp":
        if not smtp_host.strip() or any(char in smtp_host for char in "\r\n\x00"):
            raise SetupError("SMTP host is required and cannot contain line breaks.")
        if not 1 <= int(smtp_port) <= 65535:
            raise SetupError("SMTP port must be between 1 and 65535.")
        if not smtp_username.strip():
            raise SetupError("SMTP username is required in smtp mode.")
        if not smtp_password or any(char in smtp_password for char in "\r\n\x00"):
            raise SetupError("SMTP password is required and cannot contain line breaks.")
        from_address = _email_address(smtp_from, field="SMTP from address")
    else:
        smtp_host = ""
        smtp_username = ""
        smtp_password = ""
        from_address = ""

    values = {
        "LITELLM_MASTER_KEY": f"sk-local-{secrets.token_urlsafe(48)}",
        "GROQ_API_KEY": groq_key,
        "ROUTER_MODE": "session",
        "ROUTER_LEVEL": "L3",
        "ROUTER_ENFORCE": "true",
        "DEMO_MODEL": "gpt",
        "DEMO_TOOL_SERVER_URL": "http://localhost:8002",
        "DEMO_EMAIL_MODE": email_mode,
        "DEMO_RECIPIENT": recipient,
        "DEMO_EMAIL_ALLOWLIST": recipient,
        "DEMO_EMAIL_SUBJECT_PREFIX": "[SecureLiteLLM DEMO]",
        "SMTP_HOST": smtp_host.strip(),
        "SMTP_PORT": str(smtp_port),
        "SMTP_STARTTLS": str(smtp_starttls).lower(),
        "SMTP_USERNAME": smtp_username.strip(),
        "SMTP_PASSWORD": smtp_password,
        "SMTP_FROM": from_address,
        "DEMO_GMAIL_READ_ENABLED": str(gmail_read).lower(),
        "DEMO_GMAIL_LABEL": gmail_label.strip(),
        "JIRA_BASE_URL": jira_base_url.strip().rstrip("/"),
        "JIRA_EMAIL": jira_email.strip(),
        "JIRA_API_TOKEN": jira_api_token,
        "JIRA_PROJECT_KEY": jira_project_key.strip().upper(),
        "JIRA_CLOUD_ID": jira_cloud_id.strip(),
        "GITHUB_ISSUES_REPO": github_repo.strip(),
        "GITHUB_ISSUES_TOKEN": github_token,
    }
    _validate_work_settings(values)
    lines = [
        "# Generated by scripts/setup_demo.py. Contains secrets; never commit or share.",
        "# Use your own provider credentials; never copy another person's deploy/.env.",
    ]
    lines.extend(f"{key}={_dotenv_value(value)}" for key, value in values.items())
    return "\n".join(lines) + "\n"


def write_private_file(path: Path, contents: str, *, force: bool = False) -> None:
    """Atomically write a private config, refusing to replace one by default."""
    path = path.resolve()
    if path.exists() and not force:
        raise SetupError(
            f"{path} already exists; it was left unchanged. "
            "Use --check to validate it or --force to replace it."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def rotate_local_key(path: Path) -> None:
    """Replace only the clone-local proxy key, preserving provider credentials."""
    path = path.resolve()
    if not path.is_file():
        raise SetupError(f"Configuration file not found: {path}")
    contents = path.read_text(encoding="utf-8")
    replacement = f"LITELLM_MASTER_KEY=sk-local-{secrets.token_urlsafe(48)}"
    updated, count = re.subn(
        r"^LITELLM_MASTER_KEY=.*$",
        replacement,
        contents,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise SetupError("Expected exactly one LITELLM_MASTER_KEY setting.")
    write_private_file(path, updated, force=True)


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise SetupError(f"Invalid configuration syntax at {path}:{line_number}.")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def check_config(path: Path) -> list[str]:
    """Validate structure and permissions without printing any secret values."""
    path = path.resolve()
    if not path.is_file():
        raise SetupError(f"Configuration file not found: {path}")
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise SetupError(f"{path} is readable by other users; run: chmod 600 {path}")

    values = parse_env(path)
    required = (
        "LITELLM_MASTER_KEY",
        "GROQ_API_KEY",
        "DEMO_EMAIL_MODE",
        "DEMO_RECIPIENT",
        "DEMO_EMAIL_ALLOWLIST",
    )
    missing = [key for key in required if not values.get(key)]
    if missing:
        raise SetupError(f"Missing required settings: {', '.join(missing)}")
    if "replace-with" in values["LITELLM_MASTER_KEY"]:
        raise SetupError("LITELLM_MASTER_KEY still contains the example placeholder.")
    if not re.fullmatch(r"gsk_[A-Za-z0-9_-]{20,}", values["GROQ_API_KEY"]):
        raise SetupError("GROQ_API_KEY does not look like a current Groq API key.")

    mode = values["DEMO_EMAIL_MODE"].lower()
    if mode not in {"log", "smtp", "gmail"}:
        raise SetupError("DEMO_EMAIL_MODE must be log, smtp or gmail.")
    recipient = _email_address(values["DEMO_RECIPIENT"], field="DEMO_RECIPIENT")
    configured = {
        item.strip().lower() for item in values["DEMO_EMAIL_ALLOWLIST"].split(",") if item.strip()
    }
    if configured != {recipient}:
        raise SetupError("DEMO_EMAIL_ALLOWLIST must contain only DEMO_RECIPIENT.")
    checks = ["private file permissions", "local proxy credential", "Groq credential format"]
    if mode == "smtp":
        smtp_required = ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM")
        smtp_missing = [key for key in smtp_required if not values.get(key)]
        if smtp_missing:
            raise SetupError(f"SMTP mode is missing: {', '.join(smtp_missing)}")
        _email_address(values["SMTP_FROM"], field="SMTP_FROM")
        try:
            port = int(values.get("SMTP_PORT", str(DEFAULT_SMTP_PORT)))
        except ValueError as exc:
            raise SetupError("SMTP_PORT must be a number.") from exc
        if not 1 <= port <= 65535:
            raise SetupError("SMTP_PORT must be between 1 and 65535.")
        checks.extend(["SMTP credential presence", "single-recipient allowlist"])
    elif mode == "gmail":
        checks.append("Gmail send-only mode")
    else:
        checks.append("safe local-only outbox mode")
    checks.extend(check_work_tools(values, online=False, base=path.parent))
    return checks


def _tls_context() -> ssl.SSLContext:
    """Use the OS trust store, with the project's CA bundle as a fallback."""
    try:
        import truststore
    except ImportError:
        pass
    else:
        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def validate_groq(groq_key: str, *, timeout: float = 15) -> None:
    if shutil.which("curl"):
        curl_config = "\n".join(
            (
                f'url = "{GROQ_MODELS_URL}"',
                f'header = "Authorization: Bearer {groq_key}"',
                'header = "User-Agent: SecureLiteLLM-Setup/1.0"',
                f"max-time = {timeout}",
                "fail-with-body",
                "silent",
                "show-error",
            )
        )
        result = subprocess.run(
            ["curl", "--config", "-"],
            input=curl_config,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise SetupError(
                f"Groq rejected the credential or connection (curl exit {result.returncode})."
            )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SetupError("Groq returned an invalid validation response.") from exc
        _require_groq_model(payload)
        return

    request = urllib.request.Request(
        GROQ_MODELS_URL,
        headers={"Authorization": f"Bearer {groq_key}", "User-Agent": "SecureLiteLLM-Setup/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_tls_context()) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        raise SetupError(f"Groq rejected the credential (HTTP {exc.code}).") from exc
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise SetupError(f"Could not validate Groq connectivity: {exc}") from exc
    _require_groq_model(payload)


def _require_groq_model(payload: dict) -> None:
    model_ids = {item.get("id") for item in payload.get("data", []) if isinstance(item, dict)}
    if REQUIRED_GROQ_MODEL not in model_ids:
        raise SetupError(f"Groq key is valid, but {REQUIRED_GROQ_MODEL} is not available.")


def validate_smtp(
    *,
    host: str,
    port: int,
    starttls: bool,
    username: str,
    password: str,
    timeout: float = 15,
) -> None:
    if shutil.which("curl"):
        settings = [
            f'url = "smtp://{host}:{port}/"',
            f'user = "{username}:{password}"',
            'request = "NOOP"',
            f"max-time = {timeout}",
            "fail-with-body",
            "silent",
            "show-error",
        ]
        if starttls:
            settings.insert(1, "ssl-reqd")
        curl_config = "\n".join(settings)
        result = subprocess.run(
            ["curl", "--config", "-"],
            input=curl_config,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise SetupError(
                f"SMTP server rejected the credential or connection (curl exit {result.returncode})."
            )
        return

    try:
        with smtplib.SMTP(host, port, timeout=timeout) as client:
            client.ehlo()
            if starttls:
                client.starttls(context=_tls_context())
                client.ehlo()
            client.login(username, password)
            client.noop()
    except (OSError, smtplib.SMTPException) as exc:
        raise SetupError(f"SMTP server rejected the credential or connection: {exc}") from exc


def check_online(path: Path) -> list[str]:
    """Validate the local file plus live provider authentication without side effects."""
    checks = check_config(path)
    values = parse_env(path)
    validate_groq(values["GROQ_API_KEY"])
    checks.append("live Groq access")
    if values["DEMO_EMAIL_MODE"].lower() == "smtp":
        validate_smtp(
            host=values["SMTP_HOST"],
            port=int(values.get("SMTP_PORT", str(DEFAULT_SMTP_PORT))),
            starttls=values.get("SMTP_STARTTLS", "true").lower() in {"1", "true", "yes"},
            username=values["SMTP_USERNAME"],
            password=values["SMTP_PASSWORD"],
        )
        checks.append("live SMTP login (no email sent)")
    checks.extend(check_work_tools(values, online=True, base=path.parent))
    return checks


def _prompt_secret(prompt: str) -> str:
    value = getpass.getpass(prompt).strip()
    if not value:
        raise SetupError("A required credential was left empty.")
    return value


def _prompt_email_mode() -> str:
    answer = input("Email mode [log/smtp/gmail] (default: log): ").strip().lower() or "log"
    if answer not in {"log", "smtp", "gmail"}:
        raise SetupError("Enter log, smtp or gmail.")
    return answer


def _prompt_value(prompt: str, *, default: str = "") -> str:
    suffix = f" (default: {default})" if default else ""
    value = input(f"{prompt}{suffix}: ").strip() or default
    if not value:
        raise SetupError(f"{prompt} is required.")
    return value


def _prompt_yes_no(prompt: str, *, default: bool = True) -> bool:
    marker = "Y/n" if default else "y/N"
    value = input(f"{prompt} [{marker}]: ").strip().lower()
    if not value:
        return default
    if value not in {"y", "yes", "n", "no"}:
        raise SetupError("Enter yes or no.")
    return value in {"y", "yes"}


def configure(path: Path, *, force: bool, skip_validation: bool) -> None:
    if path.exists() and not force:
        raise SetupError(
            f"{path.resolve()} already exists; it was left unchanged. "
            "Run 'make demo-check' to validate it."
        )

    print("SecureLiteLLM demo setup")
    print("Secrets stay in a private, Git-ignored local file and are never displayed.")
    groq_key = _prompt_secret("Paste your individually issued Groq API key: ")
    if not re.fullmatch(r"gsk_[A-Za-z0-9_-]{20,}", groq_key):
        raise SetupError("The Groq key does not look like a current gsk_ API key.")

    email_mode = _prompt_email_mode()
    demo_recipient = DEFAULT_DEMO_RECIPIENT
    smtp_host = ""
    smtp_port = DEFAULT_SMTP_PORT
    smtp_starttls = True
    smtp_username = ""
    smtp_password = ""
    smtp_from = ""
    if email_mode == "smtp":
        print("Configure your own SMTP account. Gmail defaults are provided for convenience.")
        smtp_host = _prompt_value("SMTP host", default=DEFAULT_SMTP_HOST)
        try:
            smtp_port = int(_prompt_value("SMTP port", default=str(DEFAULT_SMTP_PORT)))
        except ValueError as exc:
            raise SetupError("SMTP port must be a number.") from exc
        smtp_starttls = _prompt_yes_no("Use STARTTLS", default=True)
        smtp_username = _prompt_value("SMTP username (usually your sender email)")
        smtp_password = _prompt_secret("SMTP password or app password: ")
        smtp_from = _prompt_value("From email", default=smtp_username)
        demo_recipient = _prompt_value("Demo recipient email", default=smtp_from)
    elif email_mode == "gmail":
        demo_recipient = _prompt_value("Demo recipient email")
        print("Gmail needs a separate send-only token: make gmail-auth SCOPE=send")
    else:
        print(
            f"Using local-only outbox with synthetic recipient {DEFAULT_DEMO_RECIPIENT}. "
            "No email will leave this computer."
        )

    work = {}
    work["gmail_read"] = _prompt_yes_no("Enable demo Gmail inbox reads", default=False)
    if work["gmail_read"]:
        work["gmail_label"] = _prompt_value("Gmail demo label", default="securelitellm-demo")
        print("Sign in with the read-only token: make gmail-auth SCOPE=read")
    if _prompt_yes_no("Enable Jira demo project", default=False):
        work["jira_base_url"] = _prompt_value("Jira HTTPS site URL")
        work["jira_email"] = _prompt_value("Jira account email")
        work["jira_api_token"] = _prompt_secret("Jira API token: ")
        work["jira_project_key"] = _prompt_value("Jira project key")
        work["jira_cloud_id"] = input(
            "Jira cloud ID (required for scoped tokens; blank for legacy tokens): "
        ).strip()
    if _prompt_yes_no("Enable GitHub demo issues", default=False):
        work["github_repo"] = _prompt_value("GitHub demo repository (owner/name)")
        if _prompt_yes_no("Use a read-only GitHub token", default=False):
            work["github_token"] = _prompt_secret("GitHub read-only Issues token: ")

    if not skip_validation:
        print("Validating Groq access (no model inference is performed)...")
        validate_groq(groq_key)
        if email_mode == "smtp":
            print("Validating SMTP login (no email is sent)...")
            validate_smtp(
                host=smtp_host,
                port=smtp_port,
                starttls=smtp_starttls,
                username=smtp_username,
                password=smtp_password,
            )

    contents = render_config(
        groq_key=groq_key,
        email_mode=email_mode,
        demo_recipient=demo_recipient,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_starttls=smtp_starttls,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        smtp_from=smtp_from,
        **work,
    )
    write_private_file(path, contents, force=force)
    checks = ["private configuration written"]
    print(f"Created private demo configuration: {path.resolve()}")
    print(f"Checks passed: {', '.join(checks)}")
    print("Next: authorize enabled Gmail tokens, then make demo-check-live and make demo-dual-up")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true", help="validate an existing config")
    action.add_argument(
        "--check-online",
        action="store_true",
        help="validate the config plus live Groq/SMTP authentication",
    )
    action.add_argument(
        "--rotate-local-key",
        action="store_true",
        help="replace only the clone-local LiteLLM credential",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing config (the default is to preserve it)",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="skip network credential checks for offline/local-log setup",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.check:
            checks = check_config(args.output)
            print(f"Configuration is ready: {', '.join(checks)}")
        elif args.check_online:
            checks = check_online(args.output)
            print(f"Live configuration is ready: {', '.join(checks)}")
        elif args.rotate_local_key:
            rotate_local_key(args.output)
            print("Rotated the clone-local LiteLLM credential; provider secrets were unchanged.")
        else:
            configure(args.output, force=args.force, skip_validation=args.skip_validation)
    except SetupError as exc:
        print(f"Setup failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
