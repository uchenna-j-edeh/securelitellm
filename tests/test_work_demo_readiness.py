"""Optional work-tool setup, scoped connection checks, and configurable UI beats."""

import json
import os
from pathlib import Path

import httpx
import pytest

from demo import github_issues, google_mail, jira
from demo.work_beats import work_beats
from scripts import setup_demo


def token_file(tmp_path, scope):
    path = tmp_path / "token.json"
    path.write_text(json.dumps({"scopes": [scope]}))
    path.chmod(0o600)
    return path


def test_gmail_mode_is_rendered_and_requires_a_send_only_token(tmp_path):
    content = setup_demo.render_config(groq_key="gsk_" + "a" * 30, email_mode="gmail")
    env = tmp_path / ".env"
    setup_demo.write_private_file(env, content)
    with pytest.raises(setup_demo.SetupError, match="SCOPE=send"):
        setup_demo.check_config(env)
    path = token_file(tmp_path, google_mail.SEND_SCOPE)
    (tmp_path / "gmail_send_token.json").write_text(path.read_text())
    (tmp_path / "gmail_send_token.json").chmod(0o600)
    assert "Gmail send single-permission token" in setup_demo.check_config(env)


def test_extra_token_scopes_are_rejected_offline(tmp_path):
    path = token_file(tmp_path, google_mail.READ_SCOPE)
    path.write_text(json.dumps({"scopes": [google_mail.READ_SCOPE, google_mail.SEND_SCOPE]}))
    with pytest.raises(setup_demo.SetupError, match="only"):
        setup_demo.check_work_tools(
            {"DEMO_GMAIL_READ_ENABLED": "true", "DEMO_GMAIL_READ_TOKEN": str(path)}, online=False
        )


def test_disabled_tools_make_no_provider_calls(monkeypatch, tmp_path):
    def unexpected(*args, **kwargs):
        pytest.fail("Unconfigured tools must not contact any service")

    monkeypatch.setattr(httpx, "get", unexpected)
    assert setup_demo.check_work_tools({}, online=True, base=tmp_path) == []


def test_partial_jira_configuration_is_rejected():
    with pytest.raises(setup_demo.SetupError, match="Jira needs"):
        setup_demo.check_work_tools({"JIRA_PROJECT_KEY": "DEMO"}, online=False)


def test_scoped_jira_settings_are_validated_and_rendered():
    values = dict(
        groq_key="gsk_" + "a" * 30,
        email_mode="log",
        jira_base_url="https://demo.atlassian.net",
        jira_email="demo@example.test",
        jira_api_token="synthetic-token",
        jira_project_key="DEMO",
        jira_cloud_id="12345678-1234-1234-1234-123456789abc",
    )
    assert "JIRA_CLOUD_ID=12345678-1234-1234-1234-123456789abc" in setup_demo.render_config(
        **values
    )
    with pytest.raises(setup_demo.SetupError, match="site UUID"):
        setup_demo.render_config(**{**values, "jira_cloud_id": "../other-site"})
    with pytest.raises(setup_demo.SetupError, match="Jira needs"):
        setup_demo.check_work_tools({"JIRA_CLOUD_ID": values["jira_cloud_id"]}, online=False)


def test_online_checks_never_send_and_restore_environment(monkeypatch, tmp_path):
    path = token_file(tmp_path, google_mail.SEND_SCOPE)
    values = {
        "DEMO_EMAIL_MODE": "gmail",
        "DEMO_GMAIL_SEND_TOKEN": str(path),
        "JIRA_BASE_URL": "https://demo.atlassian.net",
        "JIRA_EMAIL": "demo@example.test",
        "JIRA_API_TOKEN": "synthetic-token",
        "JIRA_PROJECT_KEY": "DEMO",
        "GITHUB_ISSUES_REPO": "demo/issues",
    }
    seen = []
    monkeypatch.setenv("JIRA_PROJECT_KEY", "ORIGINAL")
    monkeypatch.setattr(google_mail, "validate_token", lambda p, s: seen.append((p, s)))
    monkeypatch.setattr(google_mail, "send_message", lambda *a: pytest.fail("No mail may be sent"))
    monkeypatch.setattr(jira, "check_project", lambda: seen.append(os.environ["JIRA_PROJECT_KEY"]))
    monkeypatch.setattr(
        github_issues, "check_repository", lambda: seen.append(os.environ["GITHUB_ISSUES_REPO"])
    )
    checks = setup_demo.check_work_tools(values, online=True, base=tmp_path)
    assert seen == [(path, google_mail.SEND_SCOPE), "DEMO", "demo/issues"]
    assert os.environ["JIRA_PROJECT_KEY"] == "ORIGINAL"
    assert "live Gmail send token (no email sent)" in checks


def test_failed_connection_does_not_print_provider_credentials(monkeypatch, tmp_path):
    monkeypatch.setattr(
        github_issues,
        "check_repository",
        lambda: (_ for _ in ()).throw(RuntimeError("secret-token")),
    )
    with pytest.raises(setup_demo.SetupError) as exc:
        setup_demo.check_work_tools(
            {"GITHUB_ISSUES_REPO": "demo/issues"}, online=True, base=tmp_path
        )
    assert "secret-token" not in str(exc.value)


def test_gmail_checks_granted_scopes_on_google(monkeypatch, tmp_path):
    monkeypatch.setattr(google_mail, "access_token", lambda *a: "synthetic-access-token")
    monkeypatch.setattr(
        httpx,
        "get",
        lambda *a, **k: httpx.Response(
            200, json={"scope": google_mail.READ_SCOPE + " " + google_mail.SEND_SCOPE}
        ),
    )
    with pytest.raises(google_mail.GmailError, match="granted scopes"):
        google_mail.validate_token(tmp_path / "token", google_mail.SEND_SCOPE)


def test_project_and_repository_checks_work_without_any_items(monkeypatch):
    monkeypatch.delenv("JIRA_CLOUD_ID", raising=False)
    monkeypatch.setenv("JIRA_BASE_URL", "https://demo.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "demo@example.test")
    monkeypatch.setenv("JIRA_API_TOKEN", "synthetic")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "DEMO")
    monkeypatch.setenv("GITHUB_ISSUES_REPO", "demo/issues")
    urls = []

    def get(url, **kwargs):
        urls.append(url)
        return httpx.Response(
            200,
            json={"key": "DEMO"}
            if "atlassian" in url
            else {"full_name": "demo/issues", "has_issues": True},
        )

    monkeypatch.setattr(httpx, "get", get)
    jira.check_project()
    github_issues.check_repository()
    assert urls == [
        "https://demo.atlassian.net/rest/api/3/project/DEMO",
        "https://api.github.com/repos/demo/issues",
    ]


def test_ui_prompts_use_selected_project_and_have_corpus_fallbacks(monkeypatch, tmp_path):
    monkeypatch.setenv("JIRA_PROJECT_KEY", "TEAM")
    monkeypatch.setenv("JIRA_BASE_URL", "https://demo.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "demo@example.test")
    monkeypatch.setenv("JIRA_API_TOKEN", "synthetic")
    monkeypatch.setenv("GITHUB_ISSUES_REPO", "demo/issues")
    monkeypatch.setenv("DEMO_GMAIL_READ_TOKEN", str(tmp_path / "missing"))
    monkeypatch.setenv("DEMO_GMAIL_READ_ENABLED", "false")
    beats = work_beats()
    assert len(beats) == 6
    assert all(not beat["configured"] for beat in beats if beat["channel"] == "Gmail")
    prompt = next(b["prompt"] for b in beats if b["channel"] == "Jira" and b["attack"])
    assert "TEAM demo project" in prompt
    assert "order 4471" in prompt
    root = Path(__file__).parent.parent
    assert all((root / "corpus/scenarios" / f"{b['replay']}.yaml").exists() for b in beats)


def test_interactive_setup_can_precede_gmail_authorization(monkeypatch, tmp_path, capsys):
    answers = iter(
        [
            "gmail",
            "recipient@example.test",
            "y",
            "demo-label",
            "y",
            "https://demo.atlassian.net",
            "demo@example.test",
            "DEMO",
            "",
            "y",
            "demo/issues",
            "y",
        ]
    )
    secrets = iter(["gsk_" + "a" * 30, "synthetic-jira-token", "synthetic-github-token"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    monkeypatch.setattr(setup_demo.getpass, "getpass", lambda prompt: next(secrets))
    path = tmp_path / ".env"
    setup_demo.configure(path, force=False, skip_validation=True)
    values = setup_demo.parse_env(path)
    assert values["DEMO_EMAIL_MODE"] == "gmail"
    assert values["DEMO_GMAIL_READ_ENABLED"] == "true"
    assert values["JIRA_PROJECT_KEY"] == "DEMO"
    assert values["GITHUB_ISSUES_REPO"] == "demo/issues"
    assert "synthetic-jira-token" not in capsys.readouterr().out
    with pytest.raises(setup_demo.SetupError, match="SCOPE=read"):
        setup_demo.check_config(path)


def test_work_channel_generated_arguments_match_the_real_tool_schemas():
    from demo.mcp_server import HttpPostRequest, SendEmailRequest
    from harness.runner import load_scenario

    models = {"send_email": SendEmailRequest, "http_post": HttpPostRequest}
    for prefix in ("sc", "bn"):
        for number in range(60, 63):
            case = load_scenario(Path(f"corpus/scenarios/{prefix}-{number:03}.yaml"))
            for call in case.turns[-1].scripted_tool_calls:
                models[call.function.name].model_validate(json.loads(call.function.arguments))


def test_clean_control_items_can_be_selected_without_listing_planted_attacks(monkeypatch):
    monkeypatch.setenv("DEMO_GMAIL_CONTROL_QUERY", 'subject:"benign status"')
    monkeypatch.setenv("JIRA_CONTROL_ISSUE", "TEAM-8")
    monkeypatch.setenv("GITHUB_ISSUES_CONTROL_NUMBER", "3")
    controls = {b["channel"]: b["prompt"] for b in work_beats() if not b["attack"]}
    assert 'subject:"benign status"' in controls["Gmail"]
    assert "TEAM-8" in controls["Jira"]
    assert "issue #3" in controls["GitHub"]
    assert all("without" in prompt for prompt in controls.values())
