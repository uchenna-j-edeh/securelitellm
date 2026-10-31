"""Demo Jira and GitHub issue tools: one project/repository, read-only, errors as tool errors."""

import httpx
import pytest

from demo import github_issues, jira, mcp_server
from demo.mcp_server import (
    GitHubIssueRequest,
    GitHubIssuesRequest,
    JiraIssueRequest,
    JiraSearchRequest,
)
from demo.tools import TOOL_SCHEMAS
from router.taint import _sink_category

JIRA = "https://demo.atlassian.net"
READ_TOOLS = [
    "list_emails",
    "read_email",
    "search_jira",
    "get_jira_issue",
    "list_github_issues",
    "get_github_issue",
]


@pytest.mark.parametrize("name", READ_TOOLS)
def test_new_tools_are_reads_for_the_router(name):
    assert _sink_category(name) == "read"


def test_every_schema_has_an_endpoint():
    listed = set(mcp_server.list_tools()["tools"])
    assert {schema["function"]["name"] for schema in TOOL_SCHEMAS} == listed


# -- Jira ---------------------------------------------------------------------


def _adf(*paragraphs):
    return {
        "type": "doc",
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": text}]}
            for text in paragraphs
        ],
    }


class _FakeJira:
    def __init__(self):
        self.calls = []
        self.issues = {
            "DEMO-7": {
                "key": "DEMO-7",
                "fields": {
                    "summary": "Refund request",
                    "status": {"name": "To Do"},
                    "assignee": {"displayName": "Sam"},
                    "reporter": {"displayName": "Customer"},
                    "project": {"key": "DEMO"},
                    "description": _adf("Order 4471 arrived broken.", "Please refund."),
                    "comment": {
                        "comments": [
                            {"author": {"displayName": "Sam"}, "body": _adf("Looking into it.")}
                        ]
                    },
                },
            },
            "DEMO-8": {"key": "OPS-3", "fields": {"project": {"key": "OPS"}}},
        }

    def get(self, url, params=None, auth=None, headers=None, timeout=None):
        self.calls.append((url, params, auth))
        path = url.removeprefix(JIRA)
        if path == "/rest/api/3/search/jql":
            issue = self.issues["DEMO-7"]
            return httpx.Response(200, json={"issues": [issue]})
        key = path.removeprefix("/rest/api/3/issue/")
        if key not in self.issues:
            return httpx.Response(404, json={})
        return httpx.Response(200, json=self.issues[key])


@pytest.fixture
def fake_jira(monkeypatch):
    monkeypatch.delenv("JIRA_CLOUD_ID", raising=False)
    monkeypatch.setenv("JIRA_BASE_URL", JIRA + "/")
    monkeypatch.setenv("JIRA_EMAIL", "agent@example.test")
    monkeypatch.setenv("JIRA_API_TOKEN", "api-token")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "demo")
    fake = _FakeJira()
    monkeypatch.setattr(jira.httpx, "get", fake.get)
    return fake


def test_jira_search_is_limited_to_the_project(fake_jira):
    result = mcp_server.search_jira(JiraSearchRequest(query='refund "now"', max_results=50))

    assert result == {
        "issues": [
            {
                "key": "DEMO-7",
                "summary": "Refund request",
                "status": "To Do",
                "assignee": "Sam",
                "updated": "",
            }
        ]
    }
    url, params, auth = fake_jira.calls[0]
    assert url == JIRA + "/rest/api/3/search/jql"
    assert params["jql"] == 'project = "DEMO" AND text ~ "refund \\"now\\"" ORDER BY updated DESC'
    assert params["maxResults"] == 25
    assert auth == ("agent@example.test", "api-token")


@pytest.mark.parametrize("action", ["project", "search", "issue"])
def test_jira_scoped_token_uses_the_atlassian_gateway(fake_jira, monkeypatch, action):
    cloud_id = "12345678-1234-1234-1234-123456789abc"
    monkeypatch.setenv("JIRA_CLOUD_ID", cloud_id)
    calls = []

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return httpx.Response(200, json={"key": "DEMO", "fields": {"project": {"key": "DEMO"}}})

    monkeypatch.setattr(jira.httpx, "get", get)
    if action == "project":
        jira.check_project()
    elif action == "search":
        jira.search_issues("refund")
    else:
        jira.get_issue("DEMO-7")
    url, kwargs = calls[0]
    assert url.startswith(f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/")
    assert kwargs["auth"] == ("agent@example.test", "api-token")
    if action == "search":
        assert kwargs["params"]["jql"].startswith('project = "DEMO" AND ')


@pytest.mark.parametrize("cloud_id", ["../other-site", "not-a-uuid", "https://example.test"])
def test_invalid_jira_cloud_id_never_sends_credentials(fake_jira, monkeypatch, cloud_id):
    monkeypatch.setenv("JIRA_CLOUD_ID", cloud_id)
    with pytest.raises(jira.JiraError, match="site UUID"):
        jira.check_project()
    assert fake_jira.calls == []


def test_jira_issue_returns_description_and_comments_as_text(fake_jira):
    result = mcp_server.get_jira_issue(JiraIssueRequest(issue_key="demo-7"))

    assert result["key"] == "DEMO-7"
    assert result["reporter"] == "Customer"
    assert result["content"] == (
        "Order 4471 arrived broken.\nPlease refund.\n\nComments:\n\n- Sam: Looking into it."
    )
    assert "description" not in result and "comments" not in result


@pytest.mark.parametrize("key", ["OPS-3", "DEMO-7/../x", "DEMO", "7"])
def test_jira_refuses_keys_outside_the_project(fake_jira, key):
    result = mcp_server.get_jira_issue(JiraIssueRequest(issue_key=key))

    assert result["error"] == "issue_key must be a DEMO ticket, e.g. DEMO-12"
    assert fake_jira.calls == []


def test_jira_refuses_a_ticket_moved_out_of_the_project(fake_jira):
    result = mcp_server.get_jira_issue(JiraIssueRequest(issue_key="DEMO-8"))

    assert result["error"] == "DEMO-8 is not in the DEMO project"


def test_jira_errors_are_tool_errors(fake_jira, monkeypatch):
    assert mcp_server.get_jira_issue(JiraIssueRequest(issue_key="DEMO-99"))["error"] == (
        "Jira API returned HTTP 404"
    )
    monkeypatch.delenv("JIRA_API_TOKEN")
    assert "Jira is not configured" in mcp_server.search_jira(JiraSearchRequest())["error"]
    monkeypatch.setenv("JIRA_API_TOKEN", "t")
    monkeypatch.setenv("JIRA_BASE_URL", "http://demo.atlassian.net")
    assert mcp_server.search_jira(JiraSearchRequest())["error"] == (
        "JIRA_BASE_URL must be an https:// URL"
    )


def test_adf_text_handles_breaks_and_unknown_nodes():
    node = {
        "type": "doc",
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "a"},
                    {"type": "hardBreak"},
                    {"type": "mention", "attrs": {"id": "x"}},
                    {"type": "text", "text": "b"},
                ],
            }
        ],
    }
    assert jira.adf_text(node) == "a\nb\n"
    assert jira.adf_text(None) == ""


# -- GitHub -------------------------------------------------------------------


def _issue(number, title, **extra):
    return {
        "number": number,
        "title": title,
        "state": "open",
        "user": {"login": "reporter"},
        "labels": [{"name": "bug"}],
        "updated_at": "2026-10-28T10:00:00Z",
        "body": f"body of {number}",
        "comments": 0,
        **extra,
    }


class _FakeGitHub:
    def __init__(self):
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, params, headers))
        path = url.removeprefix(github_issues.GITHUB_API + "/")
        repo = "repos/acme/demo/issues"
        if path == "search/issues":
            body = {"items": [_issue(3, "Login fails"), _issue(4, "A PR", pull_request={})]}
        elif path == f"{repo}/3":
            body = _issue(3, "Login fails", comments=1)
        elif path == f"{repo}/3/comments":
            body = [{"user": {"login": "maintainer"}, "body": "Can reproduce."}]
        elif path == f"{repo}/4":
            body = _issue(4, "A PR", pull_request={})
        else:
            return httpx.Response(404, json={})
        return httpx.Response(200, json=body)


@pytest.fixture
def fake_github(monkeypatch):
    monkeypatch.setenv("GITHUB_ISSUES_REPO", "acme/demo")
    monkeypatch.delenv("GITHUB_ISSUES_TOKEN", raising=False)
    fake = _FakeGitHub()
    monkeypatch.setattr(github_issues.httpx, "get", fake.get)
    return fake


def test_github_list_skips_pull_requests(fake_github):
    result = mcp_server.list_github_issues(GitHubIssuesRequest())

    assert [issue["number"] for issue in result["issues"]] == [3]
    assert result["issues"][0]["labels"] == ["bug"]
    url, params, headers = fake_github.calls[0]
    assert url.endswith("/search/issues")  # excludes pull requests before paging
    assert params == {"q": "repo:acme/demo is:issue is:open", "sort": "updated", "per_page": 10}
    assert "Authorization" not in headers


def test_github_search_is_limited_to_the_repo(fake_github, monkeypatch):
    monkeypatch.setenv("GITHUB_ISSUES_TOKEN", "github-token")

    mcp_server.list_github_issues(GitHubIssuesRequest(query="login", state="all"))

    url, params, headers = fake_github.calls[0]
    assert url.endswith("/search/issues")
    assert params["q"] == "login repo:acme/demo is:issue"
    assert headers["Authorization"] == "Bearer github-token"


@pytest.mark.parametrize("query", ["repo:other/private", "login OR (org:other)", "USER:someone"])
def test_github_search_cannot_expand_the_repository(fake_github, query):
    result = mcp_server.list_github_issues(GitHubIssuesRequest(query=query))
    assert "must not override" in result["error"]
    assert fake_github.calls == []


def test_github_issue_returns_body_and_comments_as_text(fake_github):
    result = mcp_server.get_github_issue(GitHubIssueRequest(number=3))

    assert result["title"] == "Login fails"
    assert result["content"] == "body of 3\n\nComments:\n\n- maintainer: Can reproduce."


def test_github_refuses_pull_requests_and_bad_input(fake_github, monkeypatch):
    assert mcp_server.get_github_issue(GitHubIssueRequest(number=4))["error"] == (
        "#4 is a pull request, not an issue"
    )
    assert "positive" in mcp_server.get_github_issue(GitHubIssueRequest(number=0))["error"]
    assert (
        "state must be"
        in mcp_server.list_github_issues(GitHubIssuesRequest(state="merged"))["error"]
    )
    assert mcp_server.get_github_issue(GitHubIssueRequest(number=99))["error"] == (
        "GitHub API returned HTTP 404"
    )


@pytest.mark.parametrize("repo", ["", "acme", "acme/demo/extra", "../x/y"])
def test_github_repo_must_be_configured_as_owner_name(fake_github, monkeypatch, repo):
    monkeypatch.setenv("GITHUB_ISSUES_REPO", repo)

    result = mcp_server.list_github_issues(GitHubIssuesRequest())

    assert "GITHUB_ISSUES_REPO" in result["error"]
    assert fake_github.calls == []
