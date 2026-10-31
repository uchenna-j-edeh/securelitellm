"""Jira Cloud for the demo tool service: search and read tickets in one project.

Configured from deploy/.env:

    JIRA_BASE_URL      https://<site>.atlassian.net
    JIRA_EMAIL         the Atlassian account the API token belongs to
    JIRA_API_TOKEN     an API token for that account
    JIRA_PROJECT_KEY   the one project the agent may read, e.g. DEMO
    JIRA_CLOUD_ID      site UUID, required for API tokens with scopes

Every search is limited to that project, and a ticket outside it is refused,
so the agent sees only what the operator put there. The tool only reads; use
an account that can see nothing but the demo project. Ticket text is a tool
result: it goes to the model through SecureLiteLLM, which treats it as
untrusted. Anyone who can file or comment on a ticket can write it.
"""

from __future__ import annotations

import os
import re
from typing import Any

import httpx

TIMEOUT_SECONDS = 20
MAX_COMMENTS = 20


class JiraError(RuntimeError):
    """Jira is not configured, refused the request, or the ticket is out of scope."""


def _config() -> tuple[str, tuple[str, str], str]:
    base = os.environ.get("JIRA_BASE_URL", "").strip().rstrip("/")
    email = os.environ.get("JIRA_EMAIL", "").strip()
    token = os.environ.get("JIRA_API_TOKEN", "").strip()
    project = os.environ.get("JIRA_PROJECT_KEY", "").strip().upper()
    if not (base and email and token and project):
        raise JiraError(
            "Jira is not configured: set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN "
            "and JIRA_PROJECT_KEY in deploy/.env"
        )
    if not base.startswith("https://"):
        raise JiraError("JIRA_BASE_URL must be an https:// URL")
    cloud_id = os.environ.get("JIRA_CLOUD_ID", "").strip()
    if cloud_id:
        if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", cloud_id):
            raise JiraError("JIRA_CLOUD_ID must be a site UUID")
        base = f"https://api.atlassian.com/ex/jira/{cloud_id}"
    return base, (email, token), project


def _get(url: str, auth: tuple[str, str], params: dict | None = None) -> dict:
    response = httpx.get(
        url,
        params=params,
        auth=auth,
        headers={"Accept": "application/json"},
        timeout=TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        raise JiraError(f"Jira API returned HTTP {response.status_code}")
    return response.json()


def _jql_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def check_project() -> None:
    """Check the configured project, including an empty project, without writes."""
    base, auth, project = _config()
    from urllib.parse import quote

    result = _get(f"{base}/rest/api/3/project/{quote(project, safe='')}", auth)
    if result.get("key", "").upper() != project:
        raise JiraError("Jira returned a different project")


def adf_text(node: Any) -> str:
    """Plain text from an Atlassian Document Format tree (Jira's rich-text JSON)."""
    if isinstance(node, str):
        return node
    if not isinstance(node, dict):
        return ""
    if node.get("type") == "text":
        return node.get("text", "")
    if node.get("type") == "hardBreak":
        return "\n"
    inner = "".join(adf_text(child) for child in node.get("content") or [])
    block = {"paragraph", "heading", "listItem", "codeBlock", "blockquote", "rule"}
    return inner + "\n" if node.get("type") in block else inner


def _name(person: dict | None) -> str:
    return (person or {}).get("displayName", "")


def search_issues(query: str = "", max_results: int = 10) -> list[dict[str, str]]:
    """Tickets in the demo project matching a text query, most recently updated first."""
    base, auth, project = _config()
    jql = f"project = {_jql_string(project)}"
    if query.strip():
        jql += f" AND text ~ {_jql_string(query.strip())}"
    found = _get(
        f"{base}/rest/api/3/search/jql",
        auth,
        {
            "jql": jql + " ORDER BY updated DESC",
            "fields": "summary,status,assignee,updated",
            "maxResults": max(1, min(max_results, 25)),
        },
    )
    issues = []
    for issue in found.get("issues", []):
        fields = issue.get("fields") or {}
        issues.append(
            {
                "key": issue.get("key", ""),
                "summary": fields.get("summary", ""),
                "status": (fields.get("status") or {}).get("name", ""),
                "assignee": _name(fields.get("assignee")),
                "updated": fields.get("updated", ""),
            }
        )
    return issues


def get_issue(issue_key: str) -> dict[str, Any]:
    """One ticket from the demo project: its fields, description and comments as text."""
    base, auth, project = _config()
    key = issue_key.strip().upper()
    if not re.fullmatch(rf"{re.escape(project)}-\d+", key):
        raise JiraError(f"issue_key must be a {project} ticket, e.g. {project}-12")
    issue = _get(
        f"{base}/rest/api/3/issue/{key}",
        auth,
        {"fields": "summary,description,status,assignee,reporter,comment,project"},
    )
    fields = issue.get("fields") or {}
    if (fields.get("project") or {}).get("key", "").upper() != project:
        raise JiraError(f"{key} is not in the {project} project")  # moved since
    comments = ((fields.get("comment") or {}).get("comments") or [])[-MAX_COMMENTS:]
    return {
        "key": issue.get("key", key),
        "summary": fields.get("summary", ""),
        "status": (fields.get("status") or {}).get("name", ""),
        "assignee": _name(fields.get("assignee")),
        "reporter": _name(fields.get("reporter")),
        "description": adf_text(fields.get("description")).strip(),
        "comments": [
            {"author": _name(c.get("author")), "body": adf_text(c.get("body")).strip()}
            for c in comments
        ],
    }
