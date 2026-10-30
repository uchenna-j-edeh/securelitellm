"""GitHub issues for the demo tool service: list and read issues in one repository.

Configured from deploy/.env:

    GITHUB_ISSUES_REPO    owner/name, the one repository the agent may read
    GITHUB_ISSUES_TOKEN   optional: a fine-grained token with read-only access to
                          Issues on that repository (needed for a private one;
                          a public one works without, at a lower rate limit)

Pull requests are refused: the tools read issues only. Issue text is a tool
result: it goes to the model through SecureLiteLLM, which treats it as
untrusted. On a public repository anyone can write it.
"""

from __future__ import annotations

import os
import re
from typing import Any

import httpx

GITHUB_API = "https://api.github.com"
TIMEOUT_SECONDS = 20
MAX_COMMENTS = 20


class GitHubIssuesError(RuntimeError):
    """GitHub is not configured, refused the request, or the item is out of scope."""


def _repo() -> str:
    repo = os.environ.get("GITHUB_ISSUES_REPO", "").strip()
    if not repo:
        raise GitHubIssuesError("GitHub issues are not configured: set GITHUB_ISSUES_REPO")
    if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+", repo):
        raise GitHubIssuesError("GITHUB_ISSUES_REPO must be owner/name")
    return repo


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SecureLiteLLM-Demo/1.0",
    }
    token = os.environ.get("GITHUB_ISSUES_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get(path: str, params: dict | None = None) -> Any:
    response = httpx.get(
        f"{GITHUB_API}/{path}", params=params, headers=_headers(), timeout=TIMEOUT_SECONDS
    )
    if response.status_code >= 400:
        raise GitHubIssuesError(f"GitHub API returned HTTP {response.status_code}")
    return response.json()


def _summary(issue: dict) -> dict[str, Any]:
    return {
        "number": issue.get("number"),
        "title": issue.get("title", ""),
        "state": issue.get("state", ""),
        "author": (issue.get("user") or {}).get("login", ""),
        "labels": [label.get("name", "") for label in issue.get("labels") or []],
        "updated_at": issue.get("updated_at", ""),
    }


def list_issues(query: str = "", state: str = "open", max_results: int = 10) -> list[dict]:
    """Issues in the demo repository, most recently updated first; optional text search."""
    repo = _repo()
    if state not in {"open", "closed", "all"}:
        raise GitHubIssuesError("state must be open, closed or all")
    # Search, not the list endpoint: that one mixes in pull requests, which would
    # use up the page before they could be dropped.
    qualifiers = f"repo:{repo} is:issue" + ("" if state == "all" else f" is:{state}")
    found = _get(
        "search/issues",
        {
            "q": f"{query.strip()} {qualifiers}".strip(),
            "sort": "updated",
            "per_page": max(1, min(max_results, 25)),
        },
    )
    return [_summary(item) for item in found.get("items", []) if "pull_request" not in item]


def get_issue(number: int) -> dict[str, Any]:
    """One issue from the demo repository, with its body and its first comments."""
    repo = _repo()
    if number < 1:
        raise GitHubIssuesError("issue number must be a positive integer")
    issue = _get(f"repos/{repo}/issues/{number}")
    if "pull_request" in issue:
        raise GitHubIssuesError(f"#{number} is a pull request, not an issue")
    comments = []
    if issue.get("comments"):
        listed = _get(f"repos/{repo}/issues/{number}/comments", {"per_page": MAX_COMMENTS})
        comments = [
            {"author": (c.get("user") or {}).get("login", ""), "body": c.get("body") or ""}
            for c in listed
        ]
    return {**_summary(issue), "body": issue.get("body") or "", "comments": comments}
