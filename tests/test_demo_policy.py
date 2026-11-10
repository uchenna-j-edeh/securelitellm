"""The demo proxies' generated policy (scripts/demo_policy.py)."""

import importlib.util
from pathlib import Path

import pytest

from router.controls import resolve_controls
from router.policy import load_policy_document

_SCRIPT = Path(__file__).parent.parent / "scripts" / "demo_policy.py"
_spec = importlib.util.spec_from_file_location("demo_policy", _SCRIPT)
demo_policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo_policy)


def _bundled():
    return load_policy_document(demo_policy.SOURCE)


def test_turns_on_the_winning_switches_and_lists_the_recipient():
    policy = demo_policy.demo_policy(_bundled(), "you@example.com")

    controls = resolve_controls(policy, env="")
    assert controls.classifier and controls.allowlist and controls.user_named
    assert policy["allowed_destinations"][-1] == "you@example.com"
    assert policy["own_destinations"][-1] == "you@example.com"
    assert "you+exfil@example.com" not in policy["allowed_destinations"]
    assert "you+exfil@example.com" not in policy["own_destinations"]
    demo_policy.validate(policy)


def test_the_beat_1_page_is_allowed():
    """Beat 1 fetches https://httpbin.org/html; since #219 a fetch is checked like a send."""
    import json

    from router.allowlist import Allowlist, not_user_named
    from router.taint import sink_category

    policy = demo_policy.demo_policy(_bundled(), "you@example.com")
    arguments = json.dumps({"url": "https://httpbin.org/html"})
    sink = {
        "category": sink_category("fetch_url", arguments),
        "_arguments": arguments,
        "_user_request": "Go to https://httpbin.org/html and summarise what the page says",
    }
    assert sink["category"] == "network"
    assert Allowlist.from_entries(policy["allowed_destinations"]).unlisted([sink]) == []
    assert not_user_named([sink]) == []
    assert Allowlist.from_entries(policy["allowed_destinations"]).refused(
        "https://httpbin.org/html?secret=1"
    ) == ["httpbin.org"]


def test_corpus_url_controls_keep_their_exact_endpoints():
    from router.allowlist import Allowlist

    policy = demo_policy.demo_policy(_bundled(), "you@example.com")
    allowed = Allowlist.from_entries(policy["allowed_destinations"])
    for path in ("ingest", "debug"):
        assert allowed.refused(f"https://reports.example.com/{path}") == []
        assert allowed.refused(f"https://reports.example.com/{path}?secret=1") == [
            "reports.example.com"
        ]


def test_keeps_the_rest_of_the_bundled_policy():
    bundled = _bundled()
    policy = demo_policy.demo_policy(bundled, "you@example.com")

    assert policy["rules"] == bundled["rules"]
    assert policy["matrix"] == bundled["matrix"]
    assert set(bundled["allowed_destinations"]) < set(policy["allowed_destinations"])
    assert bundled["controls"] != policy["controls"]  # the source file is not changed


def test_a_listed_recipient_is_not_added_twice():
    policy = demo_policy.demo_policy(_bundled(), "ops@example.com")
    assert policy["allowed_destinations"].count("ops@example.com") == 1


def test_an_invalid_recipient_fails_before_the_proxy_starts():
    policy = demo_policy.demo_policy(_bundled(), "not-an-address")
    with pytest.raises(ValueError, match="allowed_destinations"):
        demo_policy.validate(policy)


def test_main_writes_the_policy(monkeypatch, tmp_path):
    target = tmp_path / "policy.demo.yaml"
    monkeypatch.setattr(demo_policy, "TARGET", target)
    monkeypatch.setattr(demo_policy, "REPO_ROOT", tmp_path)
    monkeypatch.setenv("DEMO_RECIPIENT", "You@Example.com")

    assert demo_policy.main() == 0
    written = load_policy_document(target)
    assert "you@example.com" in written["allowed_destinations"]
    assert target.read_text().startswith("# GENERATED")


def test_validate_refuses_a_policy_without_user_named():
    policy = demo_policy.demo_policy(_bundled(), "you@example.com")
    policy["controls"] = {"classifier": "on", "allowlist": "on", "user_named": "off"}
    with pytest.raises(ValueError, match="every switch on"):
        demo_policy.validate(policy)
