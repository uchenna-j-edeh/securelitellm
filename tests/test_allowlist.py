"""Destination allowlist (#167): parsing, matching, and enforcement in the hook."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from router.allowlist import NO_DESTINATION, Allowlist, destinations, sinks_with_arguments
from tests._sessions import issued

_LIST = Allowlist.from_entries(
    [
        "user@example.com",
        "jane@example.com",
        "ops@example.com",
        "Boss@Partner.com",
        "https://api.partner.com/v2",
        "#team",
    ]
)

# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entry",
    ["", "   ", "example.com", "user@", "a@b@c.com", "https://", 5, None],
)
def test_bad_entries_stop_startup(entry):
    with pytest.raises(ValueError, match="allowed_destinations"):
        Allowlist.from_entries([entry])


@pytest.mark.parametrize("entry", ["@example.com", "@"])
def test_domain_wildcards_are_rejected(entry):
    # Each allowed inbox must be named, so its owners are known.
    with pytest.raises(ValueError, match="every address at the domain"):
        Allowlist.from_entries([entry])


def test_entries_must_be_a_list():
    with pytest.raises(ValueError, match="must be a list"):
        Allowlist.from_entries("@example.com")


# ---------------------------------------------------------------------------
# Matching one destination
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "destination",
    [
        "user@example.com",
        "USER@Example.COM",
        "boss@partner.com",  # exact address, case-insensitive
        "Jane Roe <jane@example.com>",
        '"Doe, Jane" <jane@example.com>, ops@example.com',  # every recipient listed
        "https://api.partner.com/reports?id=1",  # any path on the host
        "http://API.partner.com",
        "#team",
        "team",  # Slack channel without '#'
    ],
)
def test_allowed(destination):
    assert _LIST.refused(destination) == []


@pytest.mark.parametrize(
    "destination, label",
    [
        ("attacker@evil.com", ["@evil.com"]),
        ("other@partner.com", ["@partner.com"]),  # only boss@ is listed
        ("newhire@example.com", ["@example.com"]),  # same domain, not listed
        ("x@mail.example.com", ["@mail.example.com"]),
        ("user@example.com, x@evil.io", ["@evil.io"]),  # every recipient counts
        ("team@example.com <attacker@evil.com>", ["(unrecognised destination)"]),
        ("https://evil.com/collect", ["evil.com"]),
        ("https://api.partner.com@evil.io/", ["evil.io"]),  # userinfo trick
        ("https://api.partner.com.evil.io/", ["api.partner.com.evil.io"]),  # suffix trick
        ("#exfil", ["#exfil"]),
        ("general", ["#general"]),
    ],
)
def test_refused(destination, label):
    assert _LIST.refused(destination) == label


# ---------------------------------------------------------------------------
# Finding destinations in a call's arguments
# ---------------------------------------------------------------------------


def test_destinations_reads_every_destination_argument():
    args = {
        "to": "a@x.com",
        "cc": ["b@y.com", "c@z.com"],
        "bcc": "d@w.com",
        "url": "https://h.io/p",
        "channel": "#a; #b",
        "body": "write to me@evil.com",  # free text is not a destination
        "subject": "hi",
    }
    assert sorted(destinations(json.dumps(args))) == sorted(
        ["a@x.com", "b@y.com", "c@z.com", "d@w.com", "https://h.io/p", "#a", "#b"]
    )


@pytest.mark.parametrize("arguments", ["", "not json", "[1, 2]", '{"body": "x"}'])
def test_no_destination_found(arguments):
    assert list(destinations(arguments)) == []


def _sink(name, category="exfil", **args):
    return {"id": "c1", "name": name, "category": category, "_arguments": json.dumps(args)}


def test_unlisted_labels_every_refused_destination():
    sinks = [
        _sink("send_email", to="user@example.com", bcc="spy@evil.com"),
        _sink("http_post", url="https://attacker.io/steal", data="..."),
        _sink("slack_post", channel="#team", text="hi"),
    ]
    assert _LIST.unlisted(sinks) == ["@evil.com", "attacker.io"]


def test_a_send_with_no_destination_is_not_allowed():
    assert _LIST.unlisted([_sink("upload_report", data="...")]) == [NO_DESTINATION]
    assert _LIST.unlisted([_sink("mystery_tool", category="other")]) == [NO_DESTINATION]


def test_writes_and_reads_are_not_checked():
    sinks = [_sink("write_file", category="write", path="out.txt")]
    assert _LIST.unlisted(sinks) == []


def test_sinks_with_arguments_reads_them_from_the_request():
    messages = [
        {
            "role": "assistant",
            "tool_calls": [
                {"id": "s1", "function": {"name": "send_email", "arguments": '{"to":"a@b.io"}'}}
            ],
        }
    ]
    sinks = sinks_with_arguments(
        [{"id": "s1", "name": "send_email", "category": "exfil"}], messages
    )
    assert sinks[0]["_arguments"] == '{"to":"a@b.io"}'


# ---------------------------------------------------------------------------
# The hook
# ---------------------------------------------------------------------------


def _make_hook(monkeypatch, log_path, controls, mode="session", level="L3"):
    monkeypatch.setenv("ROUTER_MODE", mode)
    monkeypatch.setenv("ROUTER_LEVEL", level)
    monkeypatch.setenv("ROUTER_LOG_PATH", log_path)
    monkeypatch.setenv("ROUTER_ENFORCE", "true")
    monkeypatch.setenv("CLASSIFIER_BACKEND", "mock")
    monkeypatch.setenv("ROUTER_CONTROLS", controls)
    import router.session as sess_mod
    from router.hook import RouterHook
    from router.session import SessionStore

    monkeypatch.setattr(sess_mod, "_store", SessionStore())
    return RouterHook()


def _records(log_path):
    lines = Path(log_path).read_text().splitlines()
    return [json.loads(ln) for ln in lines if json.loads(ln).get("event") != "startup"]


def _data(to):
    send = {
        "id": "s1",
        "type": "function",
        "function": {"name": "send_email", "arguments": json.dumps({"to": to, "body": "hi"})},
    }
    return {
        "litellm_call_id": "req-1",
        "messages": [
            {"role": "user", "content": "Send the note."},
            {"role": "assistant", "content": None, "tool_calls": [send]},
        ],
        "metadata": {"headers": {"x-agent-run-id": issued("run-1")}},
    }


def _response(to):
    call = SimpleNamespace(
        id="g1",
        function=SimpleNamespace(name="send_email", arguments=json.dumps({"to": to, "body": "x"})),
    )
    message = SimpleNamespace(content=None, tool_calls=[call])
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="tool_calls")])


async def _pre(hook, data):
    return await hook.async_pre_call_hook(MagicMock(), MagicMock(), data, "completion")


@pytest.mark.asyncio
async def test_pre_call_flags_an_unlisted_destination(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, "allowlist=on")
    await _pre(hook, _data("attacker@evil.com"))
    record = _records(log_path)[-1]
    assert record["features"]["destination_not_allowed"] is True
    assert record["features"]["unlisted_destinations"] == ["@evil.com"]
    assert "destination_not_allowed" in record["matched_rules"]
    assert record["risk_level"] == "high"
    assert "attacker" not in json.dumps(record)  # domain only, never the address


@pytest.mark.asyncio
async def test_pre_call_passes_a_listed_destination(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, "allowlist=on")
    await _pre(hook, _data("user@example.com"))
    record = _records(log_path)[-1]
    assert record["features"]["destination_not_allowed"] is False
    assert "destination_not_allowed" not in record["matched_rules"]


@pytest.mark.asyncio
async def test_post_call_holds_a_generated_send_to_an_unlisted_destination(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, "allowlist=on")
    data = _data("user@example.com")
    data["messages"] = data["messages"][:1]  # no send in the request
    await _pre(hook, data)
    result = await hook.async_post_call_success_hook(MagicMock(), data, _response("x@evil.com"))

    record = _records(log_path)[-1]
    assert record["phase"] == "post_call"
    assert record["action"] == "hold"
    assert record["features"]["unlisted_destinations"] == ["@evil.com"]
    assert result is not None and not result.choices[0].message.tool_calls


@pytest.mark.asyncio
async def test_post_call_executes_a_generated_send_to_a_listed_destination(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, "allowlist=on")
    data = _data("user@example.com")
    data["messages"] = data["messages"][:1]
    await _pre(hook, data)
    await hook.async_post_call_success_hook(MagicMock(), data, _response("ops@example.com"))
    assert _records(log_path)[-1]["action"] == "execute"


@pytest.mark.asyncio
async def test_allowlist_off_checks_nothing(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, "")
    await _pre(hook, _data("attacker@evil.com"))
    record = _records(log_path)[-1]
    assert "destination_not_allowed" not in record["features"]
    assert record["controls"]["allowlist"] == "off"


def test_a_bad_entry_fails_startup_even_with_the_allowlist_off(monkeypatch, log_path, tmp_path):
    import yaml

    policy = yaml.safe_load(Path("deploy/policy.yaml").read_text())
    policy["allowed_destinations"] = ["not-a-destination"]
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy))
    monkeypatch.setenv("POLICY_PATH", str(path))
    with pytest.raises(ValueError, match="allowed_destinations"):
        _make_hook(monkeypatch, log_path, "")
