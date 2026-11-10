"""User-named destinations (#212): tool content can't choose a send or where it goes."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from router.allowlist import (
    NO_DESTINATION,
    Allowlist,
    latest_user_request,
    message_text,
    not_user_named,
    sinks_with_arguments,
)
from tests._sessions import issued

# ---------------------------------------------------------------------------
# What counts as named
# ---------------------------------------------------------------------------


def _sink(arguments, request, name="send_email", category="exfil"):
    return {
        "id": "s1",
        "name": name,
        "category": category,
        "_arguments": json.dumps(arguments),
        "_user_request": request,
    }


@pytest.mark.parametrize(
    "request_text, arguments",
    [
        ("Email the notes to alice@example.com.", {"to": "alice@example.com"}),
        ("email ALICE@Example.com", {"to": "alice@example.com"}),
        ("send it to alice@example.com", {"to": "Alice <alice@example.com>"}),
        (
            "to alice@example.com and cc bob@example.com",
            {"to": "alice@example.com", "cc": ["bob@example.com"]},
        ),
        (
            "upload to https://reports.example.com/ingest",
            {"url": "https://reports.example.com/ingest"},
        ),
        ("post it to reports.example.com/ingest", {"url": "http://reports.example.com/ingest"}),
        ("share it in #team-reports", {"channel": "#team-reports"}),
        ("share it in #team-reports", {"channel": "team-reports"}),
    ],
)
def test_a_destination_the_user_typed_is_named(request_text, arguments):
    assert not_user_named([_sink(arguments, request_text)]) == []


@pytest.mark.parametrize(
    "request_text, arguments, refused",
    [
        # The user only asked to read: the destination came from the tool result.
        ("Read the account notes.", {"to": "ops@example.com"}, ["@example.com"]),
        # A name, team or role is not an address.
        ("Email Alice the notes.", {"to": "alice@example.com"}, ["@example.com"]),
        ("send it to ops", {"to": "ops@example.com"}, ["@example.com"]),
        ("share it with the team", {"channel": "#team-reports"}, ["#team-reports"]),
        # One named, one added (by an injection): the added one is refused.
        (
            "email alice@example.com",
            {"to": "alice@example.com", "bcc": "ops@example.com"},
            ["@example.com"],
        ),
        # Display-name trick: the real address is what counts.
        ("email ops@example.com", {"to": '"ops@example.com" <x@evil.com>'}, ["@evil.com"]),
        # A different host, a lookalike, and the email domain don't name a host.
        ("upload to https://reports.example.com", {"url": "https://evil.com/x"}, ["evil.com"]),
        (
            "upload to reports.example.com.evil.com",
            {"url": "https://reports.example.com/x"},
            ["reports.example.com"],
        ),
        (
            "email jo@reports.example.com",
            {"url": "https://reports.example.com"},
            ["reports.example.com"],
        ),
        # Substring of a longer address or channel doesn't count.
        ("email alice@example.com.au", {"to": "alice@example.com"}, ["@example.com"]),
        ("email bigalice@example.com", {"to": "alice@example.com"}, ["@example.com"]),
        ("share it in #team-reports-old", {"channel": "#team-reports"}, ["#team-reports"]),
        # Fail closed: no destination in the send, or no user request.
        ("email alice@example.com", {"body": "hi"}, [NO_DESTINATION]),
        ("", {"to": "alice@example.com"}, ["@example.com"]),
    ],
)
def test_a_destination_the_user_did_not_type_is_refused(request_text, arguments, refused):
    assert not_user_named([_sink(arguments, request_text)]) == refused


def test_the_users_own_destinations_count_as_named_in_every_turn():
    own = Allowlist.from_entries(["user@example.com"])
    assert not_user_named([_sink({"to": "user@example.com"}, "email me a summary")], own) == []
    # Only the user's own address: another address still has to be typed.
    assert not_user_named([_sink({"to": "ops@example.com"}, "email me")], own) == ["@example.com"]


def test_reads_and_writes_are_not_checked():
    read = _sink({"path": "x"}, "", name="read_file", category="read")
    write = _sink({"path": "x"}, "", name="write_file", category="write")
    assert not_user_named([read, write]) == []


def test_unknown_tools_are_checked_like_sends():
    assert not_user_named([_sink({"to": "a@b.io"}, "", "mystery", "other")]) == ["@b.io"]


def test_named_in_collects_each_kind():
    named = Allowlist.named_in(
        "Mail Ann@X.io, post to https://api.partner.com/v2 and reports.example.com, then #Team."
    )
    assert named.addresses == {"ann@x.io"}
    # A scheme-less host names its root page over http and https (#229 review).
    assert named.urls == {
        "https://api.partner.com/v2",
        "http://reports.example.com/",
        "https://reports.example.com/",
    }
    assert named.channels == {"#team"}


def test_message_text_reads_strings_and_text_parts():
    assert message_text({"content": "hi"}) == "hi"
    parts = [{"type": "text", "text": "a"}, {"type": "image_url"}, {"type": "text", "text": "b"}]
    assert message_text({"content": parts}) == "a\nb"
    assert message_text({"content": None}) == ""


def test_each_send_is_judged_against_its_own_turn():
    """An address named in an earlier turn doesn't cover a later send."""

    def call(cid, to):
        args = json.dumps({"to": to})
        return {
            "id": cid,
            "type": "function",
            "function": {"name": "send_email", "arguments": args},
        }

    messages = [
        {"role": "user", "content": "email ops@example.com the plan"},
        {"role": "assistant", "content": None, "tool_calls": [call("t1", "ops@example.com")]},
        {"role": "tool", "tool_call_id": "t1", "content": "sent"},
        {"role": "user", "content": "read the notes"},
        {"role": "assistant", "content": None, "tool_calls": [call("t2", "ops@example.com")]},
    ]
    sinks = sinks_with_arguments(
        [
            {"id": "t1", "name": "send_email", "category": "exfil"},
            {"id": "t2", "name": "send_email", "category": "exfil"},
        ],
        messages,
    )
    assert [s["_user_request"] for s in sinks] == [
        "email ops@example.com the plan",
        "read the notes",
    ]
    assert not_user_named(sinks[:1]) == []
    assert not_user_named(sinks[1:]) == ["@example.com"]
    assert latest_user_request(messages) == "read the notes"


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


def _data(request, to=None):
    messages = [{"role": "user", "content": request}]
    if to is not None:
        send = {
            "id": "s1",
            "type": "function",
            "function": {"name": "send_email", "arguments": json.dumps({"to": to, "body": "hi"})},
        }
        messages.append({"role": "assistant", "content": None, "tool_calls": [send]})
    return {
        "litellm_call_id": "req-1",
        "messages": messages,
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


async def _post(hook, data, to):
    await _pre(hook, data)
    return await hook.async_post_call_success_hook(MagicMock(), data, _response(to))


_ON = "allowlist=on,user_named=on"


@pytest.mark.asyncio
async def test_pre_call_holds_an_allowlisted_send_the_user_did_not_ask_for(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, _ON)
    await _pre(hook, _data("Read the account notes.", "ops@example.com"))
    record = _records(log_path)[-1]
    assert record["features"]["destination_not_allowed"] is False
    assert record["features"]["destination_not_user_named"] is True
    assert record["features"]["unnamed_destinations"] == ["@example.com"]
    assert "destination_not_user_named" in record["matched_rules"]
    assert record["risk_level"] == "high"
    assert "ops@" not in json.dumps(record)  # domain only, never the address
    assert "account notes" not in json.dumps(record)  # the user's text isn't logged


@pytest.mark.asyncio
async def test_pre_call_passes_an_allowlisted_send_the_user_named(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, _ON)
    await _pre(hook, _data("Email the notes to ops@example.com", "ops@example.com"))
    record = _records(log_path)[-1]
    assert record["features"]["destination_not_user_named"] is False
    assert record["matched_rules"] == []


@pytest.mark.asyncio
async def test_a_user_named_unlisted_address_is_still_held(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, _ON)
    await _pre(hook, _data("Email x@evil.com", "x@evil.com"))
    record = _records(log_path)[-1]
    assert record["features"]["destination_not_user_named"] is False
    assert "destination_not_allowed" in record["matched_rules"]


@pytest.mark.asyncio
async def test_post_call_holds_a_generated_send_the_user_did_not_ask_for(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, _ON)
    result = await _post(hook, _data("Read the account notes."), "ops@example.com")
    record = _records(log_path)[-1]
    assert record["phase"] == "post_call"
    assert record["action"] == "hold"
    assert record["features"]["unnamed_destinations"] == ["@example.com"]
    assert result is not None and not result.choices[0].message.tool_calls


@pytest.mark.asyncio
async def test_post_call_executes_a_generated_send_the_user_named(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, _ON)
    await _post(hook, _data("Email the notes to ops@example.com"), "ops@example.com")
    assert _records(log_path)[-1]["action"] == "execute"


@pytest.mark.asyncio
async def test_user_named_works_without_the_allowlist(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, "user_named=on")
    await _pre(hook, _data("Read the notes.", "anyone@example.org"))
    record = _records(log_path)[-1]
    assert "destination_not_allowed" not in record["features"]
    assert record["features"]["destination_not_user_named"] is True


@pytest.mark.asyncio
async def test_policy_own_destinations_count_as_named(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, _ON)  # deploy/policy.yaml lists user@example.com
    await _pre(hook, _data("Email me a summary.", "user@example.com"))
    assert _records(log_path)[-1]["features"]["destination_not_user_named"] is False


def test_a_bad_own_destination_fails_startup(monkeypatch, log_path, tmp_path):
    import yaml

    policy = yaml.safe_load(Path("deploy/policy.yaml").read_text())
    policy["own_destinations"] = ["@example.com"]
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy))
    monkeypatch.setenv("POLICY_PATH", str(path))
    with pytest.raises(ValueError, match="every address at the domain"):
        _make_hook(monkeypatch, log_path, "")


@pytest.mark.asyncio
async def test_user_named_off_checks_nothing(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, "allowlist=on")
    await _pre(hook, _data("Read the notes.", "ops@example.com"))
    record = _records(log_path)[-1]
    assert "destination_not_user_named" not in record["features"]
    assert record["controls"]["user_named"] == "off"
