"""Protection switches (#196): parsing, and what classifier=off changes in the hook."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from router.controls import Controls, parse_env, resolve_controls
from tests._sessions import issued, key

# ---------------------------------------------------------------------------
# resolve_controls
# ---------------------------------------------------------------------------


def test_defaults_are_todays_configuration():
    controls = resolve_controls({}, env="")
    assert controls == Controls(classifier=True, allowlist=False)
    assert controls.summary() == {"classifier": "on", "allowlist": "off"}
    assert controls.label() == "classifier=on,allowlist=off"


@pytest.mark.parametrize("value", [False, "off", "OFF", "false", "no", "0"])
def test_policy_section_switches_off(value):
    assert resolve_controls({"controls": {"classifier": value}}, env="").classifier is False


def test_env_overrides_the_policy():
    doc = {"controls": {"classifier": "off"}}
    assert resolve_controls(doc, env="classifier=on").classifier is True
    assert resolve_controls(doc, env="").classifier is False


def test_env_is_read_from_router_controls(monkeypatch):
    monkeypatch.setenv("ROUTER_CONTROLS", "classifier=off")
    assert resolve_controls({}).classifier is False


@pytest.mark.parametrize(
    "doc, env, message",
    [
        ({"controls": {"clasifier": "off"}}, "", "unknown controls"),
        ({}, "memory=session", "unknown controls"),  # memory is ROUTER_MODE
        ({"controls": {"classifier": "maybe"}}, "", "must be on or off"),
        ({}, "classifier", "expected name=on|off"),
        ({}, "=off", "expected name=on|off"),
        ({"controls": ["classifier"]}, "", "must be a mapping"),
    ],
)
def test_bad_controls_stop_startup(doc, env, message):
    with pytest.raises(ValueError, match=message):
        resolve_controls(doc, env=env)


def test_allowlist_on_needs_the_destination_list():
    with pytest.raises(ValueError, match="allowed_destinations"):
        resolve_controls({}, env="allowlist=on")
    doc = {"allowed_destinations": ["alice@example.com"]}
    assert resolve_controls(doc, env="allowlist=on").allowlist is True


def test_parse_env_ignores_blanks():
    assert parse_env(" classifier = off , ,") == {"classifier": "off"}


# ---------------------------------------------------------------------------
# The hook with classifier=off
# ---------------------------------------------------------------------------

_PAYLOAD = "Quarterly figures: revenue 4.2M."


def _make_hook(monkeypatch, log_path, mode, level="L3", controls="classifier=off"):
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
    return [json.loads(line) for line in Path(log_path).read_text().splitlines()]


def _data(messages, session="run-1"):
    return {
        "litellm_call_id": "req-1",
        "messages": messages,
        "metadata": {"headers": {"x-agent-run-id": issued(session)}},
    }


def _read_then_send(body="summary"):
    return [
        {"role": "user", "content": "Read the report and email it."},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "r1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "r1", "content": _PAYLOAD},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "s1",
                    "type": "function",
                    "function": {
                        "name": "send_email",
                        "arguments": json.dumps({"to": "a@example.com", "body": body}),
                    },
                }
            ],
        },
    ]


async def _pre(hook, data):
    return await hook.async_pre_call_hook(MagicMock(), MagicMock(), data, "completion")


def test_classifier_off_is_never_created_and_is_recorded(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, "stateless")
    assert hook._classifier is None
    startup = _records(log_path)[0]
    assert startup["event"] == "startup"
    assert startup["controls"] == {"classifier": "off", "allowlist": "off"}


def test_classifier_on_is_the_default(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, "stateless", controls="")
    assert hook._classifier is not None
    assert _records(log_path)[0]["controls"] == {"classifier": "on", "allowlist": "off"}


@pytest.mark.asyncio
async def test_classifier_off_does_not_reject_tool_results(monkeypatch, log_path):
    # With the classifier on but missing, C10b rejects this request; off is a choice, not a fault.
    hook = _make_hook(monkeypatch, log_path, "stateless", level="L0")
    await _pre(hook, _data(_read_then_send()))
    record = _records(log_path)[-1]
    assert record["controls"]["classifier"] == "off"
    assert "classifier_verdicts" not in record["features"]


@pytest.mark.asyncio
async def test_missing_classifier_still_rejects_when_it_is_on(monkeypatch, log_path):
    import litellm.exceptions as _le

    hook = _make_hook(monkeypatch, log_path, "stateless", level="L0", controls="")
    hook._classifier = None
    with pytest.raises(_le.BadRequestError, match="classifier is required"):
        await _pre(hook, _data(_read_then_send()))


@pytest.mark.parametrize("mode", ["stateless", "session"])
@pytest.mark.asyncio
async def test_classifier_off_counts_every_tool_result_as_untrusted(monkeypatch, log_path, mode):
    hook = _make_hook(monkeypatch, log_path, mode, level="L0")
    await _pre(hook, _data(_read_then_send()))
    record = _records(log_path)[-1]
    assert record["features"]["untrusted_seen"] is True
    assert "untrusted_and_sink" in record["matched_rules"]


@pytest.mark.asyncio
async def test_classifier_off_session_taint_carries_to_a_later_turn(monkeypatch, log_path):
    from router.session import get_store

    hook = _make_hook(monkeypatch, log_path, "session", level="L0")
    await _pre(hook, _data(_read_then_send()[:3]))  # read only, no send
    assert get_store().state(key("run-1")).tainted is True


@pytest.mark.asyncio
async def test_classifier_off_stateless_l3_blocks_verbatim_untrusted_content(monkeypatch, log_path):
    import litellm.exceptions as _le

    hook = _make_hook(monkeypatch, log_path, "stateless")
    data = _data(_read_then_send()[:3])
    await _pre(hook, data)
    call = SimpleNamespace(
        id="g1",
        function=SimpleNamespace(
            name="send_email", arguments=json.dumps({"to": "a@example.com", "body": _PAYLOAD})
        ),
    )
    message = SimpleNamespace(content=None, tool_calls=[call])
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="tool_calls")]
    )

    with pytest.raises(_le.BadRequestError):
        await hook.async_post_call_success_hook(MagicMock(), data, response)
    record = _records(log_path)[-1]
    assert record["phase"] == "post_call"
    assert record["controls"]["classifier"] == "off"
    assert "tainted_in_sink_args" in record["matched_rules"]


def test_lock_rejects_classifier_off(monkeypatch, log_path):
    monkeypatch.setenv("ROUTER_LOCK", "true")
    with pytest.raises(ValueError, match="classifier=off"):
        _make_hook(monkeypatch, log_path, "session")
