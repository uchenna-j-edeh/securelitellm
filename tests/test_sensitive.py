"""Data classification (#181): detector, data-class rules, sensitive routing."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from router.policy import PolicyEngine, load_policy_document
from router.routing import RoutingTable, verify_model_groups
from router.sensitive import DETECTORS, detect, scan_messages
from tests._sessions import issued
from tests.test_routing import (
    _TABLE,
    _group,
    _make_hook,
    _records,
    _sensitive_group,
    _write_litellm_config,
)

# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, detector",
    [
        ("key: sk-live-x7k9mQ8rF2nP4vL1", "api_key_detected"),
        ("OPENAI_API_KEY=sk-proj-abcdefghijklmnop1234", "api_key_detected"),
        ("stripe sk_live_51HxQabcdefghijklmnop", "api_key_detected"),
        ("GROQ_API_KEY=gsk_abcdefghijklmnopqrstu12", "api_key_detected"),
        ("token ghp_" + "a" * 36, "api_key_detected"),
        ("aws AKIAIOSFODNN7EXAMPLE", "api_key_detected"),
        ("slack xoxb-1234567890-abcdef", "api_key_detected"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "private_key_detected"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private_key_detected"),
        ("postgresql://admin:Tr0ub4dor@db9f.internal/app", "credential_url_detected"),
        ("https://user:hunter2@example.com/repo.git", "credential_url_detected"),
        ("SSN: 123-45-6789", "ssn_detected"),
        ("card 4111 1111 1111 1111 exp 12/29", "card_number_detected"),
        ("card 4111-1111-1111-1111", "card_number_detected"),
        ("amex 378282246310005", "card_number_detected"),
        ("contact jane.doe@example.com", "email_detected"),
        ("call (555) 123-4567", "phone_detected"),
        ("call +1 555-123-4567", "phone_detected"),
    ],
)
def test_detector_finds(text, detector):
    assert detector in detect(text)


@pytest.mark.parametrize(
    "text, detector",
    [
        ("the sk-short key", "api_key_detected"),
        ("task-livestream-abcdefghijklmnop", "api_key_detected"),  # sk- inside a word
        ("-----BEGIN PUBLIC KEY-----", "private_key_detected"),
        ("https://example.com/path@v2", "credential_url_detected"),
        ("postgresql://db.internal:5432/app", "credential_url_detected"),
        ("SSN 000-12-3456", "ssn_detected"),  # area 000 is never issued
        ("SSN 666-12-3456", "ssn_detected"),
        ("SSN 912-12-3456", "ssn_detected"),
        ("SSN 123-00-4567", "ssn_detected"),
        ("SSN 123-45-0000", "ssn_detected"),
        ("ref 123-45-67890", "ssn_detected"),  # longer run of digits
        ("card 4111 1111 1111 1112", "card_number_detected"),  # fails Luhn
        ("order 0000000000000000", "card_number_detected"),  # one repeated digit
        ("version 1.2.3", "phone_detected"),
        ("user at example dot com", "email_detected"),
    ],
)
def test_detector_ignores_near_misses(text, detector):
    assert detector not in detect(text)


def test_plain_text_matches_nothing():
    assert detect("Quarterly revenue grew 12% to $4.2M across 3 regions.") == set()


def test_scan_reads_user_and_tool_messages_only():
    messages = [
        {"role": "system", "content": "SSN 123-45-6789"},
        {"role": "assistant", "content": "card 4111 1111 1111 1111"},
        {"role": "user", "content": [{"type": "text", "text": "my key sk-live-x7k9mQ8rF2nP4vL1"}]},
        {"role": "tool", "tool_call_id": "t1", "content": "jane@example.com"},
    ]
    found = scan_messages(messages)
    assert set(found) == set(DETECTORS)
    assert {k for k, v in found.items() if v} == {"api_key_detected", "email_detected"}


def test_scan_skips_sink_result_echoes():
    """The receipt of the agent's own send is first-party, as in taint tracking."""
    messages = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "s1",
                    "type": "function",
                    "function": {"name": "send_email", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "s1", "content": "sent: SSN 123-45-6789"},
    ]
    assert not any(scan_messages(messages).values())


# ---------------------------------------------------------------------------
# Data-class rules
# ---------------------------------------------------------------------------

_RULES = [{"id": "r", "when": {"untrusted_seen": True}, "score": 0.5}]


def test_bundled_policy_classifies_only_high_confidence_detectors():
    engine = PolicyEngine.from_yaml()
    for detector in DETECTORS:
        data_class, rules = engine.classify({detector: True})
        expected = "public" if detector in ("email_detected", "phone_detected") else "sensitive"
        assert data_class == expected, detector
        assert bool(rules) == (expected == "sensitive"), detector
    assert engine.classify({}) == ("public", [])


@pytest.mark.parametrize(
    "data_classes, error",
    [
        ({"id": "x"}, "must be a list"),
        (["x"], "must be a mapping"),
        ([{"id": "r", "when": {"ssn_detected": True}, "class": "sensitive"}], "unique"),
        ([{"id": "x", "when": {}, "class": "sensitive"}], "non-empty 'when'"),
        ([{"id": "x", "when": {"untrusted_seen": True}, "class": "sensitive"}], "unknown features"),
        ([{"id": "x", "when": {"ssn_detected": True}, "class": "public"}], "class must be one of"),
        ([{"id": "x", "when": {"ssn_detected": True}, "class": "secret"}], "class must be one of"),
    ],
)
def test_invalid_data_class_rules_rejected(data_classes, error):
    with pytest.raises(ValueError, match=error):
        PolicyEngine.from_mapping({"rules": _RULES, "data_classes": data_classes})


def test_data_classes_without_routing_table_rejected():
    with pytest.raises(ValueError, match="need a routing table"):
        RoutingTable.from_mapping({"data_classes": []})


# ---------------------------------------------------------------------------
# Sensitive column checks
# ---------------------------------------------------------------------------


def _table(**overrides) -> RoutingTable:
    return RoutingTable.from_mapping({**json.loads(json.dumps(_TABLE)), **overrides})


def test_sensitive_column_must_keep_the_public_controls():
    routes = {**_TABLE["routes"], "sensitive-quarantine": {"model": "sensitive"}}
    with pytest.raises(ValueError, match="high/sensitive .* less restrictive than high/public"):
        _table(routes=routes)


def test_every_cell_of_the_sensitive_column_is_required():
    matrix = {**_TABLE["matrix"], "low": {"public": "standard"}}
    with pytest.raises(ValueError, match="low/sensitive is missing"):
        _table(matrix=matrix)


def test_sensitive_column_may_not_keep_the_requested_model(tmp_path):
    matrix = {**_TABLE["matrix"], "low": {"public": "standard", "sensitive": "standard"}}
    with pytest.raises(RuntimeError, match="sensitive column but keep the client's requested"):
        verify_model_groups(_table(matrix=matrix), "")


def _config(tmp_path, sensitive):
    return str(_write_litellm_config(tmp_path, _group("hardened"), _group("quarantine"), sensitive))


def test_sensitive_group_must_be_cleared(tmp_path):
    with pytest.raises(RuntimeError, match="not cleared for sensitive data"):
        verify_model_groups(_table(), _config(tmp_path, _group("sensitive")))


def test_every_deployment_of_the_sensitive_group_must_be_cleared(tmp_path):
    config = _write_litellm_config(
        tmp_path,
        _group("hardened"),
        _group("quarantine"),
        _sensitive_group(),
        _group("sensitive", model="groq/other"),
    )
    with pytest.raises(RuntimeError, match="groq/other"):
        verify_model_groups(_table(), str(config))


@pytest.mark.parametrize("cleared", ["sensitive", ["secret"]])
def test_malformed_cleared_for_rejected(tmp_path, cleared):
    with pytest.raises(RuntimeError, match="cleared_for"):
        verify_model_groups(_table(), _config(tmp_path, _group("sensitive", cleared=cleared)))


def test_cleared_sensitive_group_passes(tmp_path):
    verify_model_groups(_table(), _config(tmp_path, _sensitive_group()))


def test_legacy_table_needs_no_cleared_group(tmp_path):
    """A policy without a routing table never classifies, so nothing must be cleared."""
    table = RoutingTable.legacy()
    assert table.resolve("low", "sensitive") == table.resolve("low", "public")
    verify_model_groups(table, str(_write_litellm_config(tmp_path, _group("hardened"))))


def test_bundled_sensitive_routes_use_the_dedicated_group():
    table = RoutingTable.from_mapping(load_policy_document())
    for level in ("low", "elevated", "high"):
        public, sensitive = table.resolve(level, "public"), table.resolve(level, "sensitive")
        assert sensitive.model == "sensitive", level
        assert (sensitive.tools, sensitive.prompt, sensitive.hold) == (
            public.tools,
            public.prompt,
            public.hold,
        ), level
    assert table.resolve("critical", "sensitive").blocks


_ROOT = Path(__file__).parent.parent


@pytest.mark.parametrize(
    "config, prefix",
    [
        ("deploy/litellm_config.yaml", "openai/mock"),
        ("deploy/litellm_config.local.yaml", "openai/mock"),
        ("deploy/litellm_config.demo.yaml", "ollama_chat/"),
        ("deploy/litellm_config_prod.yaml", "ollama_chat/"),
    ],
)
def test_sensitive_group_is_local_outside_the_eval(config, prefix):
    """Production and the demo never send sensitive requests to a hosted provider."""
    entries = yaml.safe_load((_ROOT / config).read_text())["model_list"]
    sensitive = [e for e in entries if e["model_name"] == "sensitive"]
    assert sensitive, config
    for entry in sensitive:
        assert entry["litellm_params"]["model"].startswith(prefix), config
        assert entry["model_info"]["cleared_for"] == ["sensitive"], config


def test_production_sensitive_group_uses_the_task_sidecar():
    entries = yaml.safe_load((_ROOT / "deploy/litellm_config_prod.yaml").read_text())
    sensitive = next(e for e in entries["model_list"] if e["model_name"] == "sensitive")
    assert sensitive["litellm_params"]["api_base"] == "http://localhost:11434"


# ---------------------------------------------------------------------------
# Hook
# ---------------------------------------------------------------------------

_SSN = "123-45-6789"


def _data(*messages, session="sensitive", request_id="req-1"):
    return {
        "litellm_call_id": request_id,
        "model": "groq",
        "messages": list(messages) or [{"role": "user", "content": "hi"}],
        "tools": [{"type": "function", "function": {"name": "send_email", "parameters": {}}}],
        "metadata": {"headers": {"x-agent-run-id": issued(session)}},
    }


def _hook(monkeypatch, log_path, mode="session"):
    hook = _make_hook(monkeypatch, log_path)
    hook.config.mode = mode
    return hook


def _pii_turn():
    return (
        {"role": "user", "content": "Summarize the employee record."},
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
        {"role": "tool", "tool_call_id": "r1", "content": f"Name: Jane Roe. SSN: {_SSN}."},
    )


@pytest.fixture
def benign_classifier(monkeypatch):
    """A classifier that calls every tool result benign, so risk stays low."""

    async def classify(src):
        return {"source_id": src.get("tool_call_id"), "label": "BENIGN", "score": 0.0}

    monkeypatch.setattr(
        "router.hook._classify_sources",
        lambda clf, sources: _gather([classify(s) for s in sources]),
    )


async def _gather(coros):
    return [await c for c in coros]


@pytest.mark.asyncio
async def test_pii_routes_to_the_sensitive_model_with_tools(
    monkeypatch, log_path, benign_classifier
):
    hook = _hook(monkeypatch, log_path)
    hook._classifier = MagicMock()
    result = await hook.async_pre_call_hook(MagicMock(), MagicMock(), _data(*_pii_turn()), "x")

    assert result["model"] == "sensitive"
    assert "tools" in result  # sensitive data changes the model, not the tools
    record = _records(log_path)[-1]
    assert (record["risk_level"], record["data_class"]) == ("low", "sensitive")
    assert (record["route"], record["action"]) == ("sensitive", "allow")
    assert record["data_class_rules"] == ["ssn"]
    assert record["features"]["sensitive_detectors"] == ["ssn_detected"]
    assert _SSN not in Path(log_path).read_text()  # the matched text is never logged


@pytest.mark.asyncio
async def test_email_address_alone_stays_public(monkeypatch, log_path):
    hook = _hook(monkeypatch, log_path)
    data = _data({"role": "user", "content": "Email the notes to bob@example.com"})
    result = await hook.async_pre_call_hook(MagicMock(), MagicMock(), data, "x")
    assert result["model"] == "groq"
    record = _records(log_path)[-1]
    assert (record["data_class"], record["route"]) == ("public", "standard")
    assert record["features"]["sensitive_detectors"] == ["email_detected"]


@pytest.mark.asyncio
async def test_sensitive_class_is_sticky_in_session_mode(monkeypatch, log_path, benign_classifier):
    hook = _hook(monkeypatch, log_path)
    hook._classifier = MagicMock()
    await hook.async_pre_call_hook(MagicMock(), MagicMock(), _data(*_pii_turn()), "x")

    later = _data({"role": "user", "content": "Thanks, anything else?"}, request_id="req-2")
    result = await hook.async_pre_call_hook(MagicMock(), MagicMock(), later, "x")

    assert result["model"] == "sensitive"
    record = _records(log_path)[-1]
    assert (record["data_class"], record["data_class_rules"]) == ("sensitive", [])
    assert record["features"]["session_sensitive"] is True


@pytest.mark.asyncio
async def test_stateless_mode_classifies_each_request(monkeypatch, log_path, benign_classifier):
    hook = _hook(monkeypatch, log_path, mode="stateless")
    hook._classifier = MagicMock()
    await hook.async_pre_call_hook(MagicMock(), MagicMock(), _data(*_pii_turn()), "x")
    later = _data({"role": "user", "content": "Thanks"}, request_id="req-2")
    result = await hook.async_pre_call_hook(MagicMock(), MagicMock(), later, "x")
    assert result["model"] == "groq"
    assert _records(log_path)[-1]["data_class"] == "public"


@pytest.mark.asyncio
async def test_elevated_sensitive_request_keeps_the_hardened_controls(monkeypatch, log_path):
    hook = _hook(monkeypatch, log_path)
    monkeypatch.setattr(hook._policy, "assess", lambda f: (0.5, "elevated", ["forced"]))
    data = _data({"role": "user", "content": f"My SSN is {_SSN}"})
    result = await hook.async_pre_call_hook(MagicMock(), MagicMock(), data, "x")
    assert result["model"] == "sensitive"
    assert result["messages"][0]["role"] == "system"  # the hardened safety prompt
    record = _records(log_path)[-1]
    assert (record["route"], record["action"]) == ("sensitive-guarded", "route-hardened")


@pytest.mark.asyncio
async def test_post_call_routes_on_the_pre_call_data_class(monkeypatch, log_path):
    """sensitive-guarded holds generated sinks, like hardened."""
    from tests.test_routing import _tool_response

    hook = _hook(monkeypatch, log_path)
    levels = iter(["elevated", "low"])
    monkeypatch.setattr(hook._policy, "assess", lambda f: (0.0, next(levels), []))
    data = _data({"role": "user", "content": f"My SSN is {_SSN}"})
    await hook.async_pre_call_hook(MagicMock(), MagicMock(), data, "x")

    held = await hook.async_post_call_success_hook(MagicMock(), data, _tool_response())

    assert held.choices[0].message.tool_calls is None
    record = _records(log_path)[-1]
    assert (record["phase"], record["data_class"]) == ("post_call", "sensitive")
    assert (record["route"], record["action"]) == ("sensitive-guarded", "hold")
