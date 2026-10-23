"""Tests for the corpus scenario schema and validator."""

from pathlib import Path

import pytest

from corpus.validate import Message, Scenario, validate_file

SCENARIOS_DIR = Path(__file__).parent.parent / "corpus" / "scenarios"


# ---------------------------------------------------------------------------
# Message constraints
# ---------------------------------------------------------------------------


def test_tool_message_requires_tool_call_id():
    with pytest.raises(Exception, match="tool_call_id"):
        Message.model_validate({"role": "tool", "content": "data"})


def test_assistant_message_requires_content_or_tool_calls():
    with pytest.raises(Exception, match="content or tool_calls"):
        Message.model_validate({"role": "assistant"})


def test_user_message_valid():
    m = Message.model_validate({"role": "user", "content": "hello"})
    assert m.role == "user"


def test_tool_message_valid():
    m = Message.model_validate({"role": "tool", "tool_call_id": "tc-1", "content": "result"})
    assert m.tool_call_id == "tc-1"


def test_assistant_tool_call_valid():
    m = Message.model_validate(
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "c1",
                    "type": "function",
                    "function": {"name": "send_email", "arguments": "{}"},
                }
            ],
        }
    )
    assert m.tool_calls[0].function.name == "send_email"


def test_assistant_empty_tool_calls_fails():
    with pytest.raises(Exception, match="content or tool_calls"):
        Message.model_validate({"role": "assistant", "content": None, "tool_calls": []})


def test_tool_arguments_must_be_valid_json_object():
    with pytest.raises(Exception, match="valid JSON"):
        Message.model_validate(
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {"name": "send_email", "arguments": "not-json"},
                    }
                ],
            }
        )


def test_unknown_message_field_fails():
    with pytest.raises(Exception, match="Extra inputs"):
        Message.model_validate({"role": "user", "content": "hello", "contnet": "typo"})


# ---------------------------------------------------------------------------
# Scenario-level constraints
# ---------------------------------------------------------------------------

_MINIMAL_ATTACK = {
    "id": "sc-001",
    "name": "test",
    "label": "attack",
    "class": "direct_exfil",
    "description": "test scenario",
    "turns": [
        {
            "name": "t1",
            "is_attack_turn": True,
            "messages": [{"role": "user", "content": "hello"}],
        }
    ],
}

_MINIMAL_BENIGN = {
    "id": "bn-001",
    "name": "test",
    "label": "benign",
    "class": "direct_exfil",
    "description": "benign scenario",
    "turns": [
        {
            "name": "t1",
            "messages": [{"role": "user", "content": "hello"}],
        }
    ],
}


def test_minimal_attack_valid():
    s = Scenario.model_validate(_MINIMAL_ATTACK)
    assert s.label == "attack"
    assert s.scenario_class == "direct_exfil"


def test_minimal_benign_valid():
    s = Scenario.model_validate(_MINIMAL_BENIGN)
    assert s.label == "benign"


def test_attack_without_attack_turn_fails():
    bad = {
        **_MINIMAL_ATTACK,
        "turns": [{"name": "t1", "messages": [{"role": "user", "content": "x"}]}],
    }
    with pytest.raises(Exception, match="is_attack_turn"):
        Scenario.model_validate(bad)


def test_invalid_id_format_fails():
    bad = {**_MINIMAL_ATTACK, "id": "attack-001"}
    with pytest.raises(Exception):
        Scenario.model_validate(bad)


def test_sc_prefix_valid():
    s = Scenario.model_validate({**_MINIMAL_ATTACK, "id": "sc-042"})
    assert s.id == "sc-042"


def test_bn_prefix_valid():
    s = Scenario.model_validate({**_MINIMAL_BENIGN, "id": "bn-099"})
    assert s.id == "bn-099"


def test_attack_label_requires_sc_prefix():
    with pytest.raises(Exception, match="attack scenario ids"):
        Scenario.model_validate({**_MINIMAL_ATTACK, "id": "bn-001"})


def test_benign_label_requires_bn_prefix():
    with pytest.raises(Exception, match="benign scenario ids"):
        Scenario.model_validate({**_MINIMAL_BENIGN, "id": "sc-001"})


def test_variant_of_without_tag_fails():
    bad = {**_MINIMAL_ATTACK, "variant_of": "sc-001"}
    with pytest.raises(Exception, match="variant"):
        Scenario.model_validate(bad)


def test_variant_tag_without_variant_of_fails():
    bad = {**_MINIMAL_ATTACK, "variant_tag": "paraphrase"}
    with pytest.raises(Exception, match="variant"):
        Scenario.model_validate(bad)


def test_variant_pair_valid():
    s = Scenario.model_validate(
        {**_MINIMAL_ATTACK, "id": "sc-002", "variant_of": "sc-001", "variant_tag": "paraphrase"}
    )
    assert s.variant_tag == "paraphrase"


def test_variant_cannot_reference_itself():
    bad = {**_MINIMAL_ATTACK, "variant_of": "sc-001", "variant_tag": "paraphrase"}
    with pytest.raises(Exception, match="itself"):
        Scenario.model_validate(bad)


def test_unknown_class_fails():
    bad = {**_MINIMAL_ATTACK, "class": "social_engineering"}
    with pytest.raises(Exception):
        Scenario.model_validate(bad)


def test_empty_turns_fails():
    bad = {**_MINIMAL_ATTACK, "turns": []}
    with pytest.raises(Exception):
        Scenario.model_validate(bad)


def test_unknown_scenario_field_fails():
    bad = {**_MINIMAL_ATTACK, "expected_detect": {}}
    with pytest.raises(Exception, match="Extra inputs"):
        Scenario.model_validate(bad)


# ---------------------------------------------------------------------------
# validate_file helper
# ---------------------------------------------------------------------------


def test_validate_file_returns_empty_for_valid(tmp_path):
    import yaml

    path = tmp_path / "sc-001.yaml"
    path.write_text(yaml.dump(_MINIMAL_ATTACK))
    assert validate_file(path) == []


def test_validate_file_returns_errors_for_invalid(tmp_path):
    import yaml

    bad = {**_MINIMAL_ATTACK, "id": "bad-id"}
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.dump(bad))
    errors = validate_file(path)
    assert len(errors) > 0


def test_validate_file_handles_yaml_parse_error(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("id: [unclosed")
    errors = validate_file(path)
    assert any("YAML" in e or "parse" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# Integration — all corpus scenarios must be valid
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", sorted(SCENARIOS_DIR.glob("*.yaml")))
def test_corpus_scenario_valid(path):
    errors = validate_file(path)
    assert errors == [], f"{path.name} failed validation:\n" + "\n".join(errors)


def test_delayed_exfil_first_turn_has_no_dangerous_sink():
    import yaml

    from router.policy import PolicyEngine
    from router.taint import classify_sinks, classify_sources

    raw = yaml.safe_load((SCENARIOS_DIR / "sc-010.yaml").read_text())
    messages = raw["turns"][0]["messages"]
    features = {
        "untrusted_seen": bool(classify_sources(messages)),
        "sink_requested": bool(classify_sinks(messages)),
    }
    _, action, _ = PolicyEngine.from_yaml().evaluate(features)
    assert action == "allow"


# ---------------------------------------------------------------------------
# Scripted model replies (#177)
# ---------------------------------------------------------------------------

_SEND = {
    "id": "c1",
    "type": "function",
    "function": {"name": "send_email", "arguments": '{"to":"a@b.c"}'},
}


def _two_turns(first: dict, second: dict) -> list[dict]:
    return [
        {"name": "t1", "messages": [{"role": "user", "content": "a"}], **first},
        {"name": "t2", "messages": [{"role": "user", "content": "b"}], **second},
    ]


def test_scripted_tool_call_on_attack_turn_valid():
    s = Scenario.model_validate(
        {
            **_MINIMAL_ATTACK,
            "turns": _two_turns(
                {}, {"is_attack_turn": True, "model_response": {"tool_calls": [_SEND]}}
            ),
        }
    )
    assert [t.function.name for t in s.turns[1].scripted_tool_calls] == ["send_email"]
    assert s.turns[0].scripted_tool_calls == []


def test_model_response_must_not_be_empty():
    bad = {**_MINIMAL_BENIGN, "turns": [{**_MINIMAL_BENIGN["turns"][0], "model_response": {}}]}
    with pytest.raises(Exception, match="content or tool_calls"):
        Scenario.model_validate(bad)


def test_model_response_only_on_last_turn():
    bad = {**_MINIMAL_BENIGN, "turns": _two_turns({"model_response": {"content": "hi"}}, {})}
    with pytest.raises(Exception, match="last turn"):
        Scenario.model_validate(bad)


def test_attack_scripted_tool_call_must_be_attack_turn():
    turns = _two_turns({"is_attack_turn": True}, {"model_response": {"tool_calls": [_SEND]}})
    with pytest.raises(Exception, match="must be an attack turn"):
        Scenario.model_validate({**_MINIMAL_ATTACK, "turns": turns})


@pytest.mark.parametrize("path", sorted(SCENARIOS_DIR.glob("*.yaml")))
def test_generated_variants_script_a_tool_call(path):
    """A 'generated' variant replays its sink as a model reply, not as request history."""
    from harness.runner import load_scenario

    s = load_scenario(path)
    scripted = [t for t in s.turns if t.scripted_tool_calls]
    assert bool(scripted) == (s.variant_tag == "generated"), path.name
    for turn in scripted:
        sent = [tc for m in turn.messages for tc in m.tool_calls or []]
        assert not {tc.function.name for tc in sent} & {
            tc.function.name for tc in turn.scripted_tool_calls
        }, path.name
