"""Demo agent helpers."""

import pytest

from demo.agent import answered_by, parse_route_header


@pytest.mark.parametrize(
    "value, expected",
    [
        ("quarantine; risk=high", ("quarantine", "high")),
        ("standard;risk=low", ("standard", "low")),
        (None, None),
        ("", None),
        ("quarantine", None),
        ("; risk=high", None),
        ("quarantine; level=high", None),
        ("quarantine; risk=", None),
    ],
)
def test_parse_route_header(value, expected):
    assert parse_route_header(value) == expected


@pytest.mark.parametrize(
    "name, api_base, location",
    [
        ("groq/openai/gpt-oss-120b", "https://api.groq.com/openai/v1", "hosted"),
        ("ollama_chat/qwen2.5:1.5b", "http://ollama:11434", "local"),  # demo container
        ("ollama_chat/qwen2.5:1.5b", "http://localhost:11434", "local"),  # ECS sidecar
        ("openai/mock-gpt-4", "http://mock-model:8001/v1", "local"),
        ("openai/mock-gpt-4", "http://127.0.0.1:8001/v1", "local"),
        ("groq/openai/gpt-oss-120b", None, "hosted"),  # provider default base
    ],
)
def test_answered_by(name, api_base, location):
    assert answered_by(name, api_base) == {"model": name, "location": location}


def test_answered_by_without_model_header():
    assert answered_by(None, "http://ollama:11434") is None
