"""The mock model's per-request scripted replies (#177)."""

import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_spec = importlib.util.spec_from_file_location(
    "mock_model_main", Path(__file__).parents[1] / "deploy/mock_model/main.py"
)
mock_main = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mock_main)

_CALL = {"id": "c1", "type": "function", "function": {"name": "send_email", "arguments": "{}"}}
_TOOLS = [
    {"type": "function", "function": {"name": "send_email", "parameters": {"type": "object"}}}
]
_MESSAGES = [{"role": "user", "content": "go"}]


@pytest.fixture
def client():
    return TestClient(mock_main.app)


def _message(client, **body):
    resp = client.post("/v1/chat/completions", json={"model": "m", "messages": _MESSAGES, **body})
    assert resp.status_code == 200
    return resp.json()["choices"][0]


def test_scripted_tool_call_is_returned_when_tools_are_offered(client):
    choice = _message(client, tools=_TOOLS, mock_reply={"tool_calls": [_CALL]})
    assert choice["message"]["tool_calls"] == [_CALL]
    assert choice["finish_reason"] == "tool_calls"


@pytest.mark.parametrize(
    "extra",
    [{}, {"tools": _TOOLS, "tool_choice": "none"}],
    ids=["tools-removed", "tool-choice-none"],
)
def test_scripted_tool_call_becomes_text_without_tools(client, extra):
    """Like a real provider: no tools offered, no tool calls returned (the quarantine route)."""
    choice = _message(client, mock_reply={"content": "cannot", "tool_calls": [_CALL]}, **extra)
    assert choice["message"] == {"role": "assistant", "content": "cannot"}
    assert choice["finish_reason"] == "stop"

    bare = _message(client, mock_reply={"tool_calls": [_CALL]}, **extra)
    assert bare["message"]["content"] == mock_main._NO_TOOLS_TEXT


def test_scripted_text_reply(client):
    assert _message(client, mock_reply={"content": "hello"})["message"]["content"] == "hello"


def test_unscripted_request_still_echoes(client):
    assert _message(client)["message"] == {"role": "assistant", "content": "[mock] go"}
