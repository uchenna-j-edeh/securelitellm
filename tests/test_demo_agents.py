"""Registering the demo agent and its virtual key (#148)."""

import importlib.util
import os
import stat
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parent.parent / "scripts" / "demo_agents.py"
_spec = importlib.util.spec_from_file_location("demo_agents", _SCRIPT)
demo_agents = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo_agents)


def _env(tmp_path, text="LITELLM_MASTER_KEY=sk-local-master\n"):
    path = tmp_path / ".env"
    path.write_text(text)
    path.chmod(0o600)
    return path


def test_prepare_adds_the_missing_settings_and_keeps_the_file_private(tmp_path):
    path = _env(tmp_path, "LITELLM_MASTER_KEY=sk-local-master")  # no trailing newline
    assert demo_agents.prepare(path) == [
        "DEMO_AGENT_ID",
        "DEMO_AGENT_KEY",
        "LITELLM_DB_PASSWORD",
        "SESSION_DB_ADMIN_PASSWORD",
        "SESSION_DB_PROXY_PASSWORD",
        "SESSION_HMAC_KEY",
    ]
    values = demo_agents._parse_env(path)
    assert values["LITELLM_MASTER_KEY"] == "sk-local-master"
    assert values["DEMO_AGENT_ID"] == "demo-assistant"
    assert values["DEMO_AGENT_KEY"].startswith("sk-agent-") and len(values["DEMO_AGENT_KEY"]) > 40
    assert len(values["LITELLM_DB_PASSWORD"]) >= 32
    if os.name == "posix":  # Unix permission bits only
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_prepare_never_replaces_existing_settings(tmp_path):
    path = _env(tmp_path)
    demo_agents.prepare(path)
    before = path.read_text()
    assert demo_agents.prepare(path) == []
    assert path.read_text() == before


def test_prepare_needs_an_existing_env_file(tmp_path):
    with pytest.raises(demo_agents.AgentSetupError, match="demo-setup"):
        demo_agents.prepare(tmp_path / ".env")


class _Proxy:
    """A stand-in for the proxy's admin API."""

    def __init__(self, users=(), keys=None):
        self.users = set(users)
        self.keys = dict(keys or {})
        self.calls = []

    def __call__(self, base, method, route, master_key, body=None):
        self.calls.append((method, route.split("?")[0], body))
        if route == "/user/new":
            if body["user_id"] in self.users:
                return 409, {"error": {"message": f"User with id {body['user_id']} already exists"}}
            self.users.add(body["user_id"])
            return 200, {"user_id": body["user_id"]}
        if route.startswith("/key/info"):
            key = route.split("key=")[1]
            return (200, {"info": self.keys[key]}) if key in self.keys else (404, {"error": "none"})
        if route == "/key/generate":
            self.keys[body["key"]] = body
            return 200, {"key": body["key"]}
        if route in ("/key/block", "/key/unblock"):
            return (200, {}) if body["key"] in self.keys else (404, {"error": "none"})
        raise AssertionError(route)


@pytest.fixture()
def proxy(monkeypatch):
    fake = _Proxy()
    monkeypatch.setattr(demo_agents, "_call", fake)
    monkeypatch.setattr(demo_agents, "_wait_until_up", lambda base, timeout: None)
    return fake


def test_register_creates_the_agent_with_a_key_limited_to_chat(proxy):
    result = demo_agents.register("http://proxy", "sk-master", "demo-assistant", "sk-agent-1")
    assert result == "agent 'demo-assistant' created, key issued"
    user = next(body for _, route, body in proxy.calls if route == "/user/new")
    assert user == {
        "user_id": "demo-assistant",
        "user_role": "internal_user",
        "auto_create_key": False,
    }
    key = proxy.keys["sk-agent-1"]
    assert key["user_id"] == key["key_alias"] == "demo-assistant"
    # An unrestricted key can mint more keys for its own user.
    assert key["allowed_routes"] == ["/v1/chat/completions", "/chat/completions"]
    # The gateway chooses the route groups; a client can't ask for them.
    assert not {"hardened", "quarantine", "sensitive"} & set(key["models"])


def test_register_is_safe_to_repeat(proxy):
    demo_agents.register("http://proxy", "sk-master", "demo-assistant", "sk-agent-1")
    result = demo_agents.register("http://proxy", "sk-master", "demo-assistant", "sk-agent-1")
    assert result == "agent 'demo-assistant' exists, key exists"
    assert sum(route == "/key/generate" for _, route, _ in proxy.calls) == 1


def test_register_refuses_a_key_that_belongs_to_another_agent(proxy):
    proxy.keys["sk-agent-1"] = {
        "user_id": "someone-else",
        "allowed_routes": demo_agents.ALLOWED_ROUTES,
    }
    with pytest.raises(demo_agents.AgentSetupError, match="already registered to 'someone-else'"):
        demo_agents.register("http://proxy", "sk-master", "demo-assistant", "sk-agent-1")


def test_register_refuses_an_existing_unrestricted_key(proxy):
    proxy.keys["sk-agent-1"] = {"user_id": "demo-assistant", "allowed_routes": []}
    with pytest.raises(demo_agents.AgentSetupError, match="not limited to the chat-completions"):
        demo_agents.register("http://proxy", "sk-master", "demo-assistant", "sk-agent-1")


def test_block_and_unblock_use_the_admin_routes(proxy):
    demo_agents.register("http://proxy", "sk-master", "demo-assistant", "sk-agent-1")
    demo_agents.set_blocked("http://proxy", "sk-master", "sk-agent-1", True)
    demo_agents.set_blocked("http://proxy", "sk-master", "sk-agent-1", False)
    assert [route for _, route, _ in proxy.calls][-2:] == ["/key/block", "/key/unblock"]
    with pytest.raises(demo_agents.AgentSetupError, match="/key/block failed"):
        demo_agents.set_blocked("http://proxy", "sk-master", "sk-unknown", True)


def test_the_key_never_appears_in_command_output(proxy, monkeypatch, tmp_path, capsys):
    path = _env(tmp_path)
    monkeypatch.setattr(demo_agents, "ENV_PATH", path)
    for name in ("LITELLM_MASTER_KEY", "DEMO_AGENT_ID", "DEMO_AGENT_KEY", "PROXY_URL_SESSION"):
        monkeypatch.delenv(name, raising=False)
    assert demo_agents.main(["demo_agents.py", "prepare"]) == 0
    assert demo_agents.main(["demo_agents.py", "register"]) == 0
    assert demo_agents.main(["demo_agents.py", "block"]) == 0
    output = capsys.readouterr()
    key = demo_agents._parse_env(path)["DEMO_AGENT_KEY"]
    assert key not in output.out + output.err
    assert "sk-local-master" not in output.out + output.err
