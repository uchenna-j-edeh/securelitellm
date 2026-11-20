#!/usr/bin/env python3
"""Register the demo agent and its virtual key with the demo proxies (#148).

Each agent is a LiteLLM internal user whose user_id is the agent's name, with
its own key. The hook reads that identity from LiteLLM's key authentication and
records it in every decision.

    python scripts/demo_agents.py prepare    # before the stack starts
    python scripts/demo_agents.py register   # once the session proxy is up
    python scripts/demo_agents.py block      # revoke the agent's key
    python scripts/demo_agents.py unblock    # restore it

``prepare`` adds any missing settings to deploy/.env: the database password, the
agent's name and a new random key. ``register`` creates the user and the key
through the proxy's admin API, using the master key. Both are safe to repeat.
`make demo-dual-up` runs them. The key is never printed.

The key may call only the chat-completions routes. An unrestricted LiteLLM key
can create further keys for its own user, which would survive revoking the
original (checked against LiteLLM 1.103.2).
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / "deploy" / ".env"
DEFAULT_AGENT_ID = "demo-assistant"
# The model groups a client may ask for. The route groups (hardened,
# quarantine, sensitive) are chosen by the gateway, never requested.
REQUESTABLE_MODELS = ["gpt", "bedrock", "groq", "llm", "mock"]
ALLOWED_ROUTES = ["/v1/chat/completions", "/chat/completions"]


class AgentSetupError(Exception):
    pass


def _parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        values[name.strip()] = value.strip().strip("'\"")
    return values


def prepare(path: Path | None = None) -> list[str]:
    """Append the settings that are missing. Returns the names added."""
    path = path or ENV_PATH
    if not path.is_file():
        raise AgentSetupError(f"{path} is missing; run 'make demo-setup' first")
    values = _parse_env(path)
    wanted = {
        "LITELLM_DB_PASSWORD": lambda: secrets.token_urlsafe(32),
        "DEMO_AGENT_ID": lambda: DEFAULT_AGENT_ID,
        "DEMO_AGENT_KEY": lambda: f"sk-agent-{secrets.token_urlsafe(40)}",
        # Persistent session store (#169), used with SESSION_DB=1 make demo-dual-up.
        "SESSION_DB_ADMIN_PASSWORD": lambda: secrets.token_urlsafe(32),
        "SESSION_DB_PROXY_PASSWORD": lambda: secrets.token_urlsafe(32),
        "SESSION_HMAC_KEY": lambda: secrets.token_urlsafe(48),
    }
    missing = {name: make() for name, make in wanted.items() if not values.get(name)}
    if missing:
        text = path.read_text(encoding="utf-8")
        if text and not text.endswith("\n"):
            text += "\n"
        text += "".join(f"{name}={value}\n" for name, value in missing.items())
        path.write_text(text, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return sorted(missing)


def _call(base: str, method: str, route: str, master_key: str, body: dict | None = None):
    """(status, parsed body) from the proxy's admin API."""
    request = urllib.request.Request(
        base + route,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Authorization": f"Bearer {master_key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"error": raw.decode(errors="replace")[:300]}


def _wait_until_up(base: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            with urllib.request.urlopen(base + "/health/liveliness", timeout=3):
                return
        except OSError:
            if time.monotonic() > deadline:
                raise AgentSetupError(f"proxy at {base} did not come up") from None
            time.sleep(2)


def register(
    base: str, master_key: str, agent_id: str, agent_key: str, *, wait: float = 180
) -> str:
    """Create the agent and its key if they don't exist. Returns what was done."""
    _wait_until_up(base, wait)

    status, body = _call(
        base,
        "POST",
        "/user/new",
        master_key,
        {"user_id": agent_id, "user_role": "internal_user", "auto_create_key": False},
    )
    if status == 200:
        user = "created"
    elif "already exists" in json.dumps(body):
        user = "exists"
    else:
        raise AgentSetupError(f"could not register agent {agent_id!r}: HTTP {status} {body}")

    status, body = _call(base, "GET", f"/key/info?key={agent_key}", master_key)
    if status == 200:
        info = body.get("info") or {}
        if info.get("user_id") != agent_id:
            raise AgentSetupError(
                f"DEMO_AGENT_KEY is already registered to {info.get('user_id')!r}, "
                f"not {agent_id!r}; remove DEMO_AGENT_KEY from deploy/.env to issue a new one"
            )
        if sorted(info.get("allowed_routes") or []) != sorted(ALLOWED_ROUTES):
            raise AgentSetupError(
                "the registered key is not limited to the chat-completions routes; "
                "delete it (/key/delete) and run this again"
            )
        return f"agent {agent_id!r} {user}, key exists"

    status, body = _call(
        base,
        "POST",
        "/key/generate",
        master_key,
        {
            "user_id": agent_id,
            "key_alias": agent_id,
            "key": agent_key,
            "models": REQUESTABLE_MODELS,
            "allowed_routes": ALLOWED_ROUTES,
        },
    )
    if status != 200:
        raise AgentSetupError(f"could not issue a key for {agent_id!r}: HTTP {status} {body}")
    return f"agent {agent_id!r} {user}, key issued"


def set_blocked(base: str, master_key: str, agent_key: str, blocked: bool) -> None:
    """Block or unblock the agent's key. The other proxy follows within its key-cache TTL."""
    route = "/key/block" if blocked else "/key/unblock"
    status, body = _call(base, "POST", route, master_key, {"key": agent_key})
    if status != 200:
        raise AgentSetupError(f"{route} failed: HTTP {status} {body}")


def main(argv: list[str]) -> int:
    command = argv[1] if len(argv) > 1 else ""
    try:
        if command == "prepare":
            added = prepare()
            print("agent settings: " + (f"added {', '.join(added)}" if added else "already set"))
            return 0
        if command == "register":
            values = {**_parse_env(ENV_PATH), **os.environ}
            for name in ("LITELLM_MASTER_KEY", "DEMO_AGENT_ID", "DEMO_AGENT_KEY"):
                if not values.get(name):
                    raise AgentSetupError(f"{name} is not set; run 'prepare' first")
            base = values.get("PROXY_URL_SESSION", "http://localhost:4000")
            print(
                register(
                    base,
                    values["LITELLM_MASTER_KEY"],
                    values["DEMO_AGENT_ID"],
                    values["DEMO_AGENT_KEY"],
                )
            )
            # The stateless proxy shares the database and starts after the
            # session proxy; return only once it can serve the key too.
            _wait_until_up(values.get("PROXY_URL_STATELESS", "http://localhost:4001"), 180)
            return 0
        if command in ("block", "unblock"):
            values = {**_parse_env(ENV_PATH), **os.environ}
            for name in ("LITELLM_MASTER_KEY", "DEMO_AGENT_ID", "DEMO_AGENT_KEY"):
                if not values.get(name):
                    raise AgentSetupError(f"{name} is not set; run 'prepare' first")
            base = values.get("PROXY_URL_SESSION", "http://localhost:4000")
            set_blocked(
                base, values["LITELLM_MASTER_KEY"], values["DEMO_AGENT_KEY"], command == "block"
            )
            print(f"agent {values['DEMO_AGENT_ID']!r} key {command}ed")
            return 0
    except AgentSetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print("usage: demo_agents.py prepare|register|block|unblock", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
