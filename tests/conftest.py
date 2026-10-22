"""Shared pytest fixtures."""

from pathlib import Path

import pytest

DEPLOY_LITELLM_CONFIG = Path(__file__).parent.parent / "deploy" / "litellm_config.yaml"


@pytest.fixture(autouse=True)
def _litellm_config(monkeypatch):
    """Every hook checks its routes against a LiteLLM config, as compose does."""
    monkeypatch.setenv("ROUTER_LITELLM_CONFIG", str(DEPLOY_LITELLM_CONFIG))
    monkeypatch.delenv("ROUTER_HARDENED_MODEL", raising=False)
    monkeypatch.delenv("ROUTER_ROUTE_HEADER", raising=False)


@pytest.fixture()
def log_path(tmp_path):
    return str(tmp_path / "decisions.jsonl")
