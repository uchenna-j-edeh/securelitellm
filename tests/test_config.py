"""Tests for RouterConfig."""

import pytest

from router.config import RouterConfig


def test_defaults(monkeypatch):
    monkeypatch.delenv("ROUTER_MODE", raising=False)
    monkeypatch.delenv("ROUTER_LEVEL", raising=False)
    monkeypatch.delenv("ROUTER_LOG_PATH", raising=False)
    monkeypatch.delenv("CLASSIFIER_BACKEND", raising=False)
    cfg = RouterConfig.from_env()
    assert cfg.mode == "stateless"
    assert cfg.level == "L0"
    assert cfg.log_path == "-"
    assert cfg.classifier_backend == "none"


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("ROUTER_MODE", "session")
    monkeypatch.setenv("ROUTER_LEVEL", "L2")
    monkeypatch.setenv("ROUTER_LOG_PATH", "/tmp/test.jsonl")
    monkeypatch.setenv("CLASSIFIER_BACKEND", "promptguard")
    cfg = RouterConfig.from_env()
    assert cfg.mode == "session"
    assert cfg.level == "L2"
    assert cfg.log_path == "/tmp/test.jsonl"
    assert cfg.classifier_backend == "promptguard"


def test_invalid_mode(monkeypatch):
    monkeypatch.setenv("ROUTER_MODE", "turbo")
    with pytest.raises(ValueError, match="ROUTER_MODE"):
        RouterConfig.from_env()


def test_invalid_level(monkeypatch):
    monkeypatch.setenv("ROUTER_LEVEL", "L9")
    with pytest.raises(ValueError, match="ROUTER_LEVEL"):
        RouterConfig.from_env()


def test_invalid_classifier_backend(monkeypatch):
    monkeypatch.setenv("CLASSIFIER_BACKEND", "bogus")
    with pytest.raises(ValueError, match="CLASSIFIER_BACKEND"):
        RouterConfig.from_env()
