"""Shared pytest fixtures."""

import pytest


@pytest.fixture()
def log_path(tmp_path):
    return str(tmp_path / "decisions.jsonl")
