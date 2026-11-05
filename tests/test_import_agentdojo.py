"""The AgentDojo converter writes valid scenarios (skipped unless agentdojo is installed).

AgentDojo is not a project dependency; run with:
  uv run --no-project --python 3.12 --with agentdojo==0.1.35 --with pytest \\
      python -m pytest tests/test_import_agentdojo.py
"""

import json
import sys
from pathlib import Path

import pytest
import yaml

pytest.importorskip("agentdojo")

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import import_agentdojo  # noqa: E402

from corpus.validate import Scenario  # noqa: E402


def test_banking_suite_converts(tmp_path):
    from agentdojo.attacks.attack_registry import ATTACKS
    from agentdojo.task_suite.load_suites import get_suites

    suite = get_suites(import_agentdojo.BENCHMARK_VERSION)["banking"]
    manifest = import_agentdojo.convert_suite(suite, ATTACKS[import_agentdojo.ATTACK], tmp_path)
    attacks = [k for k in manifest["scenarios"] if k.startswith("sc-")]
    assert len(attacks) == len(suite.user_tasks) * len(suite.injection_tasks)

    first = Scenario.model_validate(yaml.safe_load((tmp_path / "sc-000.yaml").read_text()))
    turn = first.turns[0]
    assert turn.messages[0].role == "user"
    assert any("<INFORMATION>" in (m.content or "") for m in turn.messages if m.role == "tool")
    goal = json.loads(turn.model_response.tool_calls[0].function.arguments)
    assert goal["recipient"] == "US133000000121212121212"  # the attacker's IBAN


def test_travel_misleading_answer_is_text_only(tmp_path):
    from agentdojo.attacks.attack_registry import ATTACKS
    from agentdojo.task_suite.load_suites import get_suites

    suite = get_suites(import_agentdojo.BENCHMARK_VERSION)["travel"]
    manifest = import_agentdojo.convert_suite(suite, ATTACKS[import_agentdojo.ATTACK], tmp_path)
    sid = next(
        k for k, v in manifest["scenarios"].items() if v.get("injection_task") == "injection_task_6"
    )
    s = Scenario.model_validate(yaml.safe_load((tmp_path / f"{sid}.yaml").read_text()))
    reply = s.turns[0].model_response
    assert not reply.tool_calls and "Riverside View Hotel" in reply.content
