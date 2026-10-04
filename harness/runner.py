"""Agent driver — replay one corpus scenario through the LiteLLM proxy.

Each turn sends ONLY its own incremental messages (not cumulative history).
The session ID is shared across turns via x-agent-run-id so the session store
accumulates taint, but stateless routing never sees cross-turn context.

Usage (standalone test):
    PROXY_URL=http://localhost:4000 uv run python harness/runner.py sc-010
"""

from __future__ import annotations

import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Allow running from project root without installing
sys.path.insert(0, str(Path(__file__).parent.parent))

from corpus.validate import Scenario
from harness.decisions import current_log_size, wait_for_decision

# Load deploy/.env so LITELLM_MASTER_KEY is available when run standalone
_ENV_FILE = Path(__file__).parent.parent / "deploy" / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            if _k not in os.environ:
                os.environ[_k] = _v

PROXY_URL = os.getenv("PROXY_URL", "http://localhost:4000")
LITELLM_MASTER_KEY = os.getenv("LITELLM_MASTER_KEY", "")
DEFAULT_MODEL = "groq/llama-3.1-8b-instant"
REQUEST_TIMEOUT = 30


@dataclass
class TurnResult:
    scenario_id: str
    scenario_label: str  # "attack" | "benign"
    scenario_class: str  # "direct_exfil" | ...
    turn_name: str
    turn_index: int
    is_attack_turn: bool
    session_id: str
    seed: int
    # Decision record fields (None if proxy returned no decision in time)
    action: str = "unknown"
    risk_score: float = 0.0
    matched_rules: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    proxy_ok: bool = True  # False if HTTP error / timeout


def _messages_to_api(turn_messages: list) -> list[dict]:
    """Convert Pydantic Message objects to plain dicts for the OpenAI API."""
    out = []
    for m in turn_messages:
        d: dict = {"role": m.role}
        if m.content is not None:
            d["content"] = m.content
        if m.tool_call_id is not None:
            d["tool_call_id"] = m.tool_call_id
        if m.tool_calls is not None:
            d["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in m.tool_calls
            ]
        out.append(d)
    return out


def _post_turn(session_id: str, messages: list[dict]) -> tuple[bool, float]:
    """POST one turn to the proxy. Returns (ok, wall_ms)."""
    import json

    payload = json.dumps({"model": DEFAULT_MODEL, "messages": messages}).encode()

    req = urllib.request.Request(
        f"{PROXY_URL}/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {LITELLM_MASTER_KEY}",
            "x-agent-run-id": session_id,
        },
        method="POST",
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT):
            pass
        return True, (time.perf_counter() - t0) * 1000
    except urllib.error.HTTPError as exc:
        # 400/403 from block/strip-tools — proxy acted, still a valid decision
        if exc.code in (400, 403):
            return True, (time.perf_counter() - t0) * 1000
        return False, (time.perf_counter() - t0) * 1000
    except Exception:
        return False, (time.perf_counter() - t0) * 1000


def replay_scenario(scenario: Scenario, seed: int = 0) -> list[TurnResult]:
    """Replay all turns of a scenario. Returns one TurnResult per turn."""
    session_id = f"{scenario.id}-s{seed}"
    results: list[TurnResult] = []

    for idx, turn in enumerate(scenario.turns):
        before_byte = current_log_size()
        messages = _messages_to_api(turn.messages)
        ok, wall_ms = _post_turn(session_id, messages)

        decision = wait_for_decision(session_id, after_byte=before_byte) if ok else None

        tr = TurnResult(
            scenario_id=scenario.id,
            scenario_label=scenario.label,
            scenario_class=scenario.scenario_class,
            turn_name=turn.name,
            turn_index=idx,
            is_attack_turn=turn.is_attack_turn,
            session_id=session_id,
            seed=seed,
            proxy_ok=ok,
        )
        if decision:
            tr.action = decision.get("action", "unknown")
            tr.risk_score = float(decision.get("risk_score", 0.0))
            tr.matched_rules = decision.get("matched_rules", [])
            tr.latency_ms = float(decision.get("latency_ms", wall_ms))
        else:
            tr.latency_ms = wall_ms

        results.append(tr)

    return results


def load_scenario(path: Path) -> Scenario:
    raw = yaml.safe_load(path.read_text())
    return Scenario.model_validate(raw)


if __name__ == "__main__":
    import json as _json

    scenario_id = sys.argv[1] if len(sys.argv) > 1 else "sc-010"
    paths = sorted(Path("corpus/scenarios").glob(f"{scenario_id}.yaml"))
    if not paths:
        sys.exit(f"Scenario {scenario_id} not found")

    sc = load_scenario(paths[0])
    print(f"Replaying {sc.id} ({sc.label}/{sc.scenario_class}) …")
    results = replay_scenario(sc, seed=0)
    for tr in results:
        print(_json.dumps(tr.__dict__, indent=2))
