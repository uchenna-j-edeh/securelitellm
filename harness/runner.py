"""Agent driver — replay one corpus scenario through the LiteLLM proxy.

Two history modes:
  incremental  Each turn sends ONLY its own messages.  The session store
               accumulates taint via x-agent-run-id, but stateless routing
               never sees cross-turn context.  This is the baseline.

Sessions are issued by the proxy (#145). Each replay first opens a session the
way a real agent does — a request carrying only the scenario's leading user
message — reads the issued id from the x-agent-run-id response header, and
sends it with every turn. Corpus turns compress a whole agent step (user →
tool call → tool result) into one request, so they cannot open a session
themselves: the proxy rejects a new session that already contains tool turns.
  full         Each turn sends ALL prior turns' messages prepended to its own,
               mirroring how a real agent maintains conversation context.
               Stateless routing can then detect cross-turn attacks because the
               tool result from Turn 1 is present in Turn 2's request.

Usage (standalone test):
    PROXY_URL=http://localhost:4000 uv run python harness/runner.py sc-010
    PROXY_URL=http://localhost:4000 uv run python harness/runner.py sc-010 --history full
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
from router.session import session_ref

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
# Model the replay requests target. Defaults to Groq, but set HARNESS_MODEL=mock to
# drive the local mock model instead — the eval's metric (router action) is decided by
# the proxy hook, not the model's reply, so mock removes Groq latency/rate-limits.
DEFAULT_MODEL = os.environ.get("HARNESS_MODEL", "groq/llama-3.1-8b-instant")
REQUEST_TIMEOUT = 30
SESSION_HEADER = "x-agent-run-id"
_SESSION_START_ROLES = {"system", "developer", "user"}


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
    history_mode: str = "incremental"  # "incremental" | "full"
    # Decision record fields (None if proxy returned no decision in time)
    action: str = "unknown"
    risk_level: str = ""  # low | elevated | high | critical ("" if the record has none)
    route: str = ""
    data_class: str = ""  # public | sensitive ("" if the record has none, #181)
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


def _post_turn(
    messages: list[dict], session_id: str | None = None
) -> tuple[bool, float, str | None]:
    """POST one turn to the proxy. Returns (ok, wall_ms, issued session id or None)."""
    import json

    payload = json.dumps({"model": DEFAULT_MODEL, "messages": messages}).encode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LITELLM_MASTER_KEY}",
    }
    if session_id:
        headers[SESSION_HEADER] = session_id

    req = urllib.request.Request(
        f"{PROXY_URL}/chat/completions",
        data=payload,
        headers=headers,
        method="POST",
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            issued = resp.headers.get(SESSION_HEADER)
        return True, (time.perf_counter() - t0) * 1000, issued
    except urllib.error.HTTPError as exc:
        # 400/403 from block/strip-tools — proxy acted, still a valid decision
        issued = exc.headers.get(SESSION_HEADER) if exc.headers else None
        if exc.code in (400, 403):
            return True, (time.perf_counter() - t0) * 1000, issued
        return False, (time.perf_counter() - t0) * 1000, issued
    except Exception:
        return False, (time.perf_counter() - t0) * 1000, None


def _opening_messages(first_turn: list[dict]) -> list[dict]:
    """The leading system/user messages of a scenario — what a real agent's first request holds."""
    opening = []
    for m in first_turn:
        if m.get("role") not in _SESSION_START_ROLES:
            break
        opening.append(m)
    return opening or [{"role": "user", "content": "start"}]


def _open_session(first_turn: list[dict]) -> str | None:
    """Start a proxy session; return the issued x-agent-run-id (None on failure)."""
    _, _, issued = _post_turn(_opening_messages(first_turn))
    return issued


def replay_scenario(
    scenario: Scenario,
    seed: int = 0,
    history_mode: str = "incremental",
) -> list[TurnResult]:
    """Replay all turns of a scenario. Returns one TurnResult per turn.

    history_mode="incremental": each turn sends only its own messages (baseline).
    history_mode="full": each turn sends all prior turns' messages prepended,
        mirroring a real agent that maintains full conversation context.
    """
    run_label = f"{scenario.id}-s{seed}-{history_mode}"
    results: list[TurnResult] = []
    accumulated: list[dict] = []  # grows turn-by-turn in full mode

    session_id = _open_session(_messages_to_api(scenario.turns[0].messages))
    ref = session_ref(session_id) if session_id else None

    for idx, turn in enumerate(scenario.turns):
        before_byte = current_log_size()
        turn_messages = _messages_to_api(turn.messages)

        if history_mode == "full":
            messages = accumulated + turn_messages
        else:
            messages = turn_messages

        ok, wall_ms, _ = _post_turn(messages, session_id)
        accumulated.extend(turn_messages)

        decision = wait_for_decision(ref, after_byte=before_byte) if ok and ref else None

        tr = TurnResult(
            scenario_id=scenario.id,
            scenario_label=scenario.label,
            scenario_class=scenario.scenario_class,
            turn_name=turn.name,
            turn_index=idx,
            is_attack_turn=turn.is_attack_turn,
            session_id=run_label,
            seed=seed,
            history_mode=history_mode,
            proxy_ok=ok,
        )
        if decision:
            tr.action = decision.get("action", "unknown")
            tr.risk_level = decision.get("risk_level", "")
            tr.route = decision.get("route", "")
            tr.data_class = decision.get("data_class", "")
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
    import argparse
    import json as _json

    parser = argparse.ArgumentParser()
    parser.add_argument("scenario_id", nargs="?", default="sc-010")
    parser.add_argument(
        "--history",
        choices=["incremental", "full"],
        default="incremental",
        help="incremental=turn-only messages (default); full=cumulative history",
    )
    args = parser.parse_args()

    paths = sorted(Path("corpus/scenarios").glob(f"{args.scenario_id}.yaml"))
    if not paths:
        sys.exit(f"Scenario {args.scenario_id} not found")

    sc = load_scenario(paths[0])
    print(f"Replaying {sc.id} ({sc.label}/{sc.scenario_class}) history={args.history} …")
    results = replay_scenario(sc, seed=0, history_mode=args.history)
    for tr in results:
        print(_json.dumps(tr.__dict__, indent=2))
