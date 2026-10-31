#!/usr/bin/env python3
"""Replay a corpus scenario against both demo proxies and print their decisions.

The deterministic fallback for the live demo: the turns, and any generated tool
call, are scripted (HARNESS_MODEL=mock), so the only thing that varies is the
proxy's memory. The demo proxies log decisions to stdout, not to the harness
log file, so this reads them from `docker logs`.

    make demo-replay SCENARIO=sc-047     # or: uv run python scripts/demo_replay.py sc-047

Run it with deploy/.env loaded (the make target does) and the demo stack up.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from harness import runner  # noqa: E402

PROXIES = (
    (
        "stateless",
        os.getenv("PROXY_URL_STATELESS", "http://localhost:4001"),
        os.getenv("CONTAINER_STATELESS", "deploy-litellm-stateless-1"),
    ),
    (
        "session",
        os.getenv("PROXY_URL_SESSION", "http://localhost:4000"),
        os.getenv("CONTAINER_SESSION", "deploy-litellm-1"),
    ),
)


def _records(container: str, since: datetime) -> list[dict]:
    logs = subprocess.run(
        ["docker", "logs", "--since", since.isoformat(), container],
        capture_output=True,
        text=True,
        check=False,
    )
    records = []
    for line in (logs.stdout + logs.stderr).splitlines():
        start = line.find("{")
        if start < 0:
            continue
        try:
            record = json.loads(line[start:])
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("phase"):
            records.append(record)
    return records


def _docker_wait(container: str):
    """harness.decisions.wait_for_decision, reading `docker logs` after a timestamp."""

    def wait(session, after_byte, timeout=10.0, poll_interval=0.2, phase=None, request_id=None):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for record in _records(container, after_byte):
                if record.get("session_id") != session:
                    continue
                if phase and record.get("phase") != phase:
                    continue
                if request_id and record.get("request_id") != request_id:
                    continue
                return record
            time.sleep(poll_interval)
        return None

    return wait


def replay(scenario_id: str) -> int:
    path = REPO_ROOT / "corpus" / "scenarios" / f"{scenario_id}.yaml"
    if not path.exists():
        print(f"no scenario {path.relative_to(REPO_ROOT)}", file=sys.stderr)
        return 2
    scenario = runner.load_scenario(path)
    print(f"{scenario.id} ({scenario.label}): {scenario.description.strip()}\n")
    runner.DEFAULT_MODEL = "mock"  # scripted replies; the demo config routes it to the mock
    runner.current_log_size = lambda: datetime.now(timezone.utc)
    failed = False
    for mode, url, container in PROXIES:
        runner.PROXY_URL = url
        runner.wait_for_decision = _docker_wait(container)
        print(f"== {mode} ({url})")
        for turn in runner.replay_scenario(scenario):
            failed |= not turn.proxy_ok or turn.action == "unknown"
            marker = "attack turn" if turn.is_attack_turn else "setup turn"
            line = f"  {turn.turn_name:<36} {marker:<12} {turn.action:<12} risk={turn.risk_level or '-'}"
            if turn.matched_rules:
                line += f" rules={','.join(turn.matched_rules)}"
            if turn.outcome:
                line += f" -> generated call {turn.outcome}"
            print(line)
        print()
    return int(failed)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: demo_replay.py SCENARIO_ID (e.g. sc-047)", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(replay(sys.argv[1]))
