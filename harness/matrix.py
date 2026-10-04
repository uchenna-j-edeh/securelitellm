"""Matrix runner — {stateless,session} × {L0..L3} × corpus × seeds → results.csv

Iterates all 8 (mode, level) configurations.  For each config it:
  1. Restarts the Docker Compose stack with the correct env vars.
  2. Waits for the proxy health check.
  3. Replays every corpus scenario N_SEEDS times.
  4. Writes all TurnResult rows to eval/results/results.csv.

Usage:
    uv run python harness/matrix.py [--seeds N] [--dry-run]
"""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from corpus.validate import Scenario
from harness.decisions import clear_log
from harness.runner import TurnResult, load_scenario, replay_scenario

REPO_ROOT = Path(__file__).parent.parent
COMPOSE_BASE = REPO_ROOT / "deploy" / "docker-compose.yml"
COMPOSE_OVERRIDE = REPO_ROOT / "harness" / "docker-compose.override.yml"
SCENARIOS_DIR = REPO_ROOT / "corpus" / "scenarios"
RESULTS_DIR = REPO_ROOT / "eval" / "results"
RESULTS_CSV = RESULTS_DIR / "results.csv"

PROXY_URL = os.getenv("PROXY_URL", "http://localhost:4000")
HEALTH_URL = f"{PROXY_URL}/health/liveliness"
LITELLM_MASTER_KEY = os.getenv("LITELLM_MASTER_KEY", "")

CONFIGS = [
    ("stateless", "L0"),
    ("stateless", "L1"),
    ("stateless", "L2"),
    ("stateless", "L3"),
    ("session", "L0"),
    ("session", "L1"),
    ("session", "L2"),
    ("session", "L3"),
]

CSV_FIELDS = [
    "mode",
    "level",
    "scenario_id",
    "scenario_label",
    "scenario_class",
    "turn_name",
    "turn_index",
    "is_attack_turn",
    "session_id",
    "seed",
    "action",
    "risk_score",
    "matched_rules",
    "latency_ms",
    "proxy_ok",
    # Derived classification columns (filled by metrics.py)
]


def _compose_cmd(*args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(COMPOSE_BASE),
        "-f",
        str(COMPOSE_OVERRIDE),
        *args,
    ]


def start_proxy(mode: str, level: str) -> None:
    """Restart the proxy stack with new ROUTER_MODE / ROUTER_LEVEL."""
    env = {
        **os.environ,
        "ROUTER_MODE": mode,
        "ROUTER_LEVEL": level,
        "ROUTER_ENFORCE": "true",
        "ROUTER_LOG_PATH": "/logs/decisions.jsonl",
    }
    # Stop any running stack first
    subprocess.run(_compose_cmd("down", "--remove-orphans"), check=False, capture_output=True)
    subprocess.run(_compose_cmd("up", "-d", "--build"), env=env, check=True, capture_output=True)
    print(f"  started proxy mode={mode} level={level}", flush=True)


def wait_healthy(timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(
                HEALTH_URL,
                headers={"Authorization": f"Bearer {LITELLM_MASTER_KEY}"},
            )
            with urllib.request.urlopen(req, timeout=5):
                return
        except Exception:
            time.sleep(2)
    raise TimeoutError(f"Proxy did not become healthy within {timeout}s")


def stop_proxy() -> None:
    subprocess.run(_compose_cmd("down"), check=False, capture_output=True)


def load_corpus() -> list[Scenario]:
    scenarios = []
    for path in sorted(SCENARIOS_DIR.glob("*.yaml")):
        scenarios.append(load_scenario(path))
    return scenarios


def _row(mode: str, level: str, tr: TurnResult) -> dict:
    return {
        "mode": mode,
        "level": level,
        "scenario_id": tr.scenario_id,
        "scenario_label": tr.scenario_label,
        "scenario_class": tr.scenario_class,
        "turn_name": tr.turn_name,
        "turn_index": tr.turn_index,
        "is_attack_turn": tr.is_attack_turn,
        "session_id": tr.session_id,
        "seed": tr.seed,
        "action": tr.action,
        "risk_score": tr.risk_score,
        "matched_rules": "|".join(tr.matched_rules),
        "latency_ms": round(tr.latency_ms, 3),
        "proxy_ok": tr.proxy_ok,
    }


def run_matrix(n_seeds: int = 3, dry_run: bool = False) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    corpus = load_corpus()
    print(f"Loaded {len(corpus)} scenarios, {n_seeds} seeds, {len(CONFIGS)} configs")
    print(f"Total runs: {len(corpus) * n_seeds * len(CONFIGS)}\n")

    with RESULTS_CSV.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for mode, level in CONFIGS:
            print(f"[{mode}/{level}] starting …", flush=True)

            if not dry_run:
                start_proxy(mode, level)
                wait_healthy()
                clear_log()

            for scenario in corpus:
                for seed in range(n_seeds):
                    label = f"  {scenario.id} seed={seed}"
                    if dry_run:
                        print(f"{label} [dry-run]")
                        continue

                    try:
                        results = replay_scenario(scenario, seed=seed)
                        for tr in results:
                            writer.writerow(_row(mode, level, tr))
                        fh.flush()
                        actions = [tr.action for tr in results]
                        print(f"{label} → {actions}")
                    except Exception as exc:
                        print(f"{label} ERROR: {exc}", file=sys.stderr)

            if not dry_run:
                stop_proxy()
                print(f"[{mode}/{level}] done\n")

    print(f"\nResults written to {RESULTS_CSV}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=3, help="runs per scenario (default 3)")
    parser.add_argument("--dry-run", action="store_true", help="enumerate only, no proxy")
    args = parser.parse_args()
    run_matrix(n_seeds=args.seeds, dry_run=args.dry_run)
