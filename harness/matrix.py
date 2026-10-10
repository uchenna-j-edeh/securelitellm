"""Matrix runner — {stateless,session} × {L0..L3} × corpus × seeds → results.csv

Iterates all 8 (mode, level) configurations.  For each config it:
  1. Restarts the Docker Compose stack with the correct env vars.
  2. Waits for the proxy health check.
  3. Replays every corpus scenario N_SEEDS times.
  4. Writes all TurnResult rows to eval/results/results.csv.

Usage:
    uv run python harness/matrix.py [--seeds N] [--dry-run]

To run with the local DeBERTa classifier:
    CLASSIFIER_BACKEND=local uv run python harness/matrix.py --seeds 3
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
COMPOSE_CLASSIFIER = REPO_ROOT / "deploy" / "docker-compose.classifier.yml"
ENV_FILE = REPO_ROOT / "deploy" / ".env"
SCENARIOS_DIR = REPO_ROOT / "corpus" / "scenarios"
RESULTS_DIR = REPO_ROOT / "eval" / "results"
RESULTS_CSV = RESULTS_DIR / "results.csv"

PROXY_URL = os.getenv("PROXY_URL", "http://localhost:4000")
HEALTH_URL = f"{PROXY_URL}/health/liveliness"


def _load_env_file() -> None:
    """Load deploy/.env into os.environ so LITELLM_MASTER_KEY is available for HTTP calls."""
    if not ENV_FILE.exists():
        return
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        if key not in os.environ:  # don't override shell env
            os.environ[key] = val


_load_env_file()
LITELLM_MASTER_KEY = os.getenv("LITELLM_MASTER_KEY", "")

# (mode, level) — one proxy restart per entry.
# Stateless runs both history modes (incremental + full) in the same proxy
# instance since history mode only affects what the harness sends, not how
# the proxy is configured.  Session runs use incremental only — the session
# store already provides cross-turn memory.
CONFIGS = [
    ("stateless", "L0"),
    ("stateless", "L1"),
    ("stateless", "L2"),
    ("stateless", "L3"),
    ("session",   "L0"),
    ("session",   "L1"),
    ("session",   "L2"),
    ("session",   "L3"),
]

HISTORY_MODES: dict[str, list[str]] = {
    "stateless": ["incremental", "full"],
    "session":   ["incremental"],
}

CSV_FIELDS = [
    "mode",
    "level",
    "history_mode",
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
    cmd = ["docker", "compose", "-f", str(COMPOSE_BASE), "-f", str(COMPOSE_OVERRIDE)]
    # Include the classifier sidecar overlay when running with the local backend.
    if os.environ.get("CLASSIFIER_BACKEND", "none").lower() == "local":
        cmd += ["-f", str(COMPOSE_CLASSIFIER)]
    if ENV_FILE.exists():
        cmd += ["--env-file", str(ENV_FILE)]
    return [*cmd, *args]


def start_proxy(mode: str, level: str) -> None:
    """Restart the proxy stack with new ROUTER_MODE / ROUTER_LEVEL."""
    classifier_backend = os.environ.get("CLASSIFIER_BACKEND", "none")
    env = {
        **os.environ,
        "ROUTER_MODE": mode,
        "ROUTER_LEVEL": level,
        "ROUTER_ENFORCE": "true",
        "ROUTER_LOG_PATH": "/logs/decisions.jsonl",
        "CLASSIFIER_BACKEND": classifier_backend,
    }
    if classifier_backend == "local":
        env["LOCAL_CLASSIFIER_URL"] = os.environ.get(
            "LOCAL_CLASSIFIER_URL", "http://local-classifier:8080"
        )
    # Stop any running stack first
    subprocess.run(_compose_cmd("down", "--remove-orphans"), check=False, capture_output=True)
    subprocess.run(_compose_cmd("up", "-d", "--build"), env=env, check=True, capture_output=True)
    print(f"  started proxy mode={mode} level={level} classifier={classifier_backend}", flush=True)


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


def _row(mode: str, level: str, history_mode: str, tr: TurnResult) -> dict:
    return {
        "mode": mode,
        "level": level,
        "history_mode": history_mode,
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
    classifier_backend = os.environ.get("CLASSIFIER_BACKEND", "none")
    # Local classifier may need to download the model on first run (~180 MB).
    health_timeout = 300.0 if classifier_backend == "local" else 120.0
    n_history_runs = sum(len(HISTORY_MODES[m]) for m, _ in CONFIGS)
    print(f"Loaded {len(corpus)} scenarios, {n_seeds} seeds, {len(CONFIGS)} proxy configs")
    print(f"History modes per config: stateless={HISTORY_MODES['stateless']}, session={HISTORY_MODES['session']}")
    print(f"Classifier backend: {classifier_backend}")
    print(f"Total runs: {len(corpus) * n_seeds * n_history_runs}\n")

    with RESULTS_CSV.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for mode, level in CONFIGS:
            history_modes = HISTORY_MODES[mode]
            print(f"[{mode}/{level}] starting (history={history_modes}) ...", flush=True)

            if not dry_run:
                clear_log()  # clear BEFORE container starts so it opens from byte 0
                start_proxy(mode, level)
                wait_healthy(health_timeout)
                time.sleep(2)  # grace period — proxy is healthy but hook may still be loading

            for history_mode in history_modes:
                for scenario in corpus:
                    for seed in range(n_seeds):
                        label = f"  [{history_mode}] {scenario.id} seed={seed}"
                        if dry_run:
                            print(f"{label} [dry-run]")
                            continue

                        try:
                            results = replay_scenario(scenario, seed=seed, history_mode=history_mode)
                            for tr in results:
                                writer.writerow(_row(mode, level, history_mode, tr))
                            fh.flush()
                            actions = [tr.action for tr in results]
                            print(f"{label} -> {actions}")
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
