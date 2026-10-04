"""Reproducibility snapshot — issue #47.

Computes SHA-256 of every scenario file → corpus/CORPUS_HASH.txt
Captures env snapshot → eval/results/env_snapshot.txt
Tags the repo v1.0-eval when --tag is passed.

Usage:
    uv run python harness/freeze.py [--tag]
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCENARIOS_DIR = REPO_ROOT / "corpus" / "scenarios"
CORPUS_HASH_FILE = REPO_ROOT / "corpus" / "CORPUS_HASH.txt"
ENV_SNAPSHOT = REPO_ROOT / "eval" / "results" / "env_snapshot.txt"


def hash_corpus() -> str:
    lines = []
    for path in sorted(SCENARIOS_DIR.glob("*.yaml")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    return "\n".join(lines) + "\n"


def capture_env() -> str:
    parts = []
    try:
        pip = subprocess.check_output(["uv", "pip", "freeze"], text=True)
        parts.append("=== uv pip freeze ===\n" + pip)
    except Exception as exc:
        parts.append(f"=== uv pip freeze FAILED: {exc} ===\n")

    try:
        digest = subprocess.check_output(
            ["docker", "inspect", "--format={{index .RepoDigests 0}}", "ghcr.io/berriai/litellm"],
            text=True,
        ).strip()
        parts.append(f"=== LiteLLM image digest ===\n{digest}\n")
    except Exception:
        parts.append("=== LiteLLM image digest: unavailable ===\n")

    try:
        git_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        parts.append(f"=== git HEAD ===\n{git_hash}\n")
    except Exception:
        pass

    return "\n".join(parts)


def create_tag(tag: str = "v1.0-eval") -> None:
    existing = subprocess.run(
        ["git", "tag", "-l", tag], capture_output=True, text=True
    ).stdout.strip()
    if existing:
        print(f"Tag {tag} already exists — skipping")
        return
    subprocess.run(["git", "tag", "-a", tag, "-m", f"Corpus freeze: {tag}"], check=True)
    print(f"Created tag {tag}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", action="store_true", help="create git tag v1.0-eval")
    args = parser.parse_args()

    corpus_hash = hash_corpus()
    CORPUS_HASH_FILE.write_text(corpus_hash)
    print(f"Corpus hash written to {CORPUS_HASH_FILE}")
    print(corpus_hash)

    ENV_SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    env_snap = capture_env()
    ENV_SNAPSHOT.write_text(env_snap)
    print(f"Env snapshot written to {ENV_SNAPSHOT}")

    if args.tag:
        create_tag()
    else:
        print("Pass --tag to create v1.0-eval git tag")
