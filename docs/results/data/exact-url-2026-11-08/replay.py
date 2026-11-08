"""Replay existing corpus directories against an isolated local mock-model proxy.

Run from the repository root. Does not execute model-generated tools.
Prepare the proxy/configuration as described in ../../exact-url-matching.md.
"""

import argparse
import csv
import hashlib
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--decision-log", type=Path, required=True)
    parser.add_argument("--suite", action="append", required=True, help="NAME=SCENARIO_DIRECTORY")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if urlsplit(args.proxy).hostname not in ("localhost", "127.0.0.1", "::1"):
        parser.error("only an isolated local proxy may receive these fixtures")
    if args.output.exists():
        parser.error("choose a new output; existing evidence is never overwritten")
    os.environ["HARNESS_MODEL"] = "mock"
    os.environ["LITELLM_MASTER_KEY"] = "sk-exact218-eval-only"
    from harness import decisions, runner

    runner.PROXY_URL = args.proxy
    runner.DEFAULT_MODEL = "mock"
    runner.LITELLM_MASTER_KEY = "sk-exact218-eval-only"
    decisions.DECISIONS_LOG = args.decision_log
    # An old mock image can return ordinary text for every scripted reply.
    # That is not evidence of prevention: prove generation works before scoring.
    canary = {
        "id": "canary",
        "type": "function",
        "function": {"name": "get_fixture", "arguments": '{"id":"synthetic"}'},
    }
    ok, _, _, response = runner._post_turn(
        [{"role": "user", "content": "Read the synthetic fixture."}],
        extra={
            "mock_reply": {"tool_calls": [canary]},
            "tools": [
                {
                    "type": "function",
                    "function": {"name": "get_fixture", "parameters": {"type": "object"}},
                }
            ],
        },
    )
    if not ok or not response or response["choices"][0]["message"].get("tool_calls") != [canary]:
        raise RuntimeError("scripted mock generation canary failed; no result is scored")
    rows = []
    inputs = {}
    for suite in args.suite:
        name, directory = suite.split("=", 1)
        files = sorted(Path(directory).glob("*.yaml"))
        if not files:
            raise ValueError("empty suite")
        inputs[name] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        for index, path in enumerate(files, 1):
            results = runner.replay_scenario(runner.load_scenario(path), seed=0)
            rows.extend(dict(suite=name, **asdict(result)) for result in results)
            print(f"{name}: {index}/{len(files)}", flush=True)
    with args.output.open("x", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    unknown = sum(r["action"] == "unknown" for r in rows)
    failures = sum(not r["proxy_ok"] for r in rows)
    manifest = dict(
        model="mock",
        mode="session",
        level="L3",
        seed=0,
        controls="classifier=on,allowlist=on,user_named=on",
        external_tools_executed=False,
        scripted_reply_canary=True,
        rows=len(rows),
        unknown_decisions=unknown,
        proxy_http_failures=failures,
        input_files=inputs,
        output_sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
    )
    args.output.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    if unknown or failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
