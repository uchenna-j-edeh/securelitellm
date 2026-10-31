"""Small live-model probe for #199; fixed histories, real generated sink calls.

Runs the actual RouterHook in process, with real DeBERTa classification and a
real Groq completion for the final turn. Earlier turns establish session taint
without model inference. It does not run a proxy or execute any returned tool.
This is a constrained policy-hook probe, not an autonomous-agent success rate.
Model non-generation and infrastructure failures are separate from prevention.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from demo.tools import TOOL_SCHEMAS  # noqa: E402
from harness.runner import _messages_to_api, load_scenario  # noqa: E402
from scripts.setup_demo import parse_env  # noqa: E402

DEFAULT_CASES = ("sc-054", "sc-055", "sc-056", "bn-048", "bn-049")
CONDITIONS = {"baseline": "classifier=on,allowlist=off", "winner": "classifier=on,allowlist=on"}
MODEL = "openai/gpt-oss-120b"


class Records:
    def __init__(self):
        self.rows = []

    def emit(self, record):
        self.rows.append(copy.deepcopy(record))

    def close(self):
        pass


def classifier_failed(rows: list[dict]) -> bool:
    return any(
        row.get("features", {}).get("classifier_error")
        or any(
            v.get("model", "").startswith("error:")
            for v in row.get("features", {}).get("classifier_verdicts", [])
        )
        for row in rows
    )


async def groq_completion(data: dict, *, seed: int, model: str) -> tuple[dict, dict]:
    """Send only the synthetic public corpus to Groq. No tool is ever executed."""
    payload = {key: data[key] for key in ("messages", "tools", "tool_choice") if key in data}
    payload.update(model=model, seed=seed, temperature=0.7, max_completion_tokens=1024)
    async with httpx.AsyncClient(timeout=60) as client:
        for attempt in range(3):
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {os.environ['GROQ_API_KEY']}"},
                json=payload,
            )
            if response.status_code != 429 or attempt == 2:
                break
            try:
                delay = float(response.headers.get("retry-after", "10"))
            except ValueError:
                delay = 10
            await asyncio.sleep(min(30, max(1, delay)))
    if response.status_code != 200:
        if response.status_code == 400:
            try:
                code = response.json().get("error", {}).get("code")
            except ValueError:
                code = None
            if code == "tool_use_failed":
                raise RuntimeError("provider_tool_rejection")
        # Do not write provider response bodies, request headers or credentials.
        raise RuntimeError(f"provider_http_{response.status_code}")
    body = response.json()
    return body, {key: body.get(key) for key in ("model", "system_fingerprint", "usage")}


async def probe(scenario, hook, store, *, seed: int, model: str, complete=groq_completion) -> dict:
    from litellm import ModelResponse
    from litellm.exceptions import BadRequestError

    from router.session import session_ref

    owner = SimpleNamespace(token="live-probe-owner")
    raw = store.issue(owner.token)
    records = Records()
    hook.decision_logger.close()
    hook.decision_logger = records
    result = {
        "scenario_id": scenario.id,
        "label": scenario.label,
        "seed": seed,
        "outcome": "error",
        "model_called": False,
        "generated_calls": [],
        "decisions": [],
    }
    for index, turn in enumerate(scenario.turns):
        data = {
            "model": "gpt",
            "messages": _messages_to_api(turn.messages),
            "litellm_call_id": f"probe-{scenario.id}-{seed}-{index}-{session_ref(raw)}",
            "metadata": {"headers": {"x-agent-run-id": raw}},
        }
        if index == len(scenario.turns) - 1:
            names = {tc.function.name for tc in turn.scripted_tool_calls}
            data["tools"] = [
                copy.deepcopy(t) for t in TOOL_SCHEMAS if t["function"]["name"] in names
            ]
            if not data["tools"]:
                raise ValueError(
                    "Live probes require a generated-sink scenario with a demo tool schema"
                )
            data["tool_choice"] = "auto"
        try:
            data = await hook.async_pre_call_hook(owner, None, data, "completion")
        except BadRequestError:
            result["outcome"] = "blocked"
            break
        if classifier_failed(records.rows):
            result["outcome"] = "classifier_error"
            break
        stamp = data.get("metadata", {}).get("securelitellm_route", {})
        if stamp.get("data_class") == "sensitive":
            # Never send sensitive-classified context to the hosted probe model.
            result["outcome"] = "sensitive_route_unavailable"
            break
        if index != len(scenario.turns) - 1:
            continue
        if not data.get("tools") or data.get("tool_choice") == "none":
            result["outcome"] = "tools_removed"
            break
        try:
            result["model_called"] = True
            body, provenance = await complete(data, seed=seed, model=model)
            result["provider"] = provenance
            response = ModelResponse(**body)
            calls = response.choices[0].message.tool_calls or []
            result["generated_calls"] = [tc.function.name for tc in calls]
            if not calls:
                result["outcome"] = "model_no_tool_call"
                break
            try:
                changed = await hook.async_post_call_success_hook(owner, data, response)
            except BadRequestError:
                result["outcome"] = "blocked"
                break
            released = changed if changed is not None else response
            result["outcome"] = "released" if released.choices[0].message.tool_calls else "held"
        except Exception as exc:
            result["outcome"] = "provider_error"
            result["error_type"] = type(exc).__name__
            if str(exc) == "provider_tool_rejection":
                result["outcome"] = "provider_tool_rejection"
            if str(exc).startswith("provider_http_"):
                result["error_type"] = str(exc)
    result["decisions"] = [
        {
            key: row.get(key)
            for key in (
                "phase",
                "action",
                "risk_level",
                "data_class",
                "route",
                "matched_rules",
                "controls",
            )
        }
        for row in records.rows
    ]
    if classifier_failed(records.rows):
        result["outcome"] = "classifier_error"
    return result


def summarize(rows: list[dict]) -> dict:
    summary = {}
    for condition in CONDITIONS:
        selected = [row for row in rows if row["condition"] == condition]
        summary[condition] = {
            label: dict(Counter(row["outcome"] for row in selected if row["label"] == label))
            for label in ("attack", "benign")
        }
    return summary


async def run(args) -> int:
    for key, value in parse_env(args.env_file).items():
        os.environ.setdefault(key, value)
    if not os.environ.get("GROQ_API_KEY"):
        raise ValueError("GROQ_API_KEY is required")
    os.environ.update(
        ROUTER_MODE="session",
        ROUTER_LEVEL="L3",
        ROUTER_ENFORCE="true",
        CLASSIFIER_BACKEND="local",
        LOCAL_CLASSIFIER_URL=args.classifier_url,
        ROUTER_LOG_PATH=os.devnull,
        ROUTER_LITELLM_CONFIG=str(ROOT / "deploy/litellm_config.yaml"),
    )
    # This adapter measures hook controls; public tiers use the same real model.
    # Sensitive routes are rejected above, and no tools run outside the process.
    import router.session as sessions
    from router.hook import RouterHook

    cases = [load_scenario(ROOT / "corpus/scenarios" / f"{sid}.yaml") for sid in args.scenarios]
    if args.output.exists():
        raise ValueError("Output already exists; choose a new run file")
    rows = []
    failures = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    provenance = {
        "kind": "live_hook_probe",
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "policy_sha256": hashlib.sha256((ROOT / "deploy/policy.yaml").read_bytes()).hexdigest(),
        "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "dirty_worktree": bool(
            subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()
        ),
        "corpus_sha256": {
            sid: hashlib.sha256(
                (ROOT / "corpus/scenarios" / f"{sid}.yaml").read_bytes()
            ).hexdigest()
            for sid in args.scenarios
        },
        "model": args.model,
        "seeds": args.seeds,
        "classifier_url": args.classifier_url,
        "limitations": "Fixed source histories; earlier turns populate taint without inference; final completion uses a real model with constrained sink tools. Public tiers share that model. Sensitive routes are not sent. No proxy transport or real tool execution is tested. Repeated seeds are clustered by scenario, not independent samples.",
    }
    with args.output.open("x") as handle:
        handle.write(json.dumps({"provenance": provenance}) + "\n")
        for condition, controls in CONDITIONS.items():
            os.environ["ROUTER_CONTROLS"] = controls
            sessions._store = sessions.SessionStore()
            hook = RouterHook()
            for case in cases:
                for seed in range(args.seeds):
                    row = await probe(case, hook, sessions._store, seed=seed, model=args.model)
                    row["condition"] = condition
                    rows.append(row)
                    handle.write(json.dumps(row) + "\n")
                    handle.flush()
                    print(f"{condition} {case.id} seed={seed}: {row['outcome']}", flush=True)
                    failures |= row["outcome"] in {
                        "error",
                        "provider_error",
                        "classifier_error",
                        "sensitive_route_unavailable",
                    }
            hook.decision_logger.close()
        handle.write(json.dumps({"summary": summarize(rows)}) + "\n")
    print(json.dumps(summarize(rows), indent=2))
    return int(failures)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=ROOT / "deploy/.env")
    parser.add_argument("--classifier-url", default="http://localhost:8080")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--scenarios", nargs="+", default=list(DEFAULT_CASES))
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--output", type=Path, default=ROOT / "eval/results/live-probe.jsonl")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.seeds < 1:
        parser.error("--seeds must be positive")
    for sid in args.scenarios:
        if sid not in {path.stem for path in (ROOT / "corpus/scenarios").glob("*.yaml")}:
            parser.error(f"Unknown scenario: {sid}")
    if args.dry_run:
        print(
            f"Live hook probe: {len(args.scenarios)} scenarios × 2 conditions × {args.seeds} seeds; at most {len(args.scenarios) * 2 * args.seeds} completions. No tools execute."
        )
        return 0
    try:
        return asyncio.run(run(args))
    except (OSError, ValueError) as exc:
        print(
            f"Cannot run live probe ({type(exc).__name__}); check configuration and output path.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
