"""Read actual gateway decisions for one demo session, without exposing AWS credentials.

CloudWatch access belongs to the UI server, not to the browser or
the model. Missing permissions and delayed ingestion are visible states, never
substitutes for an allow/block decision.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class DecisionBatch:
    source: str
    status: str = "waiting"
    message: str = "Waiting for gateway decisions."
    records: list[dict] = field(default_factory=list)


def source_name() -> str:
    source = os.environ.get("DEMO_DECISION_SOURCE", "auto").lower()
    if source != "auto":
        return source
    if os.environ.get("DEMO_REMOTE") == "1" or os.environ.get("DEMO_CLOUDWATCH_LOG_GROUP"):
        return "cloudwatch"
    host = urlsplit(os.environ.get("PROXY_URL_SESSION", "http://localhost:4000")).hostname
    return "docker" if host in {"localhost", "127.0.0.1", "::1"} else "cloudwatch"


def decision_key(record: dict) -> str:
    return json.dumps(
        [record.get(k) for k in ("agent", "session_id", "request_id", "phase", "ts", "action")]
    )


def parse_record(value: str | dict, ref: str, agent: str, mode: str) -> dict | None:
    """Accept only the requested session/agent/mode and known audit fields."""
    try:
        record = json.loads(value) if isinstance(value, str) else value
    except (ValueError, TypeError):
        return None
    if not isinstance(record, dict):
        return None
    if record.get("session_id") != ref or (agent and record.get("agent") != agent):
        return None
    if record.get("mode") not in {None, mode}:
        return None
    if not isinstance(record.get("action"), str) or record.get("phase") not in {
        "pre_call",
        "post_call",
        "approval",
    }:
        return None
    fields = (
        "ts",
        "phase",
        "session_id",
        "agent",
        "request_id",
        "mode",
        "level",
        "controls",
        "features",
        "risk_score",
        "risk_level",
        "data_class",
        "data_class_rules",
        "route",
        "action",
        "matched_rules",
        "enforce",
        "latency_ms",
        "tool_context",
    )
    return {key: record[key] for key in fields if key in record}


def read_decisions(
    ref: str,
    *,
    agent: str = "",
    mode: str = "session",
    container: str = "deploy-litellm-1",
    since_ms: int = 0,
) -> DecisionBatch:
    source = source_name()
    batch = DecisionBatch(source)
    if source not in {"docker", "cloudwatch"}:
        batch.status, batch.message = "error", "Unknown decision source; use docker or cloudwatch."
        return batch
    try:
        if source == "docker":
            result = subprocess.run(
                ["docker", "logs", "--tail", "2000", container],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=5,
            )
            if result.returncode:
                batch.status, batch.message = "error", "Cannot read local proxy logs. Check Docker."
                return batch
            values = (result.stdout + "\n" + result.stderr).splitlines()
        else:
            values = []
            # JSON quoting makes the filter literal; ref is a server-derived fingerprint.
            pattern = "{ $.session_id = " + json.dumps(ref)
            if agent:
                pattern += " && $.agent = " + json.dumps(agent)
            pattern += " }"
            base = [
                "aws",
                "logs",
                "filter-log-events",
                "--output",
                "json",
                "--no-cli-pager",
                "--no-paginate",
                "--log-group-name",
                os.environ.get("DEMO_CLOUDWATCH_LOG_GROUP", "/ecs/securelitellm-dryrun"),
                "--filter-pattern",
                pattern,
                "--start-time",
                str(max(0, since_ms)),
            ]
            region = os.environ.get(
                "DEMO_CLOUDWATCH_REGION", os.environ.get("AWS_REGION", "us-east-1")
            )
            profile = os.environ.get("DEMO_CLOUDWATCH_PROFILE") or os.environ.get(
                "DRYRUN_AWS_PROFILE"
            )
            base += ["--region", region]
            if profile:
                base += ["--profile", profile]
            token = None
            seen_tokens = set()
            for _ in range(3):
                command = base + (["--next-token", token] if token else [])
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=5,
                    env={**os.environ, "AWS_PAGER": "", "AWS_CLI_AUTO_PROMPT": "off"},
                )
                if result.returncode:
                    # AWS stderr may include private configuration. Keep it off the web page.
                    batch.status, batch.message = (
                        "error",
                        (
                            "Cannot read CloudWatch. Check the UI server's AWS login, region and "
                            "logs:FilterLogEvents permission."
                        ),
                    )
                    return batch
                page = json.loads(result.stdout or "{}")
                if not isinstance(page, dict) or not isinstance(page.get("events", []), list):
                    raise ValueError("invalid CloudWatch response")
                values.extend(
                    e.get("message", "") for e in page.get("events", []) if isinstance(e, dict)
                )
                token = page.get("nextToken")
                if not token or token in seen_tokens:
                    break
                seen_tokens.add(token)
            else:
                batch.status, batch.message = (
                    "partial",
                    "Showing a partial log window; refresh to retry.",
                )
        records = {}
        for value in values:
            record = parse_record(value, ref, agent, mode)
            if record:
                records[decision_key(record)] = record
        batch.records = sorted(records.values(), key=lambda r: r.get("ts", ""))
        if batch.status != "partial":
            batch.status = "ready" if batch.records else "waiting"
            batch.message = (
                "Gateway decisions loaded for this session."
                if batch.records
                else "Waiting for this session's logs; CloudWatch delivery can take a few seconds."
                if source == "cloudwatch"
                else "No gateway decisions for this session yet."
            )
    except FileNotFoundError:
        batch.status, batch.message = (
            "error",
            (
                "AWS CLI is not installed on the UI server. Install it or load a recorded log."
                if source == "cloudwatch"
                else "Docker is not available on the UI server."
            ),
        )
    except subprocess.TimeoutExpired:
        batch.status, batch.message = "error", "Decision source timed out. Refresh to retry."
    except (OSError, ValueError, TypeError):
        batch.status, batch.message = "error", "Could not read gateway decisions. Refresh to retry."
    return batch
