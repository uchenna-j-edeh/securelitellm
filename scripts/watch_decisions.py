#!/usr/bin/env python3
"""Stream SecureLiteLLM decisions as one short line each.

    uv run python scripts/watch_decisions.py                 # CloudWatch, live
    uv run python scripts/watch_decisions.py --since 1h      # start further back
    uv run python scripts/watch_decisions.py --file demo/logs/decisions.jsonl
    docker logs -f <proxy> | uv run python scripts/watch_decisions.py --file -

Each line: time, agent, phase, classifier verdict, action, tool calls. Approved
approvals are green, denied ones red (on a terminal; --color always forces it, NO_COLOR or --no-color turns it off).

CloudWatch is polled with `aws logs filter-log-events` rather than followed with
`aws logs tail`, whose output stalls when piped. Needs the AWS CLI and a profile
that can read the log group (`--profile`, or AWS_PROFILE).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import deque
from datetime import datetime
from typing import Any, Iterable, Iterator

GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"
COLORS = {"approved": GREEN, "denied": RED}
COLUMNS = ("TIME", "AGENT", "PHASE", "CLASSIFIER", "ACTION", "TOOL CALLS")
WIDTHS = (8, 18, 9, 10, 32)


def classifier_verdict(record: dict[str, Any]) -> str:
    features = record.get("features") or {}
    if features.get("classifier_injection"):
        return "injection"
    if features.get("classifier_error"):
        return "error"
    if features.get("classifier_verdicts"):
        return "clean"
    return "-"


def tool_calls(record: dict[str, Any], seen: dict[str, set] | None = None) -> str:
    """Tool calls first seen in this record.

    post_call: the calls the model just asked for. The proxy writes one only
    when a call can send data out (send_email, fetch_url, ...); a response
    with read-only calls (read_file, web_search, ...) is not logged.
    pre_call: the request carries every call made so far in the conversation,
    so the read-only calls show up here, on the next step. With `seen` (call
    ids per session) only calls not shown before are listed; without it,
    pre_call shows none, since the whole history would repeat on every line.
    """
    phase = record.get("phase")
    context = record.get("tool_context") or {}
    if phase == "post_call":
        calls = context.get("generated_tool_calls") or []
    elif phase == "pre_call" and seen is not None:
        calls = context.get("tool_calls") or []
    else:
        return "-"
    calls = [call for call in calls if isinstance(call, dict)]
    if seen is not None:
        known = seen.setdefault(str(record.get("session_id")), set())
        fresh = [call for call in calls if not call.get("id") or call["id"] not in known]
        known.update(call["id"] for call in calls if call.get("id"))
        if phase == "pre_call":  # post_call always lists its calls (a held call runs later)
            calls = fresh
    return ", ".join(call.get("name") or "?" for call in calls) or "-"


def clock(ts: Any) -> str:
    if not isinstance(ts, str):
        return "-"
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone().strftime("%H:%M:%S")
    except ValueError:
        return ts[:8]


def format_record(record: dict[str, Any], color: bool, seen: dict[str, set] | None = None) -> str:
    action = str(record.get("action") or "-")
    phase = str(record.get("phase") or "-")
    if phase == "approval" and record.get("approval_ref"):
        action_text = f"{action} {record['approval_ref']}"
    else:
        action_text = action
    cells = (
        clock(record.get("ts")),
        str(record.get("agent") or "-"),
        phase,
        classifier_verdict(record),
        action_text,
    )
    line = "  ".join(cell.ljust(width) for cell, width in zip(cells, WIDTHS))
    line = f"{line}  {tool_calls(record, seen)}".rstrip()
    if color and action in COLORS:
        return f"{COLORS[action]}{line}{RESET}"
    return line


def header() -> str:
    return "  ".join(name.ljust(width) for name, width in zip(COLUMNS, WIDTHS)) + "  " + COLUMNS[-1]


def parse_record(text: str) -> dict[str, Any] | None:
    """A decision record from one log line, or None for anything else."""
    start = text.find("{")
    if start < 0:
        return None
    try:
        record = json.loads(text[start:])
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict) or "phase" not in record or "action" not in record:
        return None
    return record


# --- sources -----------------------------------------------------------------


def follow_file(path: str, poll: float) -> Iterator[str]:
    if path == "-":
        yield from sys.stdin
        return
    with open(path, encoding="utf-8") as handle:
        while True:
            line = handle.readline()
            if line:
                yield line
            else:
                time.sleep(poll)


def since_ms(since: str, now: float | None = None) -> int:
    match = re.fullmatch(r"(\d+)([smhd])", since)
    if not match:
        raise argparse.ArgumentTypeError(f"--since must look like 30s, 5m, 2h or 1d, not {since!r}")
    seconds = int(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]
    return int(((now if now is not None else time.time()) - seconds) * 1000)


def poll_cloudwatch(args: argparse.Namespace) -> Iterator[str]:
    start = since_ms(args.since)
    seen: deque[str] = deque(maxlen=5000)
    seen_set: set[str] = set()
    base = [
        "aws",
        "logs",
        "filter-log-events",
        "--output",
        "json",
        "--log-group-name",
        args.log_group,
    ]
    base += ["--filter-pattern", '"phase"', "--log-stream-name-prefix", args.stream_prefix]
    if args.region:
        base += ["--region", args.region]
    if args.profile:
        base += ["--profile", args.profile]
    while True:
        token = None
        newest = start
        while True:
            command = (
                base + ["--start-time", str(start)] + (["--next-token", token] if token else [])
            )
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"aws: {result.stderr.strip()}", file=sys.stderr)
                break
            page = json.loads(result.stdout or "{}")
            for event in sorted(page.get("events", []), key=lambda e: e.get("timestamp", 0)):
                event_id = event.get("eventId", "")
                if event_id in seen_set:
                    continue
                if len(seen) == seen.maxlen:
                    seen_set.discard(seen[0])
                seen.append(event_id)
                seen_set.add(event_id)
                newest = max(newest, event.get("timestamp", newest))
                yield event.get("message", "")
            token = page.get("nextToken")
            if not token:
                break
        # Re-read from the newest timestamp seen: CloudWatch can deliver late
        # events with the same timestamp; the event-id set drops the repeats.
        start = newest
        time.sleep(args.interval)


def run(lines: Iterable[str], color: bool, out=sys.stdout) -> None:
    seen: dict[str, set] = {}  # tool-call ids already shown, per session
    for line in lines:
        record = parse_record(line)
        if record is not None:
            print(format_record(record, color, seen), file=out, flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--log-group", default=os.getenv("WATCH_LOG_GROUP", "/ecs/securelitellm-dryrun")
    )
    parser.add_argument(
        "--stream-prefix", default="proxy", help="log stream prefix (default: proxy)"
    )
    parser.add_argument("--region", default=os.getenv("AWS_REGION", "us-east-1"))
    parser.add_argument("--profile", default=os.getenv("DRYRUN_AWS_PROFILE"))
    parser.add_argument("--since", default="5m", help="how far back to start: 30s, 5m, 2h, 1d")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between polls")
    parser.add_argument(
        "--file", help="follow a local decisions JSONL file instead ('-' for stdin)"
    )
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="auto: only on a terminal (default); always: also when piped or captured",
    )
    parser.add_argument("--no-color", action="store_const", const="never", dest="color")
    args = parser.parse_args(argv)
    since_ms(args.since)  # validate early
    if args.color == "auto":
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    else:
        color = args.color == "always"

    source = follow_file(args.file, args.interval) if args.file else poll_cloudwatch(args)
    where = args.file or f"{args.log_group} (since {args.since})"
    print(f"watching {where}  Ctrl-C to stop", file=sys.stderr)
    print(header())
    try:
        run(source, color)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
