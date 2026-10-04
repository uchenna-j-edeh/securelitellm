"""Read structured decision records from the router's JSONL log file.

The log file is written by DecisionLogger when ROUTER_LOG_PATH is set to a
file path.  The matrix runner mounts harness/logs/ into the container and sets
ROUTER_LOG_PATH=/logs/decisions.jsonl before starting the stack.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

DECISIONS_LOG = Path(__file__).parent / "logs" / "decisions.jsonl"


def wait_for_decision(
    session_id: str,
    after_byte: int,
    timeout: float = 10.0,
    poll_interval: float = 0.05,
) -> dict | None:
    """Poll the log file for a new decision record matching session_id.

    Returns the first record found after *after_byte* offset, or None on timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not DECISIONS_LOG.exists():
            time.sleep(poll_interval)
            continue
        with DECISIONS_LOG.open() as fh:
            fh.seek(after_byte)
            for raw in fh:
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if record.get("session_id") == session_id:
                    return record
        time.sleep(poll_interval)
    return None


def current_log_size() -> int:
    """Return current byte size of the log file (0 if it doesn't exist)."""
    return DECISIONS_LOG.stat().st_size if DECISIONS_LOG.exists() else 0


def clear_log() -> None:
    """Truncate the log file between matrix runs."""
    if DECISIONS_LOG.exists():
        DECISIONS_LOG.write_text("")
