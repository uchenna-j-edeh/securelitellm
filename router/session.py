"""Per-agent-run session store with TTL.

Two concurrent runs never share state. The store is keyed by session_id
(derived from the x-agent-run-id header or a per-request fallback).
Expired sessions are evicted lazily on access.
"""

import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Any

DEFAULT_TTL = 1800  # 30 minutes


@dataclass
class SessionState:
    session_id: str
    created_at: float = field(default_factory=time.monotonic)
    sources: list[dict[str, Any]] = field(default_factory=list)
    sinks: list[dict[str, Any]] = field(default_factory=list)
    tainted: bool = False
    tainted_spans: list[str] = field(default_factory=list)  # SHA-256 of raw content
    escalation_count: int = 0  # times policy fired non-allow in this session


class SessionStore:
    def __init__(self, ttl_seconds: int = DEFAULT_TTL) -> None:
        self._store: dict[str, SessionState] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def state(self, session_id: str) -> SessionState:
        """Return the session state, creating a fresh one if absent or expired."""
        with self._lock:
            s = self._store.get(session_id)
            if s is None or self._is_expired(s):
                s = SessionState(session_id=session_id)
                self._store[session_id] = s
            return s

    def record_source(self, session_id: str, source: dict[str, Any], *, taint: bool = True) -> None:
        """Record that a tool result entered the session context.

        taint=True  — content was flagged as injection; hash added to tainted_spans.
        taint=False — content is clean; tracked but does not poison the session.
                      Use this when a classifier has confirmed the content is safe.
        """
        with self._lock:
            s = self._store.setdefault(session_id, SessionState(session_id=session_id))
            s.sources.append(source)
            if taint:
                s.tainted = True
                content_hash = source.get("content_hash")
                if not content_hash:
                    raw = str(source.get("content") or source.get("content_preview", ""))
                    content_hash = hashlib.sha256(raw.encode()).hexdigest()
                s.tainted_spans.append(str(content_hash))

    def record_sink(self, session_id: str, sink: dict[str, Any]) -> None:
        """Record an egress-capable tool call observed after taint."""
        with self._lock:
            s = self._store.get(session_id)
            if s is not None:
                s.sinks.append(sink)

    def record_escalation(self, session_id: str) -> int:
        """Increment escalation counter and return new count."""
        with self._lock:
            s = self._store.get(session_id)
            if s is not None:
                s.escalation_count += 1
                return s.escalation_count
        return 0

    def expire(self, session_id: str) -> None:
        with self._lock:
            self._store.pop(session_id, None)

    def _is_expired(self, s: SessionState) -> bool:
        return (time.monotonic() - s.created_at) > self._ttl


# Module-level singleton shared across all hook instances in the same process.
_store = SessionStore()


def get_store() -> SessionStore:
    return _store
