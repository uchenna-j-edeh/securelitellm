"""Per-agent-run session store with idle and absolute expiry.

Two concurrent runs never share state. The store is keyed by session_id
(derived from the x-agent-run-id header or a per-request fallback).

Expiry (#147)
-------------
A session expires when it has not been used for longer than ``idle_ttl``,
tainted or not. Every request resets the clock (``last_seen_at``). Expired sessions are reaped: removed from
memory and replaced by a small tombstone (id, expiry time, reason). A request
that reuses an expired id raises SessionExpired instead of silently getting a
fresh, untainted session — the client must start a new run. Tombstones are
purged after ``tombstone_ttl``.

Reaping happens lazily on access and in a periodic sweep over all sessions,
so abandoned sessions do not accumulate.

Environment
-----------
SESSION_IDLE_TTL_SECONDS       idle timeout      (default 1800 = 30 min)
SESSION_TOMBSTONE_TTL_SECONDS  tombstone memory  (default 86400 = 24 h)
"""

import hashlib
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

DEFAULT_IDLE_TTL = 1800  # 30 minutes — NIST 800-63B AAL2 allows up to 1 h
DEFAULT_TOMBSTONE_TTL = 86400  # 24 hours
SWEEP_INTERVAL = 60.0  # seconds between full sweeps

Clock = Callable[[], float]


class SessionExpired(Exception):
    """Raised when a request reuses the id of an expired or ended session."""

    def __init__(self, session_id: str, reason: str) -> None:
        self.session_id = session_id
        self.reason = reason  # "idle" | "ended"
        super().__init__(
            f"Session {session_id!r} expired ({reason}); start a new run with a new x-agent-run-id"
        )


@dataclass
class SessionState:
    session_id: str
    created_at: float = field(default_factory=time.monotonic)
    last_seen_at: float = field(default_factory=time.monotonic)
    sources: list[dict[str, Any]] = field(default_factory=list)
    sinks: list[dict[str, Any]] = field(default_factory=list)
    tainted: bool = False
    tainted_spans: list[str] = field(default_factory=list)  # SHA-256 of raw content
    escalation_count: int = 0  # times policy fired non-allow in this session


@dataclass
class _Tombstone:
    expired_at: float
    reason: str


def _env_seconds(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be a positive integer, got {raw!r}") from None
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer, got {raw!r}")
    return value


class SessionStore:
    def __init__(
        self,
        idle_ttl: float = DEFAULT_IDLE_TTL,
        tombstone_ttl: float = DEFAULT_TOMBSTONE_TTL,
        clock: Clock = time.monotonic,
    ) -> None:
        self._store: dict[str, SessionState] = {}
        self._tombstones: dict[str, _Tombstone] = {}
        self._lock = threading.Lock()
        self._idle_ttl = idle_ttl
        self._tombstone_ttl = tombstone_ttl
        self._clock = clock
        self._last_sweep = clock()

    @classmethod
    def from_env(cls) -> "SessionStore":
        return cls(
            idle_ttl=_env_seconds("SESSION_IDLE_TTL_SECONDS", DEFAULT_IDLE_TTL),
            tombstone_ttl=_env_seconds("SESSION_TOMBSTONE_TTL_SECONDS", DEFAULT_TOMBSTONE_TTL),
        )

    def state(self, session_id: str) -> SessionState:
        """Return the live session state, creating it if the id is new.

        Raises SessionExpired if the id belongs to an expired or ended session.
        """
        with self._lock:
            return self._live_locked(session_id)

    def record_source(self, session_id: str, source: dict[str, Any], *, taint: bool = True) -> None:
        """Record that a tool result entered the session context.

        taint=True  — content was flagged as injection; hash added to tainted_spans.
        taint=False — content is clean; tracked but does not poison the session.
                      Use this when a classifier has confirmed the content is safe.

        Raises SessionExpired if the id belongs to an expired or ended session.
        """
        with self._lock:
            s = self._live_locked(session_id)
            s.sources.append(source)
            if taint:
                s.tainted = True
                content_hash = source.get("content_hash")
                if not content_hash:
                    raw = str(source.get("content") or source.get("content_for_classifier", ""))
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

    def expire(self, session_id: str, reason: str = "ended") -> None:
        """End a session now; its id cannot be reused until the tombstone is purged."""
        with self._lock:
            self._reap_locked(session_id, reason, self._clock())

    def reopen(self, session_id: str) -> None:
        """Forget a tombstone so the id can start a fresh session (audit mode only)."""
        with self._lock:
            self._tombstones.pop(session_id, None)

    def sweep(self) -> None:
        """Reap every expired session and purge old tombstones."""
        with self._lock:
            self._sweep_locked(self._clock())

    # -- internals (caller holds self._lock) ---------------------------------

    def _live_locked(self, session_id: str) -> SessionState:
        now = self._clock()
        if now - self._last_sweep >= SWEEP_INTERVAL:
            self._sweep_locked(now)

        tomb = self._tombstones.get(session_id)
        if tomb is not None:
            if now - tomb.expired_at <= self._tombstone_ttl:
                raise SessionExpired(session_id, tomb.reason)
            del self._tombstones[session_id]

        s = self._store.get(session_id)
        if s is not None:
            if self._is_idle(s, now):
                self._reap_locked(session_id, "idle", now)
                raise SessionExpired(session_id, "idle")
            s.last_seen_at = now
            return s

        s = SessionState(session_id=session_id, created_at=now, last_seen_at=now)
        self._store[session_id] = s
        return s

    def _is_idle(self, s: SessionState, now: float) -> bool:
        return now - s.last_seen_at > self._idle_ttl

    def _reap_locked(self, session_id: str, reason: str, now: float) -> None:
        self._store.pop(session_id, None)
        self._tombstones[session_id] = _Tombstone(expired_at=now, reason=reason)

    def _sweep_locked(self, now: float) -> None:
        self._last_sweep = now
        for session_id, s in list(self._store.items()):
            if self._is_idle(s, now):
                self._reap_locked(session_id, "idle", now)
        for session_id, tomb in list(self._tombstones.items()):
            if now - tomb.expired_at > self._tombstone_ttl:
                del self._tombstones[session_id]


# Module-level singleton shared across all hook instances in the same process.
_store = SessionStore.from_env()


def get_store() -> SessionStore:
    return _store
