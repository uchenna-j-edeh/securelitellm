"""Per-agent-run session store: proxy-issued session ids, idle expiry, taint state.

Session ids (#145, #146)
------------------------
Session ids are issued by the proxy, never chosen by the client (NIST SP
800-63B session management; OWASP Session Management Cheat Sheet):

- ``issue(owner)`` generates the id with ``secrets.token_urlsafe(32)`` —
  256 bits from the OS CSPRNG (NIST/OWASP minimum: 64 bits).
- The raw id is returned to the client once (x-agent-run-id response header)
  and never stored: the store is keyed by ``session_key(id)`` = SHA-256(id).
  Logs carry ``session_ref`` — a 16-hex-char prefix of that key.
- Each session is bound to its owner (the caller's hashed API key); a request
  presenting the id from a different key is rejected.
- An id the store does not know — never issued, forged, or lost on restart —
  is rejected (SessionUnknown). It is never silently recreated.

Expiry (#147)
-------------
A session expires when it has not been used for longer than ``idle_ttl``,
tainted or not. Every request resets the clock (``last_seen_at``). Expired
sessions are reaped: removed from memory and replaced by a small tombstone
(expiry time, reason). A request that reuses an expired id raises
SessionExpired. Tombstones are purged after ``tombstone_ttl``; after that the
id is simply unknown.

Reaping happens lazily on access and in a periodic sweep over all sessions,
so abandoned sessions do not accumulate.

Environment
-----------
SESSION_IDLE_TTL_SECONDS       idle timeout      (default 1800 = 30 min)
SESSION_TOMBSTONE_TTL_SECONDS  tombstone memory  (default 86400 = 24 h)
"""

import hashlib
import os
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

DEFAULT_IDLE_TTL = 1800  # 30 minutes — NIST 800-63B AAL2 allows up to 1 h
DEFAULT_TOMBSTONE_TTL = 86400  # 24 hours
SWEEP_INTERVAL = 60.0  # seconds between full sweeps

SESSION_ID_BYTES = 32  # 256 bits of entropy
# token_urlsafe(32) is always 43 chars of the URL-safe base64 alphabet.
SESSION_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
SESSION_REF_LENGTH = 16

Clock = Callable[[], float]


def session_key(session_id: str) -> str:
    """Store key for a raw session id: hex SHA-256. The raw id is never stored."""
    return hashlib.sha256(session_id.encode()).hexdigest()


def session_ref(session_id: str) -> str:
    """Short, non-secret fingerprint of a raw session id for logs and UIs."""
    return session_key(session_id)[:SESSION_REF_LENGTH]


def is_well_formed(session_id: str) -> bool:
    """True if the string has the exact shape of an id this proxy issues."""
    return SESSION_ID_PATTERN.fullmatch(session_id) is not None


class SessionError(Exception):
    """A request presented session metadata that violates the session contract."""

    reason = "invalid"

    def __init__(self, key: str, message: str) -> None:
        self.key = key
        super().__init__(message)


class SessionUnknown(SessionError):
    """The id was never issued by this proxy (or was lost on restart)."""

    reason = "unknown"

    def __init__(self, key: str) -> None:
        super().__init__(key, "x-agent-run-id is not a session issued by this proxy")


class SessionExpired(SessionError):
    """The id belongs to an expired or ended session."""

    def __init__(self, key: str, reason: str) -> None:
        self.reason = reason  # "idle" | "ended"
        super().__init__(key, f"session expired ({reason}); start a new session")


class SessionOwnerMismatch(SessionError):
    """The id was issued to a different API key."""

    reason = "owner_mismatch"

    def __init__(self, key: str) -> None:
        super().__init__(key, "x-agent-run-id belongs to a different API key")


@dataclass
class SessionState:
    session_id: str  # session_key(raw id), never the raw id
    owner: str = ""
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
    """Session state keyed by session_key(raw id). All methods take the key."""

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

    def issue(self, owner: str = "") -> str:
        """Create a session and return its raw id. Only the key is retained."""
        while True:
            raw = secrets.token_urlsafe(SESSION_ID_BYTES)
            key = session_key(raw)
            with self._lock:
                if key in self._store or key in self._tombstones:
                    continue  # astronomically unlikely; never reuse a key
                now = self._clock()
                self._store[key] = SessionState(
                    session_id=key, owner=owner, created_at=now, last_seen_at=now
                )
                return raw

    def state(self, key: str) -> SessionState:
        """Return the live session state.

        Raises SessionUnknown, or SessionExpired for an expired or ended session.
        """
        with self._lock:
            return self._live_locked(key)

    def authorize(self, key: str, owner: str) -> SessionState:
        """Return the live session if *owner* is the API key it was issued to."""
        with self._lock:
            s = self._live_locked(key)
            if s.owner != owner:
                raise SessionOwnerMismatch(key)
            return s

    def record_source(self, key: str, source: dict[str, Any], *, taint: bool = True) -> None:
        """Record that a tool result entered the session context.

        taint=True  — content was flagged as injection; hash added to tainted_spans.
        taint=False — content is clean; tracked but does not poison the session.
                      Use this when a classifier has confirmed the content is safe.

        Raises SessionUnknown / SessionExpired like state().
        """
        with self._lock:
            s = self._live_locked(key)
            s.sources.append(source)
            if taint:
                s.tainted = True
                content_hash = source.get("content_hash")
                if not content_hash:
                    raw = str(source.get("content") or source.get("content_for_classifier", ""))
                    content_hash = hashlib.sha256(raw.encode()).hexdigest()
                s.tainted_spans.append(str(content_hash))

    def record_sink(self, key: str, sink: dict[str, Any]) -> None:
        """Record an egress-capable tool call observed after taint."""
        with self._lock:
            s = self._store.get(key)
            if s is not None:
                s.sinks.append(sink)

    def record_escalation(self, key: str) -> int:
        """Increment escalation counter and return new count."""
        with self._lock:
            s = self._store.get(key)
            if s is not None:
                s.escalation_count += 1
                return s.escalation_count
        return 0

    def expire(self, key: str, reason: str = "ended") -> None:
        """End a session now; its id is rejected until the tombstone is purged."""
        with self._lock:
            self._reap_locked(key, reason, self._clock())

    def sweep(self) -> None:
        """Reap every expired session and purge old tombstones."""
        with self._lock:
            self._sweep_locked(self._clock())

    # -- internals (caller holds self._lock) ---------------------------------

    def _live_locked(self, key: str) -> SessionState:
        now = self._clock()
        if now - self._last_sweep >= SWEEP_INTERVAL:
            self._sweep_locked(now)

        tomb = self._tombstones.get(key)
        if tomb is not None:
            if now - tomb.expired_at <= self._tombstone_ttl:
                raise SessionExpired(key, tomb.reason)
            del self._tombstones[key]

        s = self._store.get(key)
        if s is None:
            raise SessionUnknown(key)
        if self._is_idle(s, now):
            self._reap_locked(key, "idle", now)
            raise SessionExpired(key, "idle")
        s.last_seen_at = now
        return s

    def _is_idle(self, s: SessionState, now: float) -> bool:
        return now - s.last_seen_at > self._idle_ttl

    def _reap_locked(self, key: str, reason: str, now: float) -> None:
        self._store.pop(key, None)
        self._tombstones[key] = _Tombstone(expired_at=now, reason=reason)

    def _sweep_locked(self, now: float) -> None:
        self._last_sweep = now
        for key, s in list(self._store.items()):
            if self._is_idle(s, now):
                self._reap_locked(key, "idle", now)
        for key, tomb in list(self._tombstones.items()):
            if now - tomb.expired_at > self._tombstone_ttl:
                del self._tombstones[key]


# Module-level singleton shared across all hook instances in the same process.
_store = SessionStore.from_env()


def get_store() -> SessionStore:
    return _store
