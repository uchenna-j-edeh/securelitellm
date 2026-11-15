"""Held-for-approval tool calls (#174).

With ``approvals: on`` a post-call hold no longer just drops the generated
tool calls. The whole assistant turn is stored here as a *pending approval*
and the agent is told its ID. An admin approves or denies it; after approval
the agent retries the same request with the ID, and the gateway replays the
stored calls instead of asking the model again, at most once.

Rules (from the design notes on #174)
-------------------------------------
- **The whole turn is the unit.** Every tool call in the held assistant
  message is stored with its original id and raw arguments, and is approved
  or denied together. Releasing part of a turn would leave tool call ids
  without results, which most providers reject.
- **Bound to who asked.** An approval is usable only from the session and the
  API key (agent) that produced it.
- **Once at most.** ``claim`` checks and marks the approval used in one step
  under the store's lock, so two concurrent retries can't both replay it.
  (A shared Postgres store, #169, needs a single conditional
  ``UPDATE ... RETURNING`` for the same guarantee, never a cached status.)
- **Expiry is not denial.** An approval nobody answered expires; it doesn't
  count against the agent. A denial does (see the hook).
- **Raw arguments live only here, and only while needed.** They are deleted
  once the approval is used, denied or expires, and never logged. Logs and
  the admin API identify an approval by ``approval_ref``, a prefix of the
  SHA-256 of its ID; only the agent ever holds the raw ID.

Environment
-----------
APPROVAL_TTL_SECONDS  how long an approval stays pending or approved
                      (default 900 = 15 min; must not exceed the session's
                      idle timeout, or an approved retry finds the session
                      already expired)
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

DEFAULT_APPROVAL_TTL = 900  # 15 minutes
RECORD_RETENTION = 3600.0  # decided/expired records, without arguments, kept for status lookups
APPROVAL_ID_BYTES = 32
APPROVAL_REF_LENGTH = 16

Status = Literal["pending", "approved", "denied", "used", "expired"]
Clock = Callable[[], float]


def approval_key(approval_id: str) -> str:
    return hashlib.sha256(approval_id.encode()).hexdigest()


def approval_ref(approval_id: str) -> str:
    return approval_key(approval_id)[:APPROVAL_REF_LENGTH]


def calls_hash(calls: list[dict[str, Any]]) -> str:
    """Hash of a turn's tool calls: ids, names and the raw argument strings as sent."""
    material = [
        [
            call.get("id"),
            (call.get("function") or {}).get("name"),
            (call.get("function") or {}).get("arguments"),
        ]
        for call in calls
    ]
    return hashlib.sha256(json.dumps(material, separators=(",", ":")).encode()).hexdigest()


@dataclass
class Approval:
    key: str
    session_key: str
    session_ref: str
    owner: str  # hashed API key the turn came from
    agent: str | None
    created_at: float
    expires_at: float
    summary: dict[str, Any]  # tools, destination labels, rules, risk: safe to log and show
    calls_hash: str
    calls: list[dict[str, Any]] | None  # raw tool calls; None once no longer needed
    content: str | None  # the assistant text that came with the calls
    status: Status = "pending"
    decided_at: float | None = None
    decided_by: str | None = None
    finished_at: float | None = None  # used, denied or expired
    replay_checked: bool = False

    @property
    def ref(self) -> str:
        return self.key[:APPROVAL_REF_LENGTH]

    def public(self, *, with_arguments: bool = False) -> dict[str, Any]:
        """The approval as an approver sees it. Raw arguments only on request."""
        view: dict[str, Any] = {
            "approval_ref": self.ref,
            "status": self.status,
            "agent": self.agent,
            "session_id": self.session_ref,
            "expires_in_seconds": None,
            **self.summary,
            "decided_by": self.decided_by,
        }
        if with_arguments and self.calls is not None:
            view["tool_calls"] = [
                {
                    "name": (call.get("function") or {}).get("name"),
                    "arguments": (call.get("function") or {}).get("arguments"),
                }
                for call in self.calls
            ]
        return view


@dataclass
class Claim:
    """Outcome of a retry presenting an approval ID."""

    ok: bool
    status: str  # the approval's status, or "unknown" / "mismatch"
    ref: str
    calls: list[dict[str, Any]] = field(default_factory=list)
    content: str | None = None
    session_ref: str | None = None
    agent: str | None = None


class ApprovalError(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        super().__init__(message)


class ApprovalStore:
    def __init__(self, ttl: float = DEFAULT_APPROVAL_TTL, clock: Clock = time.monotonic) -> None:
        self._records: dict[str, Approval] = {}
        self._unlogged_expiries: list[Approval] = []
        self._lock = threading.Lock()
        self._ttl = ttl
        self._clock = clock

    @property
    def ttl(self) -> float:
        return self._ttl

    def create(
        self,
        *,
        session_key: str,
        session_ref: str,
        owner: str,
        agent: str | None,
        calls: list[dict[str, Any]],
        content: str | None,
        summary: dict[str, Any],
    ) -> tuple[str, Approval]:
        """Store a held turn. Returns the raw ID (for the agent only) and the record."""
        if not calls:
            raise ValueError("an approval needs at least one tool call")
        raw = secrets.token_urlsafe(APPROVAL_ID_BYTES)
        now = self._clock()
        record = Approval(
            key=approval_key(raw),
            session_key=session_key,
            session_ref=session_ref,
            owner=owner,
            agent=agent,
            created_at=now,
            expires_at=now + self._ttl,
            summary=summary,
            calls_hash=calls_hash(calls),
            calls=[_copy_call(call) for call in calls],
            content=content,
        )
        with self._lock:
            self._records[record.key] = record
        return raw, record

    def decide(self, ref: str, *, approve: bool, approver: str | None) -> Approval:
        """Approve or deny a pending approval, addressed by its ref."""
        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            record = self._by_ref_locked(ref)
            if record.status != "pending":
                raise ApprovalError(409, f"approval {ref} is {record.status}, not pending")
            record.decided_at = now
            record.decided_by = approver
            if approve:
                record.status = "approved"
            else:
                record.status = "denied"
                record.finished_at = now
                record.calls = None
            return record

    def claim(self, approval_id: str, *, session_key: str, owner: str) -> Claim:
        """Check and use an approval in one step. At most one claim ever succeeds."""
        key = approval_key(approval_id)
        ref = key[:APPROVAL_REF_LENGTH]
        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            record = self._records.get(key)
            if record is None:
                return Claim(ok=False, status="unknown", ref=ref)
            if record.session_key != session_key or record.owner != owner:
                return Claim(ok=False, status="mismatch", ref=ref, session_ref=record.session_ref)
            if record.status != "approved" or record.calls is None:
                return Claim(
                    ok=False, status=record.status, ref=ref, session_ref=record.session_ref
                )
            record.status = "used"
            record.finished_at = now
            return Claim(
                ok=True,
                status="used",
                ref=ref,
                calls=[_copy_call(call) for call in record.calls],
                content=record.content,
                session_ref=record.session_ref,
                agent=record.agent,
            )

    def verify_replay(self, ref: str, calls: list[dict[str, Any]]) -> bool:
        """True if *calls* are exactly the claimed turn. Drops the raw arguments either way."""
        with self._lock:
            record = next((r for r in self._records.values() if r.ref == ref), None)
            if record is None or record.status != "used" or record.replay_checked:
                return False
            record.replay_checked = True
            record.calls = None
            return calls_hash(calls) == record.calls_hash

    def pending(self) -> list[Approval]:
        """Approvals waiting for a decision or for the agent's retry, oldest first."""
        with self._lock:
            self._expire_locked(self._clock())
            live = [r for r in self._records.values() if r.status in ("pending", "approved")]
        return sorted(live, key=lambda r: r.created_at)

    def get(self, ref: str) -> Approval:
        with self._lock:
            self._expire_locked(self._clock())
            return self._by_ref_locked(ref)

    def expires_in(self, record: Approval) -> int:
        return max(0, int(record.expires_at - self._clock()))

    def sweep(self) -> list[Approval]:
        """Expire overdue approvals. Returns every expiry not yet reported, once."""
        with self._lock:
            self._expire_locked(self._clock())
            expired, self._unlogged_expiries = self._unlogged_expiries, []
            return expired

    def _expire_locked(self, now: float) -> list[Approval]:
        expired = []
        for key, record in list(self._records.items()):
            if record.status in ("pending", "approved") and now >= record.expires_at:
                record.status = "expired"
                record.finished_at = now
                record.calls = None
                expired.append(record)
                self._unlogged_expiries.append(record)
            elif record.finished_at is not None and now - record.finished_at > RECORD_RETENTION:
                del self._records[key]
        return expired

    def _by_ref_locked(self, ref: str) -> Approval:
        if not isinstance(ref, str) or len(ref) != APPROVAL_REF_LENGTH:
            raise ApprovalError(404, "no such approval")
        matches = [r for r in self._records.values() if r.ref == ref]
        if len(matches) != 1:
            raise ApprovalError(404, "no such approval")
        return matches[0]


def _copy_call(call: dict[str, Any]) -> dict[str, Any]:
    function = call.get("function") or {}
    return {
        "id": call.get("id"),
        "type": call.get("type") or "function",
        "function": {"name": function.get("name"), "arguments": function.get("arguments")},
    }


def ttl_from_env(environ: dict[str, str], idle_ttl: float) -> float:
    """APPROVAL_TTL_SECONDS, checked against the session idle timeout."""
    raw = environ.get("APPROVAL_TTL_SECONDS", "").strip()
    if not raw:
        ttl = DEFAULT_APPROVAL_TTL
    else:
        try:
            ttl = int(raw)
        except ValueError:
            raise ValueError(
                f"APPROVAL_TTL_SECONDS must be a positive integer, got {raw!r}"
            ) from None
        if ttl <= 0:
            raise ValueError(f"APPROVAL_TTL_SECONDS must be a positive integer, got {raw!r}")
    if ttl > idle_ttl:
        raise ValueError(
            f"APPROVAL_TTL_SECONDS ({ttl}) must not exceed SESSION_IDLE_TTL_SECONDS "
            f"({int(idle_ttl)}): the agent is idle while it waits, so an approved retry "
            "would find its session expired"
        )
    return float(ttl)
