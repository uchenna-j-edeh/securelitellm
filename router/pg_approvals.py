"""Postgres approval store (#169, #174): approvals that survive restarts.

With ``SESSION_STORE=postgres`` and ``approvals: on``, held turns are kept in
``securelitellm_approvals`` instead of one process's memory. A restart no
longer loses a pending approval, an admin's decision made on one replica is
seen by the others, and an approved turn is replayed at most once however
many replicas the retries reach.

Same rules as the memory store (see ``router.approvals``), plus:

- **Once at most, across replicas.** Every status change is one transaction
  that locks the approval's row, checks it and updates it. Two retries on two
  replicas queue on the lock; the second finds the approval already used.
  Status is always read from the row under that lock, never from a cache.
- **Rows are signed.** An HMAC covers the approval's key, session, owner,
  agent, times, the hash of the stored calls, the hash of the summary an
  approver is shown, the status and who decided. It is checked before any
  decision or replay. A row flipped to ``approved`` inside the database, or a
  summary rewritten to look harmless, fails the check: the approval is
  reported as ``tampered`` and nothing is replayed.
- **Arguments are encrypted.** The raw tool calls must be kept to replay them,
  so they are stored AES-256-GCM encrypted, bound to their approval, under a
  key the database never sees. They are deleted when the approval is used,
  denied or expires. A database dump shows tool names and destination labels
  (the summary), not arguments.

Both keys are derived from ``SESSION_HMAC_KEY`` (HKDF-SHA256, separate labels).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from router.approvals import (
    APPROVAL_ID_BYTES,
    APPROVAL_REF_LENGTH,
    DEFAULT_APPROVAL_TTL,
    RECORD_RETENTION,
    Approval,
    ApprovalError,
    Claim,
    _copy_call,
    approval_key,
    calls_hash,
)
from router.pg_session import APPROVALS_TABLE as TABLE
from router.pg_session import _Database

Clock = Callable[[], float]

_COLUMNS = (
    "approval_key, session_key, session_ref, owner, agent, created_at, expires_at, summary, "
    "calls_hash, payload, status, decided_at, decided_by, finished_at, replay_checked, mac"
)
_OPEN = ("pending", "approved")
SWEEP_INTERVAL = 5.0  # seconds between a process's expiry sweeps
APPROVAL_MAC_VERSION = 2  # Preserve signatures when unrelated tables are added.


def _derive(secret: bytes, label: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label).derive(secret)


class _Row:
    """One approvals row, as read."""

    def __init__(self, values: tuple[Any, ...]) -> None:
        (
            self.key,
            self.session_key,
            self.session_ref,
            self.owner,
            self.agent,
            self.created_at,
            self.expires_at,
            self.summary,
            self.calls_hash,
            self.payload,
            self.status,
            self.decided_at,
            self.decided_by,
            self.finished_at,
            self.replay_checked,
            self.mac,
        ) = values

    @property
    def ref(self) -> str:
        return self.key[:APPROVAL_REF_LENGTH]


class PostgresApprovalStore:
    """Approval store backed by Postgres. Same methods as ``ApprovalStore``."""

    backend = "postgres"
    shared = True

    def __init__(
        self,
        database: _Database,
        secret: bytes,
        ttl: float = DEFAULT_APPROVAL_TTL,
        clock: Clock = time.time,
    ) -> None:
        self._db = database
        self._mac_key = _derive(secret, b"securelitellm approvals mac v1")
        self._cipher = AESGCM(_derive(secret, b"securelitellm approvals payload v1"))
        self._ttl = ttl
        self._clock = clock
        self._last_sweep: float | None = None

    @property
    def ttl(self) -> float:
        return self._ttl

    # -- lifecycle ---------------------------------------------------------

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
        if not calls:
            raise ValueError("an approval needs at least one tool call")
        raw = secrets.token_urlsafe(APPROVAL_ID_BYTES)
        key = approval_key(raw)
        now = self._clock()
        stored_calls = [_copy_call(call) for call in calls]
        row = _Row(
            (
                key,
                session_key,
                session_ref,
                owner,
                agent,
                now,
                now + self._ttl,
                summary,
                calls_hash(calls),
                self._encrypt(key, stored_calls, content),
                "pending",
                None,
                None,
                None,
                False,
                "",
            )
        )
        row.mac = self._mac(row)
        self._db.run(
            lambda conn: conn.execute(
                f"INSERT INTO {TABLE} ({_COLUMNS}) VALUES "
                "(%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    row.key,
                    row.session_key,
                    row.session_ref,
                    row.owner,
                    row.agent,
                    row.created_at,
                    row.expires_at,
                    json.dumps(row.summary),
                    row.calls_hash,
                    row.payload,
                    row.status,
                    None,
                    None,
                    None,
                    False,
                    row.mac,
                ),
            )
        )
        return raw, self._approval(row, stored_calls, content)

    def decide(self, ref: str, *, approve: bool, approver: str | None) -> Approval:
        """Approve or deny a pending approval, addressed by its ref."""
        now = self._clock()

        def work(conn: Any) -> Approval | ApprovalError:
            row = self._by_ref(conn, ref, lock=True)
            if isinstance(row, ApprovalError):
                return row
            self._expire_if_due(conn, row, now)
            if row.status != "pending":
                return ApprovalError(409, f"approval {ref} is {row.status}, not pending")
            if not self._trusted(row):
                return ApprovalError(409, f"approval {ref} failed its integrity check")
            row.status = "approved" if approve else "denied"
            row.decided_at, row.decided_by = now, approver
            if not approve:
                row.finished_at, row.payload = now, None
            row.mac = self._mac(row)
            conn.execute(
                f"UPDATE {TABLE} SET status = %s, decided_at = %s, decided_by = %s, "
                "finished_at = %s, payload = %s, mac = %s WHERE approval_key = %s",
                (
                    row.status,
                    row.decided_at,
                    row.decided_by,
                    row.finished_at,
                    row.payload,
                    row.mac,
                    row.key,
                ),
            )
            return self._approval(row)

        return self._result(self._db.run(work, transaction=True))

    def claim(self, approval_id: str, *, session_key: str, owner: str) -> Claim:
        """Check and use an approval under its row lock. At most one claim ever succeeds."""
        key = approval_key(approval_id)
        ref = key[:APPROVAL_REF_LENGTH]
        now = self._clock()

        def work(conn: Any) -> Claim:
            values = conn.execute(
                f"SELECT {_COLUMNS} FROM {TABLE} WHERE approval_key = %s FOR UPDATE", (key,)
            ).fetchone()
            if values is None:
                return Claim(ok=False, status="unknown", ref=ref)
            row = _Row(values)
            if row.session_key != session_key or row.owner != owner:
                return Claim(ok=False, status="mismatch", ref=ref, session_ref=row.session_ref)
            self._expire_if_due(conn, row, now)
            if row.status != "approved" or row.payload is None:
                return Claim(ok=False, status=row.status, ref=ref, session_ref=row.session_ref)
            if not self._trusted(row):
                return Claim(ok=False, status="tampered", ref=ref, session_ref=row.session_ref)
            opened = self._decrypt(row)
            if opened is None or calls_hash(opened[0]) != row.calls_hash:
                return Claim(ok=False, status="tampered", ref=ref, session_ref=row.session_ref)
            calls, content = opened
            row.status, row.finished_at = "used", now
            row.mac = self._mac(row)
            # The encrypted calls stay until verify_replay has compared them.
            conn.execute(
                f"UPDATE {TABLE} SET status = %s, finished_at = %s, mac = %s "
                "WHERE approval_key = %s",
                (row.status, row.finished_at, row.mac, row.key),
            )
            return Claim(
                ok=True,
                status="used",
                ref=ref,
                calls=calls,
                content=content,
                session_ref=row.session_ref,
                agent=row.agent,
            )

        return self._db.run(work, transaction=True)

    def verify_replay(self, ref: str, calls: list[dict[str, Any]]) -> bool:
        """True if *calls* are exactly the claimed turn. Drops the stored calls either way."""

        def work(conn: Any) -> bool:
            row = self._by_ref(conn, ref, lock=True)
            if isinstance(row, ApprovalError):
                return False
            if row.status != "used" or row.replay_checked or not self._trusted(row):
                return False
            conn.execute(
                f"UPDATE {TABLE} SET replay_checked = true, payload = NULL WHERE approval_key = %s",
                (row.key,),
            )
            return calls_hash(calls) == row.calls_hash

        return self._db.run(work, transaction=True)

    # -- views ----------------------------------------------------------------

    def pending(self) -> list[Approval]:
        """Approvals waiting for a decision or for the agent's retry, oldest first."""
        now = self._clock()
        rows = self._db.run(
            lambda conn: conn.execute(
                f"SELECT {_COLUMNS} FROM {TABLE} WHERE status IN ('pending', 'approved') "
                "AND expires_at > %s ORDER BY created_at",
                (now,),
            ).fetchall()
        )
        approvals = []
        for values in rows:
            row = _Row(values)
            if not self._trusted(row):
                continue  # an approver is never shown a row that was changed in the database
            opened = self._decrypt(row)
            approvals.append(self._approval(row, *(opened or (None, None))))
        return approvals

    def get(self, ref: str) -> Approval:
        now = self._clock()

        def work(conn: Any) -> Approval | ApprovalError:
            row = self._by_ref(conn, ref, lock=True)
            if isinstance(row, ApprovalError):
                return row
            self._expire_if_due(conn, row, now)
            return self._approval(row)

        return self._result(self._db.run(work, transaction=True))

    def expires_in(self, record: Approval) -> int:
        return max(0, int(record.expires_at - self._clock()))

    def due_expiries(self) -> list[Approval]:
        """``sweep()``, at most once every ``SWEEP_INTERVAL`` seconds per process.

        The hook asks on every request so expiries get logged. Expiry itself
        never waits for this: every claim, decision and listing compares the
        approval's expiry time with the clock.
        """
        now = self._clock()
        if self._last_sweep is not None and 0 <= now - self._last_sweep < SWEEP_INTERVAL:
            return []
        return self.sweep()

    def sweep(self) -> list[Approval]:
        """Expire overdue approvals. Each expiry is returned once, to one replica."""
        now = self._clock()
        self._last_sweep = now

        def work(conn: Any) -> list[tuple[Any, ...]]:
            expired = conn.execute(
                f"UPDATE {TABLE} SET status = 'expired', finished_at = %s, payload = NULL "
                f"WHERE status IN ('pending', 'approved') AND expires_at <= %s RETURNING {_COLUMNS}",
                (now, now),
            ).fetchall()
            conn.execute(
                f"DELETE FROM {TABLE} WHERE finished_at IS NOT NULL AND finished_at < %s",
                (now - RECORD_RETENTION,),
            )
            return expired

        return [self._approval(_Row(v)) for v in self._db.run(work, transaction=True)]

    # -- internals -------------------------------------------------------------

    @staticmethod
    def _result(value: Approval | ApprovalError) -> Approval:
        if isinstance(value, ApprovalError):
            raise value  # raised here, after the transaction committed any expiry
        return value

    def _by_ref(self, conn: Any, ref: str, *, lock: bool) -> _Row | ApprovalError:
        hexdigits = "0123456789abcdef"
        if (
            not isinstance(ref, str)
            or len(ref) != APPROVAL_REF_LENGTH
            or any(c not in hexdigits for c in ref)
        ):
            return ApprovalError(404, "no such approval")
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM {TABLE} WHERE approval_key LIKE %s"
            + (" FOR UPDATE" if lock else ""),
            (ref + "%",),
        ).fetchall()
        if len(rows) != 1:
            return ApprovalError(404, "no such approval")
        return _Row(rows[0])

    def _expire_if_due(self, conn: Any, row: _Row, now: float) -> None:
        """Treat an overdue open approval as expired."""
        if row.status in _OPEN and now >= row.expires_at:
            # Treated as expired from here on. The row itself is updated by
            # sweep(), which also hands the expiry to exactly one replica to log.
            row.status = "expired"

    def _trusted(self, row: _Row) -> bool:
        return hmac.compare_digest(self._mac(row), str(row.mac))

    def _mac(self, row: _Row) -> str:
        summary = json.dumps(row.summary, sort_keys=True, separators=(",", ":"))
        material = json.dumps(
            [
                APPROVAL_MAC_VERSION,
                row.key,
                row.session_key,
                row.owner,
                row.agent,
                repr(float(row.created_at)),
                repr(float(row.expires_at)),
                row.calls_hash,
                hashlib.sha256(summary.encode()).hexdigest(),
                row.status,
                row.decided_by,
            ],
            separators=(",", ":"),
        )
        return hmac.new(self._mac_key, material.encode(), hashlib.sha256).hexdigest()

    def _encrypt(self, key: str, calls: list[dict[str, Any]], content: str | None) -> bytes:
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps({"calls": calls, "content": content}).encode()
        return nonce + self._cipher.encrypt(nonce, plaintext, key.encode())

    def _decrypt(self, row: _Row) -> tuple[list[dict[str, Any]], str | None] | None:
        if row.payload is None:
            return None
        blob = bytes(row.payload)
        try:
            opened = json.loads(self._cipher.decrypt(blob[:12], blob[12:], row.key.encode()))
        except (InvalidTag, ValueError):
            return None
        return opened["calls"], opened["content"]

    def _approval(
        self,
        row: _Row,
        calls: list[dict[str, Any]] | None = None,
        content: str | None = None,
    ) -> Approval:
        return Approval(
            key=row.key,
            session_key=row.session_key,
            session_ref=row.session_ref,
            owner=row.owner,
            agent=row.agent,
            created_at=row.created_at,
            expires_at=row.expires_at,
            summary=dict(row.summary),
            calls_hash=row.calls_hash,
            calls=calls,
            content=content,
            status=row.status,
            decided_at=row.decided_at,
            decided_by=row.decided_by,
            finished_at=row.finished_at,
            replay_checked=row.replay_checked,
        )
