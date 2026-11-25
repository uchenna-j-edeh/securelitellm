"""Postgres session store (#169): sessions that survive restarts and are shared.

With ``SESSION_STORE=postgres`` the session state the router decides on
(taint, tainted content hashes, sensitivity, escalation count) and the records
of expired session ids live in Postgres. Every worker and replica sees the
same sessions, and a restart loses nothing.

What is stored
--------------
One row per session in ``securelitellm_sessions``, keyed by
``SHA-256(session id)``. Never the raw session id, and never raw tool content:
only the SHA-256 of tainted content, and for sinks only the call id, tool
name, category and argument length. Clean sources are not stored at all.

An expired session keeps its row as a tombstone (taint hashes and sinks
wiped) until ``SESSION_TOMBSTONE_TTL_SECONDS`` passes, so reusing an expired
id is still rejected after a restart.

Atomic updates
--------------
Each change to a session is one transaction that locks the row
(``SELECT ... FOR UPDATE``), so two replicas updating the same session can't
lose each other's taint. Reads and the "still in use" timestamp are single
statements.

Integrity (HMAC)
----------------
Each live row carries an HMAC-SHA256, keyed by ``SESSION_HMAC_KEY``, over the
fields decisions depend on: key, owner, creation time, tainted, sensitive,
escalation count and the tainted hashes. It is checked on every read. A row
that fails (someone with database access cleared ``tainted``, say) is rejected
as ``SessionTampered``. The HMAC can't detect a whole row being replaced by an
older valid copy of itself, or being deleted (a deleted session is simply
unknown and rejected). The recorded sinks and the last-seen time are not
covered: no decision reads the sinks, and moving last-seen can only shorten or
extend one session's idle window.

Failure
-------
Any database error raises ``SessionStoreUnavailable`` and the request is
refused. Nothing is retried mid-operation and nothing falls back to memory.
The connection is reopened on the next call.

Reads within a request
----------------------
The hook reads a session several times per request. ``authorize`` opens each
request phase with a read from the database; for the next second ``state``
reuses that row from this process's memory, updated by this process's own
writes. So a request costs two session reads instead of six, and another
replica's write is seen by the next request, when it could first matter. There
is no cross-process cache: a Redis GET measured 0.20 ms against 0.29 ms for the
Postgres key lookup it would replace, which doesn't pay for a second store
whose stale entries could hide taint.

Calls are synchronous: one connection per process, one call in flight at a
time. A call that the database doesn't answer within twice
``SESSION_DB_TIMEOUT_MS`` is abandoned and fails closed, and for the next two
seconds calls fail at once rather than queue behind a dead database.

Schema
------
The proxy does not create its tables; its database user needs no DDL rights.
Create or upgrade them once with an admin connection::

    SESSION_DB_ADMIN_URL=postgresql://admin:...@host/db \\
        python -m router.pg_session migrate --grant-to securelitellm_proxy

Add ``--role-password-env VAR`` to create that role as a login user (or reset
its password) from the password in ``$VAR``. The role gets SELECT, INSERT,
UPDATE and DELETE on the session and approval tables, SELECT on the version
table, and nothing else.

Environment
-----------
SESSION_DB_URL              libpq URL or conninfo for the proxy's user
SESSION_HMAC_KEY            secret for row HMACs, at least 32 characters
SESSION_DB_TIMEOUT_MS       connect and statement timeout (default 2000)
SESSION_DB_ALLOW_PLAINTEXT  true to allow a connection without TLS
                            (sslmode require / verify-ca / verify-full is
                            otherwise mandatory)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import secrets
import threading
import time
from collections.abc import Callable
from typing import Any

from router.session import (
    SESSION_ID_BYTES,
    SWEEP_INTERVAL,
    BaseSessionStore,
    SessionError,
    SessionExpired,
    SessionOwnerMismatch,
    SessionState,
    SessionStoreUnavailable,
    SessionTampered,
    SessionUnknown,
    session_key,
    source_hash,
    store_ttls_from_env,
)

SCHEMA_VERSION = 3  # 3 adds bounded decision history (#250)
SESSION_MAC_VERSION = 2  # Session payload is unchanged by the additive history migration.
TABLE = "securelitellm_sessions"
APPROVALS_TABLE = "securelitellm_approvals"
DECISIONS_TABLE = "securelitellm_decisions"
META_TABLE = "securelitellm_schema"
MAX_SINKS = 200  # per session; the oldest is dropped
SINK_FIELDS = ("id", "name", "category", "args_length", "inventory")
MIN_HMAC_KEY_LENGTH = 32
DEFAULT_TIMEOUT_MS = 2000
RETRY_AFTER = 2.0  # seconds to fail fast after a timeout or failed connection
SNAPSHOT_SECONDS = 1.0  # how long state() may reuse the row authorize() just read
MAX_SNAPSHOTS = 10_000
TOUCH_INTERVAL = 30.0  # seconds between last-seen writes for one busy session
TLS_MODES = ("require", "verify-ca", "verify-full")

Clock = Callable[[], float]

SCHEMA_STATEMENTS = (
    f"""
    CREATE TABLE IF NOT EXISTS {DECISIONS_TABLE} (
        decision_id text PRIMARY KEY,
        session_ref text,
        owner text NOT NULL,
        created_at double precision NOT NULL,
        expires_at double precision NOT NULL,
        record jsonb NOT NULL,
        mac text NOT NULL
    )
    """,
    f"CREATE INDEX IF NOT EXISTS {DECISIONS_TABLE}_session_idx "
    f"ON {DECISIONS_TABLE} (session_ref, owner, created_at DESC)",
    f"CREATE INDEX IF NOT EXISTS {DECISIONS_TABLE}_expiry_idx ON {DECISIONS_TABLE} (expires_at)",
    f"""
    CREATE TABLE IF NOT EXISTS {TABLE} (
        session_key      text PRIMARY KEY,
        owner            text NOT NULL,
        created_at       double precision NOT NULL,
        last_seen_at     double precision NOT NULL,
        tainted          boolean NOT NULL DEFAULT false,
        sensitive        boolean NOT NULL DEFAULT false,
        escalation_count integer NOT NULL DEFAULT 0,
        tainted_spans    text[] NOT NULL DEFAULT '{{}}',
        sinks            jsonb NOT NULL DEFAULT '[]',
        expired_at       double precision,
        expired_reason   text,
        mac              text NOT NULL
    )
    """,
    f"CREATE INDEX IF NOT EXISTS {TABLE}_live_idx ON {TABLE} (last_seen_at) "
    "WHERE expired_at IS NULL",
    f"CREATE INDEX IF NOT EXISTS {TABLE}_expired_idx ON {TABLE} (expired_at) "
    "WHERE expired_at IS NOT NULL",
    f"CREATE TABLE IF NOT EXISTS {META_TABLE} (version integer NOT NULL)",
    # Held-for-approval turns (#174). payload is the AES-GCM encrypted tool
    # calls, NULL as soon as they are no longer needed.
    f"""
    CREATE TABLE IF NOT EXISTS {APPROVALS_TABLE} (
        approval_key   text PRIMARY KEY,
        session_key    text NOT NULL,
        session_ref    text NOT NULL,
        owner          text NOT NULL,
        agent          text,
        created_at     double precision NOT NULL,
        expires_at     double precision NOT NULL,
        summary        jsonb NOT NULL,
        calls_hash     text NOT NULL,
        payload        bytea,
        status         text NOT NULL,
        decided_at     double precision,
        decided_by     text,
        finished_at    double precision,
        replay_checked boolean NOT NULL DEFAULT false,
        mac            text NOT NULL
    )
    """,
    f"CREATE INDEX IF NOT EXISTS {APPROVALS_TABLE}_open_idx ON {APPROVALS_TABLE} (expires_at) "
    "WHERE status IN ('pending', 'approved')",
)

_COLUMNS = (
    "session_key, owner, created_at, last_seen_at, tainted, sensitive, "
    "escalation_count, tainted_spans, sinks, mac"
)
_WIPE = "tainted_spans = '{}', sinks = '[]'"


def _psycopg() -> Any:
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise RuntimeError(
            "SESSION_STORE=postgres needs the 'psycopg' package (pip install 'psycopg[binary]')"
        ) from exc
    return psycopg


class _Worker(threading.Thread):
    """Runs database calls so the caller can stop waiting at a deadline.

    The connection belongs to the worker and is only touched on its thread. An
    abandoned worker therefore can't close or replace the connection of the
    worker that took over from it.
    """

    def __init__(self) -> None:
        super().__init__(name="session-store-db", daemon=True)
        self.jobs: queue.SimpleQueue[Any] = queue.SimpleQueue()
        self.conn: Any = None

    def run(self) -> None:
        while True:
            job = self.jobs.get()
            if job is None:
                self.drop()
                return
            call, result, done = job
            try:
                result.append((True, call()))
            except BaseException as exc:  # noqa: BLE001 - handed to the caller
                result.append((False, exc))
            done.set()

    def drop(self) -> None:
        conn, self.conn = self.conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - already failing; nothing to add
                pass


class _Database:
    """One connection, one call at a time. Any database problem fails closed.

    Three limits keep a sick database from holding requests:

    - the server stops a statement or lock wait after ``timeout_ms``;
    - the caller stops waiting after ``2 x timeout_ms`` even if the server
      never answers (a frozen host can't enforce its own timeout). The stuck
      call is abandoned with its worker and connection; if the server later
      runs it, the effect is at worst an extra escalation or taint, never less;
    - after a timeout or a failed connection, calls fail at once for
      ``RETRY_AFTER`` seconds instead of each waiting out the timeout.
    """

    def __init__(self, conninfo: str, timeout_ms: int) -> None:
        self._conninfo = conninfo
        self._timeout_ms = timeout_ms
        self._deadline = 2 * timeout_ms / 1000
        self._lock = threading.Lock()
        self._worker: _Worker | None = None
        self._down_until = 0.0

    def run(self, work: Callable[[Any], Any], *, transaction: bool = False) -> Any:
        with self._lock:
            if time.monotonic() < self._down_until:
                raise SessionStoreUnavailable("the session store is unavailable (not retried yet)")
            if self._worker is None:
                self._worker = _Worker()
                self._worker.start()
            worker = self._worker
            result: list[tuple[bool, Any]] = []
            done = threading.Event()
            worker.jobs.put((lambda: self._execute(worker, work, transaction), result, done))
            if not done.wait(self._deadline):
                # Leave the stuck call behind with its own worker and connection
                # (it closes them when the call finally returns) and start clean.
                worker.jobs.put(None)
                self._worker = None
                self._down_until = time.monotonic() + RETRY_AFTER
                raise SessionStoreUnavailable("the session store is unavailable (timed out)")
            ok, value = result[0]
            if ok:
                return value
            if getattr(value, "connect_failed", False):
                self._down_until = time.monotonic() + RETRY_AFTER
            raise value

    def close(self) -> None:
        with self._lock:
            if self._worker is not None:
                self._worker.jobs.put(None)  # the worker closes its connection as it exits
                self._worker = None

    def _execute(self, worker: _Worker, work: Callable[[Any], Any], transaction: bool) -> Any:
        """On the worker's thread: connect if needed, run *work*, map driver errors."""
        psycopg = _psycopg()
        try:
            conn = self._connection(worker, psycopg)
        except psycopg.Error as exc:
            worker.drop()
            error = self._unavailable(exc)
            error.connect_failed = True  # type: ignore[attr-defined]
            raise error from exc
        try:
            if transaction:
                with conn.transaction():
                    return work(conn)
            return work(conn)
        except SessionError:
            raise
        except psycopg.Error as exc:
            worker.drop()
            raise self._unavailable(exc) from exc

    @staticmethod
    def _unavailable(exc: Exception) -> SessionStoreUnavailable:
        # The driver's message can name hosts and users; keep only its type.
        return SessionStoreUnavailable(f"the session store is unavailable ({type(exc).__name__})")

    def _connection(self, worker: _Worker, psycopg: Any) -> Any:
        if worker.conn is not None and not worker.conn.closed and not worker.conn.broken:
            return worker.conn
        worker.drop()
        conn = psycopg.connect(
            self._conninfo,
            autocommit=True,
            connect_timeout=max(1, round(self._timeout_ms / 1000)),
            options=f"-c statement_timeout={self._timeout_ms} -c lock_timeout={self._timeout_ms}",
        )
        try:
            row = conn.execute(f"SELECT max(version) FROM {META_TABLE}").fetchone()
        except psycopg.errors.UndefinedTable as exc:
            conn.close()
            raise SessionStoreUnavailable(
                "the session tables are missing; run 'python -m router.pg_session migrate'"
            ) from exc
        if row is None or row[0] != SCHEMA_VERSION:
            conn.close()
            raise SessionStoreUnavailable(
                f"the session tables are at schema version {row[0] if row else None}, "
                f"this proxy needs {SCHEMA_VERSION}; run 'python -m router.pg_session migrate'"
            )
        worker.conn = conn
        return conn


class PostgresSessionStore(BaseSessionStore):
    """Session store backed by Postgres. See the module docstring."""

    backend = "postgres"
    shared = True

    def __init__(
        self,
        conninfo: str,
        hmac_key: str | bytes,
        *,
        idle_ttl: float,
        tombstone_ttl: float,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        clock: Clock = time.time,
    ) -> None:
        key = hmac_key.encode() if isinstance(hmac_key, str) else hmac_key
        if len(key) < MIN_HMAC_KEY_LENGTH:
            raise ValueError(f"SESSION_HMAC_KEY must be at least {MIN_HMAC_KEY_LENGTH} characters")
        self._hmac_key = key
        self._db = _Database(conninfo, timeout_ms)
        self._idle_ttl = idle_ttl
        self._tombstone_ttl = tombstone_ttl
        self._clock = clock
        self._last_sweep = clock()
        self._touch_every = min(TOUCH_INTERVAL, idle_ttl / 60)
        self._snapshots: dict[str, tuple[float, SessionState]] = {}

    @classmethod
    def from_env(cls) -> PostgresSessionStore:
        conninfo = os.environ.get("SESSION_DB_URL", "").strip()
        if not conninfo:
            raise ValueError("SESSION_STORE=postgres requires SESSION_DB_URL")
        hmac_key = os.environ.get("SESSION_HMAC_KEY", "")
        if not hmac_key:
            raise ValueError("SESSION_STORE=postgres requires SESSION_HMAC_KEY")
        allow_plaintext = os.environ.get("SESSION_DB_ALLOW_PLAINTEXT", "").strip().lower() == "true"
        if not allow_plaintext:
            _require_tls(conninfo)
        idle_ttl, tombstone_ttl = store_ttls_from_env()
        return cls(
            conninfo,
            hmac_key,
            idle_ttl=idle_ttl,
            tombstone_ttl=tombstone_ttl,
            timeout_ms=_timeout_from_env(),
        )

    @property
    def idle_ttl(self) -> float:
        return self._idle_ttl

    @property
    def database(self) -> _Database:
        """The connection, shared with the approval store (one per process)."""
        return self._db

    @property
    def secret(self) -> bytes:
        return self._hmac_key

    def check(self) -> None:
        """Connect and confirm the schema. Raises SessionStoreUnavailable."""
        self._db.run(lambda conn: conn.execute("SELECT 1").fetchone())

    def close(self) -> None:
        self._db.close()

    # -- sessions ----------------------------------------------------------

    def issue(self, owner: str = "") -> str:
        while True:
            raw = secrets.token_urlsafe(SESSION_ID_BYTES)
            key = session_key(raw)
            now = self._clock()
            mac = self._mac(key, owner, now, False, False, 0, [])
            created = self._db.run(
                lambda conn, key=key, now=now, mac=mac: conn.execute(
                    f"INSERT INTO {TABLE} (session_key, owner, created_at, last_seen_at, mac) "
                    "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (session_key) DO NOTHING "
                    "RETURNING session_key",
                    (key, owner, now, now, mac),
                ).fetchone()
            )
            if created is not None:
                return raw  # only the key was stored

    def state(self, key: str) -> SessionState:
        """The live session, from this process's snapshot if it is fresh.

        A request reads its session several times. ``authorize`` starts each
        request phase with a read from the database; the reads that follow
        within ``SNAPSHOT_SECONDS`` reuse that row, kept up to date with this
        process's own writes. Another replica's write is therefore seen at the
        next ``authorize``, that is, by the next request, which is when it
        could first matter.
        """
        now = self._clock()
        cached = self._snapshots.get(key)
        if cached is not None and 0 <= now - cached[0] <= SNAPSHOT_SECONDS:
            return _copy_state(cached[1])
        return self._use(key)

    def authorize(self, key: str, owner: str) -> SessionState:
        """The live session if *owner* is the API key it was issued to.

        Always read from the database, never from the snapshot.
        """
        state = self._use(key)
        if state.owner != owner:
            raise SessionOwnerMismatch(key)
        return state

    def _fresh(self, key: str, now: float, test: Callable[[SessionState], bool]) -> bool:
        """True if a fresh snapshot of *key* already satisfies *test*.

        Only used to skip writes that would change nothing: taint and the
        sensitive flag are never cleared, so "already set" can't go stale.
        """
        cached = self._snapshots.get(key)
        return cached is not None and 0 <= now - cached[0] <= SNAPSHOT_SECONDS and test(cached[1])

    def _remember(self, key: str, state: SessionState | None) -> None:
        """Keep (or with None, forget) this process's snapshot of a session."""
        if state is None:
            self._snapshots.pop(key, None)
            return
        if len(self._snapshots) >= MAX_SNAPSHOTS:
            self._snapshots.clear()  # entries live a second; a full table is all stale
        self._snapshots[key] = (self._clock(), _copy_state(state))

    def _use(self, key: str) -> SessionState:
        """Read a live session and note that it is in use, in one statement.

        The last-seen time is rewritten only when it is older than
        ``_touch_every`` seconds, so a busy session costs one write per window
        rather than one per read. A session can therefore expire up to that
        many seconds early, never late.
        """
        now = self._clock()
        # Whatever this read finds replaces the snapshot; if it fails or the row
        # is rejected, no older snapshot may answer in its place.
        self._remember(key, None)
        self._maybe_sweep(now)
        live = "session_key = %(key)s AND expired_at IS NULL AND last_seen_at >= %(cutoff)s"
        row = self._db.run(
            lambda conn: conn.execute(
                f"WITH touched AS (UPDATE {TABLE} SET last_seen_at = %(now)s WHERE {live} "
                f"AND last_seen_at < %(stale)s RETURNING {_COLUMNS}) "
                f"SELECT {_COLUMNS} FROM touched UNION ALL "
                f"SELECT {_COLUMNS} FROM {TABLE} WHERE {live} AND last_seen_at >= %(stale)s",
                {
                    "key": key,
                    "now": now,
                    "cutoff": now - self._idle_ttl,
                    "stale": now - self._touch_every,
                },
            ).fetchone()
        )
        if row is None:
            self._raise_not_live(key, now)
        state = self._state(row)
        self._remember(key, state)
        return state

    def record_source(self, key: str, source: dict[str, Any], *, taint: bool = True) -> None:
        """Taint the session with a flagged source's hash. Clean sources aren't stored."""
        if not taint:
            return
        content_hash = source_hash(source)
        now = self._clock()
        if self._fresh(key, now, lambda s: s.tainted and content_hash in s.tainted_spans):
            return  # already recorded, as this request's own read shows
        already = self._db.run(
            lambda conn: conn.execute(
                f"SELECT 1 FROM {TABLE} WHERE session_key = %s AND expired_at IS NULL "
                "AND last_seen_at >= %s AND tainted AND %s = ANY(tainted_spans)",
                (key, now - self._idle_ttl, content_hash),
            ).fetchone()
        )
        if already is not None:
            return  # every turn replays earlier sources; nothing new to record

        def change(fields: dict[str, Any]) -> None:
            fields["tainted"] = True
            if content_hash not in fields["tainted_spans"]:
                fields["tainted_spans"].append(content_hash)

        if self._change(key, now, change) is None:
            self._remember(key, None)
            self._raise_not_live(key, now)

    def record_sink(self, key: str, sink: dict[str, Any]) -> None:
        entry = {name: sink[name] for name in SINK_FIELDS if name in sink}
        self._remember(key, None)
        self._db.run(
            lambda conn: conn.execute(
                f"UPDATE {TABLE} SET sinks = (CASE WHEN jsonb_array_length(sinks) >= %s "
                "THEN sinks - 0 ELSE sinks END) || %s::jsonb "
                "WHERE session_key = %s AND expired_at IS NULL",
                (MAX_SINKS, json.dumps([entry]), key),
            )
        )

    def mark_sensitive(self, key: str) -> None:
        now = self._clock()
        if self._fresh(key, now, lambda s: s.sensitive):
            return
        already = self._db.run(
            lambda conn: conn.execute(
                f"SELECT 1 FROM {TABLE} WHERE session_key = %s AND expired_at IS NULL "
                "AND sensitive",
                (key,),
            ).fetchone()
        )
        if already is None:
            self._change(key, now, lambda fields: fields.__setitem__("sensitive", True))

    def record_escalation(self, key: str) -> int:
        def change(fields: dict[str, Any]) -> None:
            fields["escalation_count"] += 1

        state = self._change(key, self._clock(), change)
        return state.escalation_count if state is not None else 0

    # -- expiry ------------------------------------------------------------

    def expire(self, key: str, reason: str = "ended") -> None:
        now = self._clock()
        self._remember(key, None)
        self._db.run(
            lambda conn: conn.execute(
                f"INSERT INTO {TABLE} (session_key, owner, created_at, last_seen_at, "
                "expired_at, expired_reason, mac) VALUES (%s, '', %s, %s, %s, %s, '') "
                "ON CONFLICT (session_key) DO UPDATE SET expired_at = EXCLUDED.expired_at, "
                f"expired_reason = EXCLUDED.expired_reason, {_WIPE}",
                (key, now, now, now, reason),
            )
        )

    def sweep(self) -> None:
        """Expire idle sessions and delete old expired-id records, for every replica."""
        now = self._clock()
        self._last_sweep = now
        self._snapshots.clear()

        def work(conn: Any) -> None:
            conn.execute(
                f"UPDATE {TABLE} SET expired_at = %s, expired_reason = 'idle', {_WIPE} "
                "WHERE expired_at IS NULL AND last_seen_at < %s",
                (now, now - self._idle_ttl),
            )
            conn.execute(
                f"DELETE FROM {TABLE} WHERE expired_at IS NOT NULL AND expired_at < %s",
                (now - self._tombstone_ttl,),
            )

        self._db.run(work, transaction=True)

    # -- internals ---------------------------------------------------------

    def _maybe_sweep(self, now: float) -> None:
        if now - self._last_sweep >= SWEEP_INTERVAL:
            self.sweep()

    def _change(
        self, key: str, now: float, change: Callable[[dict[str, Any]], None]
    ) -> SessionState | None:
        """Apply *change* to a live session under a row lock. None if it isn't live."""

        def work(conn: Any) -> SessionState | None:
            row = conn.execute(
                f"SELECT {_COLUMNS} FROM {TABLE} WHERE session_key = %s "
                "AND expired_at IS NULL AND last_seen_at >= %s FOR UPDATE",
                (key, now - self._idle_ttl),
            ).fetchone()
            if row is None:
                return None
            state = self._state(row)  # checks the HMAC before anything is added to it
            fields = {
                "tainted": state.tainted,
                "sensitive": state.sensitive,
                "escalation_count": state.escalation_count,
                "tainted_spans": list(state.tainted_spans),
            }
            change(fields)
            spans = sorted(set(fields["tainted_spans"]))
            mac = self._mac(
                key,
                state.owner,
                state.created_at,
                fields["tainted"],
                fields["sensitive"],
                fields["escalation_count"],
                spans,
            )
            conn.execute(
                f"UPDATE {TABLE} SET tainted = %s, sensitive = %s, escalation_count = %s, "
                "tainted_spans = %s, mac = %s WHERE session_key = %s",
                (
                    fields["tainted"],
                    fields["sensitive"],
                    fields["escalation_count"],
                    spans,
                    mac,
                    key,
                ),
            )
            state.tainted = fields["tainted"]
            state.sensitive = fields["sensitive"]
            state.escalation_count = fields["escalation_count"]
            state.tainted_spans = spans
            return state

        self._remember(key, None)  # if the write fails, the snapshot must not outlive it
        changed = self._db.run(work, transaction=True)
        if changed is not None:
            self._remember(key, changed)
        return changed

    def _raise_not_live(self, key: str, now: float) -> None:
        """Work out why *key* has no live row, record an idle expiry, and raise."""

        def work(conn: Any) -> tuple[str, str]:
            row = conn.execute(
                f"SELECT expired_at, expired_reason FROM {TABLE} WHERE session_key = %s FOR UPDATE",
                (key,),
            ).fetchone()
            if row is None:
                return "unknown", ""
            expired_at, reason = row
            if expired_at is None:
                # Live but idle past the timeout: expire it now.
                conn.execute(
                    f"UPDATE {TABLE} SET expired_at = %s, expired_reason = 'idle', {_WIPE} "
                    "WHERE session_key = %s",
                    (now, key),
                )
                return "expired", "idle"
            if now - expired_at <= self._tombstone_ttl:
                return "expired", str(reason or "ended")
            conn.execute(f"DELETE FROM {TABLE} WHERE session_key = %s", (key,))
            return "unknown", ""

        outcome, reason = self._db.run(work, transaction=True)
        if outcome == "expired":
            raise SessionExpired(key, reason)
        raise SessionUnknown(key)

    def _state(self, row: tuple[Any, ...]) -> SessionState:
        key, owner, created_at, last_seen_at, tainted, sensitive, escalation, spans, sinks, mac = (
            row
        )
        expected = self._mac(key, owner, created_at, tainted, sensitive, escalation, spans)
        if not hmac.compare_digest(expected, str(mac)):
            raise SessionTampered(key)
        return SessionState(
            session_id=key,
            owner=owner,
            created_at=created_at,
            last_seen_at=last_seen_at,
            sources=[],  # raw content is never stored
            sinks=list(sinks or []),
            tainted=tainted,
            tainted_spans=list(spans),
            escalation_count=escalation,
            sensitive=sensitive,
        )

    def _mac(
        self,
        key: str,
        owner: str,
        created_at: float,
        tainted: bool,
        sensitive: bool,
        escalation_count: int,
        spans: list[str],
    ) -> str:
        material = json.dumps(
            [
                SESSION_MAC_VERSION,
                key,
                owner,
                repr(float(created_at)),
                bool(tainted),
                bool(sensitive),
                int(escalation_count),
                sorted(spans),
            ],
            separators=(",", ":"),
        )
        return hmac.new(self._hmac_key, material.encode(), hashlib.sha256).hexdigest()


def _copy_state(state: SessionState) -> SessionState:
    return SessionState(
        session_id=state.session_id,
        owner=state.owner,
        created_at=state.created_at,
        last_seen_at=state.last_seen_at,
        sources=[],
        sinks=[dict(sink) for sink in state.sinks],
        tainted=state.tainted,
        tainted_spans=list(state.tainted_spans),
        escalation_count=state.escalation_count,
        sensitive=state.sensitive,
    )


def _timeout_from_env() -> int:
    raw = os.environ.get("SESSION_DB_TIMEOUT_MS", "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_MS
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"SESSION_DB_TIMEOUT_MS must be a positive integer, got {raw!r}") from None
    if value <= 0:
        raise ValueError(f"SESSION_DB_TIMEOUT_MS must be a positive integer, got {raw!r}")
    return value


def _require_tls(conninfo: str) -> None:
    from psycopg.conninfo import conninfo_to_dict

    try:
        sslmode = conninfo_to_dict(conninfo).get("sslmode")
    except Exception:  # noqa: BLE001 - the value may hold a password; don't echo it
        raise ValueError("SESSION_DB_URL is not a valid Postgres connection string") from None
    if sslmode not in TLS_MODES:
        raise ValueError(
            f"SESSION_DB_URL must set sslmode to one of {TLS_MODES} "
            "(or set SESSION_DB_ALLOW_PLAINTEXT=true for a local database)"
        )


def migrate(conninfo: str, grant_to: str | None = None, role_password: str | None = None) -> None:
    """Create or upgrade the session tables. Needs a user allowed to create tables.

    *grant_to* is given read/write on the session tables and nothing else. With
    *role_password* that role is created as a login role first, or its password
    is reset, which needs a user allowed to create roles.
    """
    psycopg = _psycopg()
    from psycopg import sql

    if role_password is not None and not grant_to:
        raise ValueError("a role password needs --grant-to to name the role")
    with psycopg.connect(conninfo) as conn:
        if grant_to and role_password is not None:
            exists = conn.execute(
                "SELECT 1 FROM pg_roles WHERE rolname = %s", (grant_to,)
            ).fetchone()
            conn.execute(
                sql.SQL("{} ROLE {} LOGIN PASSWORD {}").format(
                    sql.SQL("ALTER" if exists else "CREATE"),
                    sql.Identifier(grant_to),
                    sql.Literal(role_password),
                )
            )
        for statement in SCHEMA_STATEMENTS:
            conn.execute(statement)
        current = conn.execute(f"SELECT max(version) FROM {META_TABLE}").fetchone()[0]
        if current is None:
            conn.execute(f"INSERT INTO {META_TABLE} (version) VALUES (%s)", (SCHEMA_VERSION,))
        elif current > SCHEMA_VERSION:
            raise RuntimeError(
                f"the database is at schema version {current}, newer than this code "
                f"({SCHEMA_VERSION})"
            )
        elif current < SCHEMA_VERSION:
            # Every statement above is "IF NOT EXISTS": older databases gained
            # the newer tables there, so only the version is left to record.
            conn.execute(f"UPDATE {META_TABLE} SET version = %s", (SCHEMA_VERSION,))
        if grant_to:
            role = sql.Identifier(grant_to)
            for table in (TABLE, APPROVALS_TABLE, DECISIONS_TABLE):
                conn.execute(
                    sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON {} TO {}").format(
                        sql.Identifier(table), role
                    )
                )
            conn.execute(
                sql.SQL("GRANT SELECT ON {} TO {}").format(sql.Identifier(META_TABLE), role)
            )


def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m router.pg_session")
    commands = parser.add_subparsers(dest="command", required=True)
    cmd = commands.add_parser("migrate", help="create or upgrade the session tables")
    cmd.add_argument(
        "--grant-to", help="role to give read/write on the session tables (the proxy's user)"
    )
    cmd.add_argument(
        "--role-password-env",
        metavar="VAR",
        help="create --grant-to as a login role (or reset its password) with the password "
        "in this environment variable",
    )
    args = parser.parse_args(argv)
    conninfo = os.environ.get("SESSION_DB_ADMIN_URL") or os.environ.get("SESSION_DB_URL")
    if not conninfo:
        parser.error("set SESSION_DB_ADMIN_URL (or SESSION_DB_URL) to the database to migrate")
    role_password = None
    if args.role_password_env:
        role_password = os.environ.get(args.role_password_env)
        if not role_password:
            parser.error(f"{args.role_password_env} is empty")
    migrate(conninfo, grant_to=args.grant_to, role_password=role_password)
    print(f"session tables are at schema version {SCHEMA_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
