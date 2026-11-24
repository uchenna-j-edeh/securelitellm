"""Response decision summaries and bounded history (#250).

Only gateway-created summaries enter this store. No prompts, tool arguments,
raw session ids, credentials or classifier input are retained. CloudWatch is
an independent audit sink, never read by this module.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import threading
import time
from collections import OrderedDict
from datetime import datetime
from typing import Any

DECISION_HEADER = "x-securelitellm-decision"
DECISIONS_PATH = "/securelitellm/decisions"
DECISION_METADATA_KEY = "securelitellm_decision_capture"
HISTORY_TTL = 3600
MAX_HISTORY = 10_000
MAX_SESSION_HISTORY = 300
MAX_HEADER_BYTES = 4096
TABLE = "securelitellm_decisions"


def summary(record: dict) -> dict:
    """A small allowlisted projection of an audit record, safe to store separately."""
    fields = (
        "decision_id",
        "ts",
        "request_id",
        "session_id",
        "agent",
        "phase",
        "mode",
        "action",
        "enforce",
        "risk_score",
        "risk_level",
        "route",
        "data_class",
    )
    result = {key: record[key] for key in fields if key in record}
    result["matched_rules"] = [str(rule)[:100] for rule in record.get("matched_rules", [])[:20]]
    verdicts = record.get("features", {}).get("classifier_verdicts", [])
    labels = {v.get("label") for v in verdicts if isinstance(v, dict)}
    result["classifier_verdict"] = next(
        (label for label in ("INJECTION", "UNKNOWN", "BENIGN") if label in labels), None
    )
    return result


def visible(records: list[dict], detailed: bool) -> list[dict]:
    if detailed:
        return copy.deepcopy(records)
    return [
        {
            "decision_id": r["decision_id"],
            "action": "observe" if r.get("enforce") is False else r["action"],
        }
        for r in records
    ]


def response_value(records: list[dict], detailed: bool, history_available: bool = True) -> dict:
    """The same object is returned in the success header and failure body."""
    value = {"version": 1, "decisions": visible(records, detailed)}
    if not history_available:
        value["history_available"] = False
    # There are at most pre-call and post-call decisions for a model request.
    # Keep every id/action if verbose route or rule labels approach header limits.
    if len(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()) > MAX_HEADER_BYTES:
        value["decisions"] = visible(records, False)
        value["details_truncated"] = True
    return value


class DecisionStore:
    """One-process history, with a global cap, per-session cap and one-hour TTL."""

    backend = "memory"

    def __init__(self, clock=time.time, limit=MAX_HISTORY, session_limit=MAX_SESSION_HISTORY):
        self.clock, self.limit, self.session_limit = clock, limit, session_limit
        self._records: OrderedDict[str, tuple[str, float, dict]] = OrderedDict()
        self._lock = threading.Lock()

    def _prune(self) -> None:
        now = self.clock()
        for key, (_, expires, _) in list(self._records.items()):
            if expires <= now:
                del self._records[key]
        while len(self._records) > self.limit:
            self._records.popitem(last=False)

    def append(self, records: list[dict], owner: str) -> None:
        with self._lock:
            for record in records:
                self._records.setdefault(
                    record["decision_id"],
                    (owner, self.clock() + HISTORY_TTL, copy.deepcopy(record)),
                )
                matching = [
                    k
                    for k, (o, _, r) in self._records.items()
                    if o == owner and r.get("session_id") == record.get("session_id")
                ]
                for key in matching[: -self.session_limit]:
                    del self._records[key]
            self._prune()

    def read(self, session: str, owner: str | None = None) -> list[dict]:
        with self._lock:
            self._prune()
            return copy.deepcopy(
                [
                    r
                    for o, _, r in self._records.values()
                    if r.get("session_id") == session and (owner is None or o == owner)
                ][-self.session_limit :]
            )


class PostgresDecisionStore:
    """Shared history on the existing session database; schema is migrated by its CLI.

    HMACs authenticate both the summary and its ownership/expiry metadata. A
    history outage never changes a policy decision and never falls back to a
    misleading empty memory store.
    """

    backend = "postgres"

    def __init__(self, database: Any, secret: bytes, clock=time.time):
        self._db, self.clock = database, clock
        self._secret = hmac.new(
            secret, b"securelitellm decision history v1", hashlib.sha256
        ).digest()

    def _mac(self, owner: str, expires: float, record: dict) -> str:
        payload = json.dumps([owner, expires, record], sort_keys=True, separators=(",", ":"))
        return hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()

    def append(self, records: list[dict], owner: str) -> None:
        now = self.clock()

        def work(conn):
            conn.execute(f"DELETE FROM {TABLE} WHERE expires_at <= %s", (now,))
            for record in records:
                expires = float(now + HISTORY_TTL)
                created = datetime.fromisoformat(record["ts"]).timestamp()
                conn.execute(
                    f"INSERT INTO {TABLE} (decision_id, session_ref, owner, created_at, expires_at, record, mac) "
                    "VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s) ON CONFLICT (decision_id) DO NOTHING",
                    (
                        record["decision_id"],
                        record.get("session_id"),
                        owner,
                        created,
                        expires,
                        json.dumps(record),
                        self._mac(owner, expires, record),
                    ),
                )
                conn.execute(
                    f"DELETE FROM {TABLE} WHERE session_ref IS NOT DISTINCT FROM %s AND owner = %s "
                    f"AND decision_id NOT IN (SELECT decision_id FROM {TABLE} "
                    "WHERE session_ref IS NOT DISTINCT FROM %s AND owner = %s "
                    "ORDER BY created_at DESC, decision_id DESC LIMIT %s)",
                    (
                        record.get("session_id"),
                        owner,
                        record.get("session_id"),
                        owner,
                        MAX_SESSION_HISTORY,
                    ),
                )

        self._db.run(work, transaction=True)

    def read(self, session: str, owner: str | None = None) -> list[dict]:
        def work(conn):
            return conn.execute(
                f"SELECT decision_id, created_at, owner, expires_at, record, mac FROM {TABLE} WHERE session_ref = %s "
                "AND expires_at > %s AND (%s::text IS NULL OR owner = %s) "
                "ORDER BY created_at DESC, decision_id DESC LIMIT %s",
                (session, self.clock(), owner, owner, MAX_SESSION_HISTORY),
            ).fetchall()

        rows = self._db.run(work)
        records = []
        for identifier, created, row_owner, expires, record, mac in reversed(rows):
            try:
                valid = (
                    isinstance(record, dict)
                    and record.get("decision_id") == identifier
                    and record.get("session_id") == session
                    and hmac.compare_digest(mac, self._mac(row_owner, float(expires), record))
                    and datetime.fromisoformat(record["ts"]).timestamp() == created
                )
            except (TypeError, ValueError, KeyError):
                valid = False
            if not valid:
                from router.session import SessionStoreUnavailable

                raise SessionStoreUnavailable("decision history failed its integrity check")
            records.append(record)
        return records


def history_store(session_store):
    if session_store.backend == "postgres":
        return PostgresDecisionStore(session_store.database, session_store.secret)
    return DecisionStore()
