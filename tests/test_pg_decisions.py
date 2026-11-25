"""Real Postgres decision history: shared across replicas, signed and expiring."""

import json

import psycopg
import pytest

from router.decisions import MAX_SESSION_HISTORY, TABLE, PostgresDecisionStore
from router.session import SessionStoreUnavailable
from tests.test_decision_response import record


@pytest.fixture()
def replica(pg_store_factory, pg_url, clock):
    with psycopg.connect(pg_url) as conn:
        conn.execute(f"TRUNCATE {TABLE}")

    def make():
        session = pg_store_factory()
        return PostgresDecisionStore(session.database, session.secret, clock)

    return make


def test_shared_history_survives_store_recreation_and_filters_owner(replica):
    first = replica()
    first.append([record()], "key-a")
    first.append([record()], "key-a")
    after_restart = replica()
    assert after_restart.read("a" * 16, "key-a") == [record()]
    assert after_restart.read("a" * 16, "key-b") == []


def test_newest_decisions_are_kept_and_old_history_expires(replica, clock):
    store = replica()
    rows = [
        record(decision_id=f"{n:032x}", ts=f"2026-11-24T02:{n // 60:02}:{n % 60:02}+00:00")
        for n in range(MAX_SESSION_HISTORY + 10)
    ]
    store.append(rows, "key-a")
    assert store.read("a" * 16) == rows[-MAX_SESSION_HISTORY:]
    clock.advance(3601)
    assert store.read("a" * 16) == []


@pytest.mark.parametrize(
    "column,value", [("owner", "other-key"), ("record", json.dumps(record(action="block")))]
)
def test_database_tampering_is_reported_instead_of_rendered_as_evidence(
    replica, pg_url, column, value
):
    store = replica()
    store.append([record()], "key-a")
    with psycopg.connect(pg_url) as conn:
        cast = "::jsonb" if column == "record" else ""
        conn.execute(f"UPDATE {TABLE} SET {column} = %s{cast}", (value,))
    with pytest.raises(SessionStoreUnavailable, match="integrity"):
        store.read("a" * 16)
