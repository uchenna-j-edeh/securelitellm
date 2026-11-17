"""Shared pytest fixtures."""

from pathlib import Path

import pytest

DEPLOY_LITELLM_CONFIG = Path(__file__).parent.parent / "deploy" / "litellm_config.yaml"


@pytest.fixture(autouse=True)
def _litellm_config(monkeypatch):
    """Every hook checks its routes against a LiteLLM config, as compose does."""
    monkeypatch.setenv("ROUTER_LITELLM_CONFIG", str(DEPLOY_LITELLM_CONFIG))
    monkeypatch.delenv("ROUTER_HARDENED_MODEL", raising=False)
    monkeypatch.delenv("ROUTER_ROUTE_HEADER", raising=False)


@pytest.fixture()
def log_path(tmp_path):
    return str(tmp_path / "decisions.jsonl")


# -- Postgres session store (#169) -------------------------------------------
# Tests that need a real Postgres run only when TEST_SESSION_DB_URL points at a
# throwaway database (CI provides one; locally: `make test-db-up`).

TEST_SESSION_HMAC_KEY = "test-hmac-key-" + "k" * 32


class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def clock():
    return FakeClock()


@pytest.fixture(scope="session")
def pg_url():
    import os

    url = os.environ.get("TEST_SESSION_DB_URL")
    if not url:
        pytest.skip("TEST_SESSION_DB_URL is not set; Postgres session store tests skipped")
    from router.pg_session import migrate

    migrate(url)
    return url


@pytest.fixture()
def pg_store_factory(pg_url, clock):
    """Build PostgresSessionStore objects on an emptied table; closed afterwards."""
    import psycopg

    from router.pg_session import APPROVALS_TABLE, TABLE, PostgresSessionStore

    with psycopg.connect(pg_url) as conn:
        conn.execute(f"TRUNCATE {TABLE}, {APPROVALS_TABLE}")
    stores = []

    def make(**kw):
        kw.setdefault("idle_ttl", 1800)
        kw.setdefault("tombstone_ttl", 86400)
        kw.setdefault("clock", clock)
        store = PostgresSessionStore(pg_url, kw.pop("hmac_key", TEST_SESSION_HMAC_KEY), **kw)
        stores.append(store)
        return store

    yield make
    for store in stores:
        store.close()


@pytest.fixture(autouse=True)
def _session_backend(request, monkeypatch):
    """TEST_SESSION_BACKEND=postgres: every store a fixture builds is Postgres.

    Fixtures and tests that build their store with ``SessionStore(...)`` after
    importing it inside the function get a PostgresSessionStore on an emptied
    table, so the whole hook suite doubles as a check that decisions don't
    depend on the backend. Modules that import SessionStore at the top (the
    memory store's own tests) are unaffected.
    """
    import os

    if os.environ.get("TEST_SESSION_BACKEND") != "postgres":
        yield
        return
    import time

    import psycopg

    import router.session as sess_mod
    from router.pg_session import APPROVALS_TABLE, TABLE, PostgresSessionStore

    url = request.getfixturevalue("pg_url")
    with psycopg.connect(url) as conn:
        conn.execute(f"TRUNCATE {TABLE}, {APPROVALS_TABLE}")
    stores = []

    def build(idle_ttl=1800, tombstone_ttl=86400, clock=time.time):
        store = PostgresSessionStore(
            url, TEST_SESSION_HMAC_KEY, idle_ttl=idle_ttl, tombstone_ttl=tombstone_ttl, clock=clock
        )
        stores.append(store)
        return store

    monkeypatch.setattr(sess_mod, "SessionStore", build)
    monkeypatch.setattr(sess_mod, "_store", build())
    yield
    for store in stores:
        store.close()
