"""Production database setup (deploy/db_setup.py, infra/rds.tf).

Runs against TEST_SESSION_DB_URL's server with a fresh admin role that,
like the RDS admin, is not a superuser. Skipped without a database.
"""

import json
import secrets
from urllib.parse import urlparse

import psycopg
import pytest

from router.pg_session import APPROVALS_TABLE, TABLE


@pytest.fixture()
def rds_like(pg_url, monkeypatch):
    """A non-superuser admin with CREATEDB and CREATEROLE, as on RDS."""
    target = urlparse(pg_url)
    admin = "rds_admin_test"
    admin_password = secrets.token_urlsafe(16)
    names = ("t_litellm", "t_sessions")
    roles = ("litellm", "securelitellm_proxy", admin)

    def cleanup():
        with psycopg.connect(pg_url, autocommit=True, dbname="postgres") as conn:
            for name in names:
                conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            for role in roles:
                if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                    conn.execute(f'DROP OWNED BY "{role}" CASCADE')
                    conn.execute(f'DROP ROLE "{role}"')

    cleanup()
    with psycopg.connect(pg_url, autocommit=True) as conn:
        conn.execute(
            f"CREATE ROLE {admin} LOGIN CREATEDB CREATEROLE PASSWORD %s".replace("%s", "'%s'")
            % admin_password
        )
    passwords = {"litellm": secrets.token_urlsafe(16), "proxy": secrets.token_urlsafe(16)}
    monkeypatch.setenv("LITELLM_DB_NAME", "t_litellm")
    monkeypatch.setenv("SESSIONS_DB_NAME", "t_sessions")
    monkeypatch.setenv("DB_HOST", target.hostname)
    monkeypatch.setenv("DB_PORT", str(target.port or 5432))
    monkeypatch.setenv("DB_SSLMODE", "disable")
    monkeypatch.setenv(
        "DB_ADMIN_SECRET", json.dumps({"username": admin, "password": admin_password})
    )
    monkeypatch.setenv("LITELLM_DB_PASSWORD", passwords["litellm"])
    monkeypatch.setenv("SESSION_DB_PROXY_PASSWORD", passwords["proxy"])
    yield target, passwords
    cleanup()


def _connect(target, user, password, database):
    return psycopg.connect(
        host=target.hostname,
        port=target.port or 5432,
        user=user,
        password=password,
        dbname=database,
        sslmode="disable",
        autocommit=True,
    )


def _denied(conn, statement):
    try:
        conn.execute(statement)
    except psycopg.errors.InsufficientPrivilege:
        return True
    return False


def test_setup_creates_two_separate_databases_and_logins(rds_like):
    from deploy.db_setup import setup

    target, passwords = rds_like
    setup()
    setup()  # re-running is safe (every deploy runs it)

    with _connect(target, "securelitellm_proxy", passwords["proxy"], "t_sessions") as proxy:
        proxy.execute(f"SELECT count(*) FROM {TABLE}")
        proxy.execute(f"SELECT count(*) FROM {APPROVALS_TABLE}")
        assert _denied(proxy, "CREATE TABLE extra (i int)")
        assert _denied(proxy, f"DROP TABLE {TABLE}")
        assert _denied(proxy, "CREATE ROLE another")
    with pytest.raises(psycopg.OperationalError, match="permission denied"):
        _connect(target, "securelitellm_proxy", passwords["proxy"], "t_litellm")

    with _connect(target, "litellm", passwords["litellm"], "t_litellm") as litellm:
        litellm.execute("CREATE TABLE prisma_like (i int)")  # LiteLLM migrates its own database
        assert _denied(litellm, "CREATE ROLE another")
    with pytest.raises(psycopg.OperationalError, match="permission denied"):
        _connect(target, "litellm", passwords["litellm"], "t_sessions")


def test_rerunning_resets_the_passwords(rds_like, monkeypatch):
    from deploy.db_setup import setup

    target, passwords = rds_like
    setup()
    monkeypatch.setenv("SESSION_DB_PROXY_PASSWORD", "rotated-" + passwords["proxy"])
    setup()
    with pytest.raises(psycopg.OperationalError):
        _connect(target, "securelitellm_proxy", passwords["proxy"], "t_sessions")
    _connect(target, "securelitellm_proxy", "rotated-" + passwords["proxy"], "t_sessions").close()


def test_missing_settings_stop_before_touching_the_database(monkeypatch):
    from deploy.db_setup import setup

    monkeypatch.delenv("DB_ADMIN_SECRET", raising=False)
    with pytest.raises(SystemExit, match="DB_ADMIN_SECRET is not set"):
        setup()


def test_urls_escape_passwords_and_require_verified_tls_by_default(monkeypatch):
    from deploy.db_setup import _url

    monkeypatch.setenv("DB_HOST", "db.internal")
    monkeypatch.delenv("DB_SSLMODE", raising=False)
    monkeypatch.delenv("DB_SSLROOTCERT", raising=False)
    url = _url("admin", "p@ss/word?&", "sessions")
    assert url.startswith("postgresql://admin:p%40ss%2Fword%3F%26@db.internal:5432/sessions?")
    assert "sslmode=verify-full" in url and "sslrootcert=/etc/ssl/rds/global-bundle.pem" in url
