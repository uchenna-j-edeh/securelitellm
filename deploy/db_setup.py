"""Prepare the production Postgres (infra/rds.tf) for the proxy. Safe to re-run.

Runs as a one-off ECS task before each deploy, with the RDS admin login.
It creates, or brings up to date:

- the ``litellm`` login and database: LiteLLM's virtual keys and usage (#148).
  LiteLLM owns that database and applies its own migrations at startup;
- the ``sessions`` database and its tables (#169), via
  ``router.pg_session.migrate``, with the ``securelitellm_proxy`` login, which
  can read and write the session and approval tables and nothing else.

Neither login can connect to the other's database, and neither can create
roles or databases. (Neither can be a superuser: on RDS the admin isn't one,
and a role created by a non-superuser never is.)

Environment
-----------
DB_HOST, DB_PORT            the RDS endpoint (port defaults to 5432)
DB_ADMIN_SECRET             the RDS-managed admin secret: JSON with
                            "username" and "password"
LITELLM_DB_PASSWORD         password to set for the litellm login
SESSION_DB_PROXY_PASSWORD   password to set for the securelitellm_proxy login
DB_SSLMODE                  default verify-full
DB_SSLROOTCERT              CA bundle for verify-full
                            (default /etc/ssl/rds/global-bundle.pem)
LITELLM_DB_NAME             default litellm
SESSIONS_DB_NAME            default sessions
"""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import quote

LITELLM_ROLE = "litellm"
PROXY_ROLE = "securelitellm_proxy"


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"{name} is not set")
    return value


def _url(user: str, password: str, database: str) -> str:
    host = _required("DB_HOST")
    port = os.environ.get("DB_PORT", "5432")
    sslmode = os.environ.get("DB_SSLMODE", "verify-full")
    query = f"sslmode={sslmode}"
    if sslmode in ("verify-ca", "verify-full"):
        root = os.environ.get("DB_SSLROOTCERT", "/etc/ssl/rds/global-bundle.pem")
        query += f"&sslrootcert={quote(root)}"
    return (
        f"postgresql://{quote(user, safe='')}:{quote(password, safe='')}"
        f"@{host}:{port}/{database}?{query}"
    )


def _set_login(conn, role: str, password: str) -> None:
    from psycopg import sql

    exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
    conn.execute(
        sql.SQL("{} ROLE {} LOGIN NOCREATEDB NOCREATEROLE PASSWORD {}").format(
            sql.SQL("ALTER" if exists else "CREATE"), sql.Identifier(role), sql.Literal(password)
        )
    )


def _create_database(conn, name: str, owner: str | None = None) -> None:
    from psycopg import sql

    if conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,)).fetchone():
        return
    statement = sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name))
    if owner:
        statement += sql.SQL(" OWNER {}").format(sql.Identifier(owner))
    conn.execute(statement)


def setup() -> None:
    import psycopg
    from psycopg import sql

    from router.pg_session import migrate

    litellm_db = os.environ.get("LITELLM_DB_NAME", "litellm")
    sessions_db = os.environ.get("SESSIONS_DB_NAME", "sessions")
    admin = json.loads(_required("DB_ADMIN_SECRET"))
    admin_user, admin_password = admin["username"], admin["password"]
    litellm_password = _required("LITELLM_DB_PASSWORD")
    proxy_password = _required("SESSION_DB_PROXY_PASSWORD")

    # CREATE DATABASE can't run inside a transaction.
    with psycopg.connect(_url(admin_user, admin_password, "postgres"), autocommit=True) as conn:
        _set_login(conn, LITELLM_ROLE, litellm_password)
        # On RDS the admin is not a superuser: to create a database owned by
        # another role it must be a member of that role.
        conn.execute(
            sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(LITELLM_ROLE), sql.Identifier(admin_user)
            )
        )
        _create_database(conn, litellm_db, owner=LITELLM_ROLE)
        _create_database(conn, sessions_db)
        for database in (litellm_db, sessions_db):
            conn.execute(
                sql.SQL("REVOKE CONNECT, TEMPORARY ON DATABASE {} FROM PUBLIC").format(
                    sql.Identifier(database)
                )
            )

    migrate(
        _url(admin_user, admin_password, sessions_db),
        grant_to=PROXY_ROLE,
        role_password=proxy_password,
    )
    with psycopg.connect(_url(admin_user, admin_password, "postgres"), autocommit=True) as conn:
        conn.execute(
            sql.SQL("ALTER ROLE {} NOCREATEDB NOCREATEROLE").format(sql.Identifier(PROXY_ROLE))
        )
        conn.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(sessions_db), sql.Identifier(PROXY_ROLE)
            )
        )
    print(f"databases {litellm_db!r} and {sessions_db!r} are ready")


if __name__ == "__main__":
    sys.path.insert(0, os.environ.get("PYTHONPATH", "/workspace"))
    setup()
