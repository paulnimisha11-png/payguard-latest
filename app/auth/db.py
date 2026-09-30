"""Account storage: Postgres when DATABASE_URL is set (Supabase / Neon / Render Postgres), SQLite otherwise.

Why: Render's free web services wipe their disk on every restart, redeploy and spin-down (after 15 idle minutes),
so accounts kept in the local SQLite file would disappear. A hosted Postgres keeps them. Locally and in tests the
same code runs on SQLite with no setup.

SQL is written once with "?" placeholders; for Postgres they're translated to "%s".
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
IS_PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))

SCHEMA = {
    "users": """CREATE TABLE IF NOT EXISTS pg_users(
        id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL DEFAULT '', phone TEXT,
        pw_hash TEXT NOT NULL, lang TEXT NOT NULL DEFAULT 'en', email_verified INTEGER NOT NULL DEFAULT 0,
        login_alerts INTEGER NOT NULL DEFAULT 1, created DOUBLE PRECISION NOT NULL, last_login DOUBLE PRECISION)""",
    "sessions": """CREATE TABLE IF NOT EXISTS pg_sessions(
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL, created DOUBLE PRECISION NOT NULL, last_seen DOUBLE PRECISION NOT NULL,
        expires DOUBLE PRECISION NOT NULL, device TEXT, ip TEXT)""",
    "sessions_idx": "CREATE INDEX IF NOT EXISTS idx_pg_sessions_user ON pg_sessions(user_id)",
    "tokens": """CREATE TABLE IF NOT EXISTS pg_tokens(
        token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, expires DOUBLE PRECISION NOT NULL,
        used INTEGER NOT NULL DEFAULT 0)""",
    "history_sqlite": """CREATE TABLE IF NOT EXISTS pg_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, created DOUBLE PRECISION NOT NULL, kind TEXT,
        level TEXT, score INTEGER, title TEXT, label TEXT, link TEXT)""",
    "history_pg": """CREATE TABLE IF NOT EXISTS pg_history(
        id BIGSERIAL PRIMARY KEY, user_id TEXT NOT NULL, created DOUBLE PRECISION NOT NULL, kind TEXT,
        level TEXT, score INTEGER, title TEXT, label TEXT, link TEXT)""",
    "history_idx": "CREATE INDEX IF NOT EXISTS idx_pg_history_user ON pg_history(user_id, id)",
    "attempts": """CREATE TABLE IF NOT EXISTS pg_login_attempts(key TEXT NOT NULL, at DOUBLE PRECISION NOT NULL)""",
    "attempts_idx": "CREATE INDEX IF NOT EXISTS idx_pg_attempts ON pg_login_attempts(key, at)",
}


class DB:
    """Tiny thread-safe wrapper. Every call is its own short transaction (autocommit)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._local = threading.local()
        self.kind = "postgres" if IS_PG else "sqlite"
        if not IS_PG:
            from .. import store
            self._sqlite = store._db
            self._sqlite_lock = store._lock
        self.init_schema()

    # ---- connections
    def _pg(self):
        import psycopg
        conn = getattr(self._local, "conn", None)
        if conn is None or conn.closed:
            # prepare_threshold=None: works through Supabase's pgbouncer pooler (transaction mode, port 6543)
            conn = psycopg.connect(DATABASE_URL, autocommit=True, prepare_threshold=None, connect_timeout=10)
            self._local.conn = conn
        return conn

    def _run(self, sql: str, params: tuple, fetch: str | None):
        if IS_PG:
            sql = sql.replace("?", "%s")
            for attempt in (1, 2):
                try:
                    with self._pg().cursor() as cur:
                        cur.execute(sql, params)
                        if fetch == "one":
                            return cur.fetchone()
                        if fetch == "all":
                            return cur.fetchall()
                        return cur.rowcount
                except Exception as e:  # dropped connection (pooler timeout, Supabase pause): reconnect once
                    import psycopg
                    if attempt == 2 or not isinstance(e, (psycopg.OperationalError, psycopg.InterfaceError)):
                        raise
                    self._local.conn = None
        with self._sqlite_lock:
            cur = self._sqlite.execute(sql, params)
            if fetch == "one":
                r = cur.fetchone()
            elif fetch == "all":
                r = cur.fetchall()
            else:
                r = cur.rowcount
            self._sqlite.commit()
            return r

    def exec(self, sql: str, *params) -> int:
        return self._run(sql, params, None)

    def one(self, sql: str, *params):
        return self._run(sql, params, "one")

    def all(self, sql: str, *params) -> list:
        return self._run(sql, params, "all")

    def init_schema(self) -> None:
        for key, ddl in SCHEMA.items():
            if key == "history_sqlite" and IS_PG or key == "history_pg" and not IS_PG:
                continue
            self.exec(ddl)

    def ping(self) -> bool:
        try:
            return self.one("SELECT 1")[0] == 1
        except Exception:
            return False


_db: DB | None = None
_db_lock = threading.Lock()


def db() -> DB:
    global _db
    with _db_lock:
        if _db is None:
            _db = DB()
        return _db


def now() -> float:
    return time.time()
