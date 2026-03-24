from __future__ import annotations

import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, func, inspect, select, text

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from server.database import Base, normalize_database_url
from server.models import Activation, ChallengeSession, License, SecurityEvent

TABLES = (
    License.__table__,
    Activation.__table__,
    ChallengeSession.__table__,
    SecurityEvent.__table__,
)


def _require_env(name: str) -> str:
    value = str(os.getenv(name, "")).strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _copy_table(source_conn, target_conn, table) -> int:
    target_count = int(target_conn.execute(select(func.count()).select_from(table)).scalar_one() or 0)
    if target_count > 0:
        print(f"skip {table.name}: target already has {target_count} row(s)")
        return 0

    rows = [dict(row) for row in source_conn.execute(select(table).order_by(table.c.id)).mappings().all()]
    if not rows:
        print(f"skip {table.name}: source is empty")
        return 0

    target_conn.execute(table.insert(), rows)
    print(f"copied {table.name}: {len(rows)} row(s)")
    return len(rows)


def _reset_postgres_sequence(target_conn, table_name: str) -> None:
    target_conn.execute(
        text(
            f"""
            SELECT setval(
                pg_get_serial_sequence('"{table_name}"', 'id'),
                COALESCE((SELECT MAX(id) FROM "{table_name}"), 1),
                true
            )
            """
        )
    )


def main() -> int:
    source_url = normalize_database_url(
        os.getenv("SOURCE_DATABASE_URL", "sqlite:///./license.db")
    )
    target_url = normalize_database_url(_require_env("DATABASE_URL"))

    if not source_url.startswith("sqlite"):
        raise RuntimeError("SOURCE_DATABASE_URL must point to SQLite for this migration script")
    if target_url.startswith("sqlite"):
        raise RuntimeError("DATABASE_URL must point to Postgres for this migration script")

    source_engine = create_engine(source_url)
    target_engine = create_engine(target_url, pool_pre_ping=True)
    Base.metadata.create_all(bind=target_engine)

    source_tables = set(inspect(source_engine).get_table_names())
    if not source_tables:
        raise RuntimeError("Source SQLite database has no tables to migrate")

    total_rows = 0
    with source_engine.connect() as source_conn, target_engine.begin() as target_conn:
        for table in TABLES:
            if table.name not in source_tables:
                print(f"skip {table.name}: source table does not exist")
                continue
            total_rows += _copy_table(source_conn, target_conn, table)

        if target_engine.dialect.name == "postgresql":
            for table in TABLES:
                _reset_postgres_sequence(target_conn, table.name)

    print(f"migration complete: {total_rows} row(s) copied")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"migration failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
