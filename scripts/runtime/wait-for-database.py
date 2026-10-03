from __future__ import annotations

import os
import sys
import time

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError


def main() -> int:
    database_url = os.environ["DATABASE_URL"]
    timeout_seconds = int(os.environ.get("DB_STARTUP_TIMEOUT_SECONDS", "90"))
    deadline = time.monotonic() + timeout_seconds
    engine = create_engine(database_url, pool_pre_ping=True)
    last_error = "unavailable"

    try:
        while time.monotonic() < deadline:
            try:
                with engine.connect() as connection:
                    connection.execute(text("SELECT 1"))
                print("Database connection is ready.", flush=True)
                return 0
            except SQLAlchemyError as exc:
                last_error = type(exc).__name__
                time.sleep(2)
    finally:
        engine.dispose()

    print(
        f"Database did not become ready within {timeout_seconds} seconds ({last_error}).",
        file=sys.stderr,
        flush=True,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
