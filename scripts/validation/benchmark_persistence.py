"""In-memory SQLite measurements using synthetic evidence, never a configured database."""

from __future__ import annotations

import json
import time
import tracemalloc
import uuid
from datetime import UTC, datetime

from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session

from vulnbatch.db.base import Base
from vulnbatch.db.models import Asset, Role, User
from vulnbatch.db.reconciliation import ObservationLocator, SourceObservation
from vulnbatch.reconciliation.models import SourceOptions
from vulnbatch.reconciliation.queries import observations
from vulnbatch.reconciliation.storage import ImportDocument, persist_bundle


def main() -> None:
    count = 5000
    rows = []
    for number in range(count):
        asset = {
            "native_id": f"synthetic-{number}",
            "hostname": f"host-{number}.example.test",
            "hardware_uuid": str(uuid.UUID(int=number + 1)),
            "observed_at": "2026-10-01T10:00:00Z",
        }
        rows.extend(
            [
                {**asset, "kind": "inventory"},
                {
                    **asset,
                    "kind": "vulnerability",
                    "vulnerability_id": "CVE-2026-0001",
                    "native_status": "open",
                },
                {**asset, "kind": "coverage", "coverage_outcome": "unreachable", "complete": False},
            ]
        )
    rows.extend(rows[:100])
    rows.extend({"kind": "inventory"} for _ in range(25))
    options = SourceOptions(
        source="inventory", instance="synthetic-benchmark", format="json", time_meaning="source_observed"
    )
    now = datetime(2026, 10, 2, tzinfo=UTC)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    statement_count = 0

    @event.listens_for(engine, "before_cursor_execute")
    def statement(*_: object) -> None:
        nonlocal statement_count
        statement_count += 1

    with Session(engine) as db:
        role = Role(name="administrator")
        db.add(role)
        db.flush()
        user = User(
            username="synthetic", display_name="Synthetic", password_hash=str(uuid.uuid4()), role_id=role.id
        )
        db.add(user)
        db.commit()
        actor = user.id
        statement_count = 0
        tracemalloc.start()
        started = time.perf_counter()
        first = persist_bundle(
            db,
            [ImportDocument("synthetic.json", json.dumps(rows).encode(), options)],
            actor_id=actor,
            request_key="benchmark-first",
            now=now,
        )
        db.commit()
        first_seconds, first_statements = time.perf_counter() - started, statement_count
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        statement_count = 0
        started = time.perf_counter()
        repeated = persist_bundle(
            db,
            [ImportDocument("reordered.json", json.dumps(list(reversed(rows))).encode(), options)],
            actor_id=actor,
            request_key="benchmark-repeat",
            now=now,
        )
        db.commit()
        repeat_seconds, repeat_statements = time.perf_counter() - started, statement_count
        statement_count = 0
        started = time.perf_counter()
        page = observations(db, offset=14_950, limit=50)
        page_seconds, page_statements = time.perf_counter() - started, statement_count
        assert first["new_observations"] == 15_000 and first["error_rows"] == 25
        assert repeated["new_observations"] == 0 and len(page["items"]) == 50
        assert db.scalar(select(func.count()).select_from(Asset)) == count
        assert db.scalar(select(func.count()).select_from(SourceObservation)) == 15_000
        assert db.scalar(select(func.count()).select_from(ObservationLocator)) == 30_200
        print(
            json.dumps(
                {
                    "method": "single in-memory SQLite run; import with tracemalloc; repeat/page without",
                    "assets": count,
                    "input_rows": len(rows),
                    "observations": 15_000,
                    "first_seconds": round(first_seconds, 3),
                    "first_sql_statements": first_statements,
                    "first_peak_python_mib": round(peak / 1024 / 1024, 2),
                    "repeat_seconds": round(repeat_seconds, 3),
                    "repeat_sql_statements": repeat_statements,
                    "page_seconds": round(page_seconds, 3),
                    "page_sql_statements": page_statements,
                    "page_items": len(page["items"]),
                    "repeat_new_observations": repeated["new_observations"],
                },
                indent=2,
            )
        )
    engine.dispose()


if __name__ == "__main__":
    main()
