"""Actual PostgreSQL protections and concurrent service/reconciliation mutations."""

from __future__ import annotations

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session
from test_persistent_postgres import database as database
from test_persistent_postgres import document, import_once, migration

from vulnbatch.db.exposure import ExposureDecision, ExposureNode, ExposureNodeFact, ExposureVersion
from vulnbatch.db.models import Asset
from vulnbatch.db.reconciliation import SourceObservation
from vulnbatch.exposure import service
from vulnbatch.reconciliation.storage import ReconciliationConflict
from vulnbatch.schemas.exposure import ApplyRequest, GraphEnvelope, UndoRequest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("VWB_TEST_DATABASE_URL"), reason="Requires the explicit disposable PostgreSQL URL"
    ),
]
NOW = datetime(2026, 10, 2, tzinfo=UTC)


def graph(asset_id: uuid.UUID | None = None) -> GraphEnvelope:
    return GraphEnvelope.model_validate(
        {
            "source": "fictional",
            "instance": "pg-qa",
            "observed_at": "2026-10-01T00:00:00Z",
            "time_meaning": "source_observed",
            "nodes": [
                {
                    "ref": "host",
                    "native_id": "host",
                    "kind": "host",
                    "label": "Fictional host",
                    "asset_id": str(asset_id) if asset_id else None,
                }
            ],
        }
    )


def request(engine: Any, actor: uuid.UUID, key: str, asset_id: uuid.UUID | None = None) -> ApplyRequest:
    envelope = graph(asset_id)
    with Session(engine) as db:
        preview = service.preview(db, envelope, actor, NOW)
    return ApplyRequest(
        graph=envelope,
        request_key=key,
        reason="Reviewed fictional PG evidence",
        confirmed=True,
        expected_revision=preview["revision"],
        preview_token=preview["preview_token"],
    )


def test_populated_service_migration_and_database_immutability(database: Any) -> None:
    engine, actor, asset_id = database
    import_once(engine, actor)
    payload = request(engine, actor, "pg-facts", asset_id)
    with Session(engine) as db:
        applied = service.apply_graph(db, payload, actor, NOW)
        db.commit()
        original = db.get(Asset, asset_id).notes
        source = db.scalar(select(SourceObservation)).normalized
    with engine.begin() as connection:
        assert (
            len([name for name in inspect(connection).get_table_names() if name.startswith("exposure_")]) == 6
        )
        migration(connection, "0003_service_exposure.py").upgrade()
    for table in ("exposure_decisions", "exposure_node_facts", "exposure_versions"):
        with engine.connect() as connection:
            with pytest.raises(DatabaseError, match="immutable"):
                # Fixed table allowlist, no user input.
                connection.execute(text(f"DELETE FROM {table}"))  # noqa: S608 -- fixed table allowlist
            connection.rollback()
    with engine.connect() as connection:
        with pytest.raises(RuntimeError, match=r"populated|evidence|data"):
            migration(connection, "0003_service_exposure.py").downgrade()
        connection.rollback()
    with Session(engine) as db:
        assert db.get(Asset, asset_id).notes == original
        assert db.scalar(select(SourceObservation)).normalized == source
        decision = db.get(ExposureDecision, uuid.UUID(applied["decision_id"]))
        assert decision is not None
        result = service.undo(
            db,
            UndoRequest(
                decision_id=decision.id,
                request_key="pg-undo",
                reason="Reviewed fictional undo",
                expected_revision=applied["revision"],
                confirmed=True,
            ),
            actor,
            NOW,
        )
        db.commit()
        assert result["revision"] > applied["revision"]
        assert db.scalar(select(ExposureNodeFact)) is not None
        assert db.scalar(select(ExposureVersion)) is not None


def test_concurrent_same_key_replays_and_import_invalidates_preview(database: Any) -> None:
    engine, actor, _ = database
    payload = request(engine, actor, "pg-concurrent")

    def write() -> dict[str, Any]:
        with Session(engine) as db:
            result = service.apply_graph(db, payload, actor, NOW)
            db.commit()
            return result

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: write(), range(2)))
    assert {result["replayed"] for result in results} == {False, True}
    assert len({result["decision_id"] for result in results}) == 1
    with Session(engine) as db:
        node = db.scalar(select(ExposureNode))
        delta = graph().model_copy(
            update={
                "nodes": [
                    graph()
                    .nodes[0]
                    .model_copy(update={"expected_version": node.version, "label": "Reviewed rename"})
                ]
            }
        )
        preview = service.preview(db, delta, actor, NOW)
    import_once(engine, actor, key="competing-import", doc=document())
    stale = ApplyRequest(
        graph=delta,
        request_key="pg-stale",
        reason="Stale preview",
        confirmed=True,
        expected_revision=preview["revision"],
        preview_token=preview["preview_token"],
    )
    with Session(engine) as db:
        with pytest.raises(ReconciliationConflict, match=r"revision|changed"):
            service.apply_graph(db, stale, actor, NOW)
        db.rollback()
        assert db.scalar(select(ExposureNode)).label == "Fictional host"
