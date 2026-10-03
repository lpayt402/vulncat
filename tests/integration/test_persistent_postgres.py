"""Disposable PostgreSQL QA. No connection is attempted without the explicit test URL."""

from __future__ import annotations

import importlib.util
import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from fastapi import HTTPException
from sqlalchemy import create_engine, func, inspect, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateSchema, DropSchema
from starlette.requests import Request

from vulnbatch.db.base import Base
from vulnbatch.db.models import Asset, AssetIdentifier, IdentityEvent, Role, User
from vulnbatch.db.reconciliation import AssignmentVersion, CurrentAssignment, SourceObservation
from vulnbatch.reconciliation.decisions import apply_decision
from vulnbatch.reconciliation.models import SourceOptions
from vulnbatch.reconciliation.queries import observations
from vulnbatch.reconciliation.storage import (
    ImportDocument,
    ReconciliationConflict,
    persist_bundle,
)
from vulnbatch.schemas.identity import IdentityReason, MergeRequest
from vulnbatch.schemas.reconciliation import DecisionRequest

URL = os.environ.get("VWB_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL, reason="Set VWB_TEST_DATABASE_URL to a disposable PostgreSQL database"),
]
NOW = datetime(2026, 10, 2, tzinfo=UTC)
NEW_TABLES = {
    "reconciliation_state",
    "reconciliation_source_instances",
    "reconciliation_batches",
    "source_observations",
    "observation_locators",
    "observation_native_ids",
    "vulnerability_occurrences",
    "coverage_observations",
    "reconciliation_decisions",
    "asset_observation_assignments",
    "asset_assignment_versions",
}


def migration(connection: Any, filename: str = "0002_persistent_reconciliation.py") -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "migration_" + uuid.uuid4().hex, Path("alembic/versions") / filename
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.op = Operations(MigrationContext.configure(connection))
    return module


@pytest.fixture
def database() -> Any:
    assert URL is not None and URL.startswith("postgresql"), (
        "QA requires an explicitly supplied disposable PostgreSQL URL"
    )
    schema = "vwb_test_" + uuid.uuid4().hex
    root = create_engine(URL)
    with root.begin() as connection:
        connection.execute(CreateSchema(schema))
    engine = create_engine(URL, connect_args={"options": f"-csearch_path={schema}"})
    Base.metadata.create_all(
        engine,
        tables=[
            table for table in Base.metadata.sorted_tables
            if table.name not in NEW_TABLES and not table.name.startswith("exposure_")
        ],
    )
    with Session(engine, expire_on_commit=False) as db:
        role = Role(name="administrator")
        asset = Asset(canonical_hostname="legacy.example.test", notes="Preserve legacy evidence")
        db.add_all([role, asset])
        db.flush()
        user = User(
            username="synthetic", display_name="Synthetic", password_hash=str(uuid.uuid4()), role_id=role.id
        )
        db.add(user)
        db.commit()
        actor_id, legacy_id = user.id, asset.id
    with engine.begin() as connection:
        migration(connection).upgrade()
        migration(connection, "0003_service_exposure.py").upgrade()
    yield engine, actor_id, legacy_id
    engine.dispose()
    with root.begin() as connection:
        connection.execute(DropSchema(schema, cascade=True))  # Disposable UUID-named schema only.
    root.dispose()


def document(rows: list[dict[str, Any]] | None = None) -> ImportDocument:
    config = SourceOptions(
        source="crowdstrike", instance="synthetic", format="json", time_meaning="source_observed"
    )
    return ImportDocument(
        "synthetic.json",
        json.dumps(
            rows
            or [{"native_id": "agent-a", "hostname": "a.example.test", "observed_at": "2026-10-01T10:00:00Z"}]
        ).encode(),
        config,
    )


def import_once(
    engine: Engine, actor: uuid.UUID, key: str = "first", doc: ImportDocument | None = None
) -> dict[str, Any]:
    with Session(engine) as db:
        result = persist_bundle(db, [doc or document()], actor_id=actor, request_key=key, now=NOW)
        db.commit()
        return result


def test_postgres_migration_and_empty_rollback_preserve_populated_legacy(database: Any) -> None:
    engine, _, legacy_id = database
    with engine.begin() as connection:
        before = dict(
            connection.execute(select(Asset.__table__).where(Asset.id == legacy_id)).mappings().one()
        )
        migration(connection).upgrade()
        migration(connection, "0003_service_exposure.py").downgrade()
        migration(connection).downgrade()
        assert not NEW_TABLES.intersection(inspect(connection).get_table_names())
        assert (
            dict(connection.execute(select(Asset.__table__).where(Asset.id == legacy_id)).mappings().one())
            == before
        )
        migration(connection).upgrade()
        migration(connection, "0003_service_exposure.py").upgrade()


def test_postgres_bad_rows_do_not_abort_later_supported_rows(database: Any) -> None:
    engine, actor, _ = database
    rows = [
        {"native_id": "x" * 513},
        {"native_id": "bad-status", "native_status": "x" * 129},
        {"native_id": "nul\x00id"},
        {"native_id": "valid", "observed_at": "2026-10-01T10:00:00Z"},
    ]
    result = import_once(engine, actor, doc=document(rows))
    assert result["error_rows"] == 3
    assert result["new_observations"] == 1
    with Session(engine) as db:
        assert observations(db)["total"] == 1


def test_postgres_page_revision_is_conservative_across_an_interleaved_commit(
    database: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vulnbatch.reconciliation import queries
    from vulnbatch.reconciliation.storage import revision

    engine, actor, _ = database
    import_once(engine, actor)

    def interleave(db: Session) -> int:
        value = revision(db)
        import_once(engine, actor, key="later", doc=document([{"native_id": "later"}]))
        return value

    monkeypatch.setattr(queries, "revision", interleave)
    with Session(engine) as db:
        page = observations(db)
        item = page["items"][0]
        assert page["revision"] == 1
        assert page["total"] == 2
        payload = DecisionRequest(
            request_key="stale-page",
            action="reject",
            expected_revision=page["revision"],
            reason="Synthetic interleaved page",
            observation_ids=[uuid.UUID(item["id"])],
            expected_versions={item["id"]: item["version"]},
        )
        with pytest.raises(ReconciliationConflict, match="changed"):
            apply_decision(db, payload, actor_id=actor, now=NOW)
        db.rollback()


def test_postgres_replayed_imports_are_one_atomic_batch(database: Any) -> None:
    engine, actor, _ = database
    gate = threading.Barrier(2)

    def run() -> dict[str, Any]:
        gate.wait(timeout=10)
        return import_once(engine, actor)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: run(), range(2)))
    assert len({result["id"] for result in results}) == 1
    assert sorted(result["replayed"] for result in results) == [False, True]
    with Session(engine) as db:
        assert observations(db)["total"] == 1
        assert db.scalar(select(func.count()).select_from(AssignmentVersion)) == 1


def test_postgres_unnamed_asset_uuid_and_fallback_search(database: Any) -> None:
    from vulnbatch.reconciliation.queries import assets

    engine, actor, _ = database
    import_once(engine, actor, doc=document([{"native_id": "unnamed-a"}, {"native_id": "unnamed-b"}]))
    with Session(engine) as db:
        page = assets(db, limit=1)
        assert page["total"] == 3 and len(page["items"]) == 1
        choices = assets(db)["items"]
        for choice in choices:
            for query in (choice["id"], choice["id"][:8], choice["display_name"]):
                assert any(item["id"] == choice["id"] for item in assets(db, q=query)["items"])


def test_postgres_preview_rejects_an_interleaved_commit(
    database: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vulnbatch.reconciliation import storage

    engine, actor, _ = database
    original = storage.matching_index

    def once(db: Session) -> Any:
        index = original(db)
        with monkeypatch.context() as isolated:
            isolated.setattr(storage, "matching_index", original)
            import_once(engine, actor, key="interleaved")
        return index

    monkeypatch.setattr(storage, "matching_index", once)
    with Session(engine) as db, pytest.raises(ReconciliationConflict, match="during preview"):
        storage.preview_bundle(db, [document()], now=NOW, actor_id=actor)


@pytest.mark.parametrize("same_key", [False, True])
def test_postgres_preview_guard_serializes_competing_saves(database: Any, same_key: bool) -> None:
    from vulnbatch.reconciliation.storage import preview_bundle

    engine, actor, _ = database
    doc = document()
    with Session(engine) as db:
        preview = preview_bundle(db, [doc], now=NOW, actor_id=actor)
    gate = threading.Barrier(2)

    def run(number: int) -> dict[str, Any] | str:
        with Session(engine) as db:
            gate.wait(timeout=10)
            try:
                result = persist_bundle(
                    db,
                    [doc],
                    actor_id=actor,
                    request_key="same" if same_key else f"save-{number}",
                    now=NOW,
                    expected_revision=preview.revision,
                    preview_token=preview.preview_token,
                )
                db.commit()
                return result
            except ReconciliationConflict:
                db.rollback()
                return "conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(run, range(2)))
    if same_key:
        assert len({item["id"] for item in results if isinstance(item, dict)}) == 1
        assert sorted(item["replayed"] for item in results if isinstance(item, dict)) == [False, True]
    else:
        assert results.count("conflict") == 1
    with Session(engine) as db:
        assert observations(db)["total"] == 1


def test_postgres_legacy_alias_edit_invalidates_signed_preview(database: Any) -> None:
    from vulnbatch.api.deps import Principal
    from vulnbatch.api.routes.identity import mark_identifier_shared
    from vulnbatch.reconciliation.storage import preview_bundle

    engine, actor, legacy_id = database
    with Session(engine) as db:
        identifier = AssetIdentifier(
            asset_id=legacy_id,
            identifier_type="ipv4",
            normalized_value="192.0.2.45",
            original_value="192.0.2.45",
            first_observed_at=NOW,
            last_observed_at=NOW,
        )
        db.add(identifier)
        db.commit()
        identifier_id = identifier.id
        proposed = preview_bundle(db, [document()], now=NOW, actor_id=actor)
    principal = cast(Principal, SimpleNamespace(user=SimpleNamespace(id=actor)))
    request = Request({"type": "http", "client": ("127.0.0.1", 1), "headers": []})
    with Session(engine) as writer:
        mark_identifier_shared(
            identifier_id, IdentityReason(reason="Synthetic legacy edit"), request, principal, writer
        )
    with Session(engine) as db, pytest.raises(ReconciliationConflict, match="after preview"):
        persist_bundle(
            db,
            [document()],
            actor_id=actor,
            request_key="stale-legacy",
            now=NOW,
            preview_token=proposed.preview_token,
        )
    with Session(engine) as db:
        assert observations(db)["total"] == 0


def test_postgres_preview_refreshes_cached_assignment(database: Any) -> None:
    from vulnbatch.reconciliation.storage import preview_bundle

    engine, actor, _ = database
    import_once(engine, actor)
    with Session(engine, expire_on_commit=False) as reader:
        item = observations(reader)["items"][0]
        held = reader.get(CurrentAssignment, uuid.UUID(item["id"]))
        reader.commit()
        with Session(engine) as writer:
            apply_decision(
                writer,
                DecisionRequest(
                    request_key="other-session",
                    expected_revision=1,
                    action="reject",
                    reason="Synthetic rejection",
                    observation_ids=[uuid.UUID(item["id"])],
                    expected_versions={item["id"]: 1},
                ),
                actor_id=actor,
                now=NOW,
            )
            writer.commit()
        assert held is not None and held.version == 1
        proposed = preview_bundle(reader, [document()], now=NOW, actor_id=actor)
        retained = proposed.items[0].current_assignment
        assert proposed.revision == 2 and retained is not None
        assert retained["version"] == 2 and retained["review_status"] == "rejected"


@pytest.mark.parametrize("same_key", [False, True])
def test_postgres_concurrent_decisions_replay_or_reject_stale_state(database: Any, same_key: bool) -> None:
    engine, actor, _ = database
    import_once(engine, actor)
    with Session(engine) as db:
        item = observations(db)["items"][0]
    gate = threading.Barrier(2)

    def run(number: int) -> dict[str, Any] | str:
        payload = DecisionRequest(
            request_key="same" if same_key else f"decision-{number}",
            action="reject",
            expected_revision=1,
            reason="Synthetic concurrent decision",
            observation_ids=[uuid.UUID(item["id"])],
            expected_versions={item["id"]: 1},
        )
        with Session(engine) as db:
            gate.wait(timeout=10)
            try:
                result = apply_decision(db, payload, actor_id=actor, now=NOW)
                db.commit()
                return result
            except ReconciliationConflict:
                db.rollback()
                return "conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(run, range(2)))
    if same_key:
        assert all(isinstance(result, dict) for result in results)
        assert len({result["id"] for result in results if isinstance(result, dict)}) == 1
    else:
        assert results.count("conflict") == 1
    with Session(engine) as db:
        assert observations(db)["items"][0]["version"] == 2
        assert db.scalar(select(func.count()).select_from(AssignmentVersion)) == 2


def test_postgres_triggers_and_populated_rollback_protect_evidence(database: Any) -> None:
    engine, actor, _ = database
    import_once(engine, actor)
    with engine.begin() as connection, pytest.raises(RuntimeError, match="evidence"):
        migration(connection).downgrade()
    with (
        engine.begin() as connection,
        pytest.raises(DatabaseError, match="immutable"),
        connection.begin_nested(),
    ):
        connection.execute(update(SourceObservation).values(parser_version="tampered"))
    with Session(engine) as db:
        assert observations(db)["items"][0]["observation"]["provenance"]["parser_version"] == "offline-v2"


def test_postgres_downgrade_waits_for_ingestion_then_refuses_evidence_deletion(database: Any) -> None:
    engine, actor, _ = database
    with Session(engine) as writer:
        persist_bundle(writer, [document()], actor_id=actor, request_key="pending", now=NOW)
        started = threading.Event()

        def downgrade() -> str:
            with engine.begin() as connection:
                started.set()
                try:
                    migration(connection).downgrade()
                except RuntimeError:
                    return "refused"
                return "dropped"

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(downgrade)
            assert started.wait(timeout=10)
            assert not future.done()
            writer.commit()
            assert future.result(timeout=20) == "refused"
    with Session(engine) as db:
        assert observations(db)["total"] == 1


@pytest.mark.parametrize("operation", ["merge", "split_undo"])
def test_postgres_assignment_and_legacy_retirement_share_one_lock(database: Any, operation: str) -> None:
    from vulnbatch.api.deps import Principal
    from vulnbatch.api.routes.identity import merge_assets, undo_identity_event

    engine, actor, legacy_id = database
    import_once(engine, actor)
    with Session(engine, expire_on_commit=False) as db:
        item = observations(db)["items"][0]
        target = Asset(canonical_hostname="target.example.test")
        db.add(target)
        db.flush()
        target_id = target.id
        event_id = uuid.uuid4()
        if operation == "split_undo":
            identifier = AssetIdentifier(
                asset_id=legacy_id,
                identifier_type="fqdn",
                normalized_value="legacy.example.test",
                original_value="legacy.example.test",
                first_observed_at=NOW,
                last_observed_at=NOW,
            )
            db.add(identifier)
            db.flush()
            # The persistence guard must reject before any legacy inverse is evaluated.
            db.add(
                IdentityEvent(
                    id=event_id,
                    event_type="split_identifier",
                    actor_user_id=actor,
                    primary_asset_id=legacy_id,
                    secondary_asset_id=target_id,
                    reversible=True,
                    payload={
                        "created_asset_id": str(legacy_id),
                        "from_asset_id": str(target_id),
                        "identifier_id": str(identifier.id),
                    },
                )
            )
        db.commit()
    principal = cast(Principal, SimpleNamespace(user=SimpleNamespace(id=actor)))
    request = Request({"type": "http", "client": ("127.0.0.1", 1), "headers": []})
    with Session(engine) as writer:
        payload = DecisionRequest(
            request_key="assign-legacy",
            action="assign",
            expected_revision=1,
            reason="Synthetic reviewed association",
            observation_ids=[uuid.UUID(item["id"])],
            expected_versions={item["id"]: 1},
            target_asset_id=legacy_id,
        )
        apply_decision(writer, payload, actor_id=actor, now=NOW)
        started = threading.Event()

        def retire() -> int:
            with Session(engine) as db:
                started.set()
                try:
                    if operation == "merge":
                        merge_assets(
                            MergeRequest(
                                source_asset_id=legacy_id,
                                target_asset_id=target_id,
                                reason="Synthetic concurrent merge",
                            ),
                            request,
                            principal,
                            db,
                        )
                    else:
                        undo_identity_event(
                            event_id,
                            IdentityReason(reason="Synthetic concurrent undo"),
                            request,
                            principal,
                            db,
                        )
                    return 200
                except HTTPException as exc:
                    db.rollback()
                    return exc.status_code

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(retire)
            assert started.wait(timeout=10)
            assert not future.done()
            writer.commit()
            assert future.result(timeout=20) == 409
    with Session(engine) as db:
        asset = db.get(Asset, legacy_id)
        assert asset is not None and asset.active and asset.merged_into_id is None
        assert db.get(CurrentAssignment, uuid.UUID(item["id"])).asset_id == legacy_id


@pytest.mark.load
def test_postgres_thousands_of_observations_and_repeat_export(database: Any) -> None:
    engine, actor, _ = database
    rows = [
        {
            "native_id": f"synthetic-{number}",
            "hostname": f"host-{number}.example.test",
            "observed_at": "2026-10-01T00:00:00Z",
        }
        for number in range(5000)
    ]
    first = import_once(engine, actor, doc=document(rows))
    repeated = import_once(engine, actor, key="repeat-export", doc=document(list(reversed(rows))))
    assert first["new_observations"] == 5000 and repeated["new_observations"] == 0
    with Session(engine) as db:
        result = observations(db, offset=4950, limit=50)
        assert result["total"] == 5000 and len(result["items"]) == 50
