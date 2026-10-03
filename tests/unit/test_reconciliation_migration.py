from __future__ import annotations

import importlib.util
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable

from vulnbatch.db.base import Base
from vulnbatch.db.models import Asset, Role, User
from vulnbatch.db.reconciliation import SourceObservation
from vulnbatch.reconciliation.models import SourceOptions
from vulnbatch.reconciliation.storage import ImportDocument, persist_bundle

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


@pytest.fixture
def migrated() -> Iterator[tuple[Engine, Connection, ModuleType, uuid.UUID, uuid.UUID]]:
    path = Path("alembic/versions/0002_persistent_reconciliation.py")
    assert path.exists(), "Additive persistent migration is not implemented"
    spec = importlib.util.spec_from_file_location("persistent_migration", path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = create_engine("sqlite://")

    def enable_fk(connection: object, _: object) -> None:
        connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[attr-defined]

    event.listen(engine, "connect", enable_fk)
    Base.metadata.create_all(
        engine,
        tables=[
            table for table in Base.metadata.sorted_tables
            if table.name not in NEW_TABLES and not table.name.startswith("exposure_")
        ],
    )
    with Session(engine) as db:
        role = Role(name="administrator")
        asset = Asset(canonical_hostname="legacy.example.test", notes="Preserve this legacy row")
        db.add_all([role, asset])
        db.flush()
        user = User(
            username="synthetic-migration",
            display_name="Synthetic",
            password_hash=str(uuid.uuid4()),
            role_id=role.id,
        )
        db.add(user)
        db.commit()
        actor_id, asset_id = user.id, asset.id
    with engine.connect() as connection:
        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()
        connection.commit()
        yield engine, connection, migration, actor_id, asset_id
    engine.dispose()


def test_populated_legacy_upgrade_and_empty_downgrade_preserve_data(
    migrated: tuple[Engine, Connection, ModuleType, uuid.UUID, uuid.UUID],
) -> None:
    _, connection, migration, _, asset_id = migrated
    assert set(inspect(connection).get_table_names()) >= NEW_TABLES
    migration.upgrade()  # Handles the initial revision's dynamic create-all safely.
    connection.commit()
    before = connection.execute(select(Asset.__table__).where(Asset.id == asset_id)).mappings().one()
    migration.downgrade()
    connection.commit()
    assert not NEW_TABLES.intersection(inspect(connection).get_table_names())
    after = connection.execute(select(Asset.__table__).where(Asset.id == asset_id)).mappings().one()
    assert dict(before) == dict(after)


def test_populated_downgrade_refuses_to_delete_evidence(
    migrated: tuple[Engine, Connection, ModuleType, uuid.UUID, uuid.UUID],
) -> None:
    engine, connection, migration, actor_id, _ = migrated
    config = SourceOptions(source="inventory", instance="synthetic", format="json")
    with Session(engine) as db:
        persist_bundle(
            db,
            [ImportDocument("synthetic.json", json.dumps([{"native_id": "one"}]).encode(), config)],
            actor_id=actor_id,
            request_key="migration-evidence",
            now=datetime(2026, 10, 2, tzinfo=UTC),
        )
        db.commit()
    with pytest.raises(RuntimeError, match=r"evidence|restore"):
        migration.downgrade()
    connection.rollback()
    assert set(inspect(connection).get_table_names()) >= NEW_TABLES
    assert connection.scalar(select(SourceObservation.id)) is not None


def test_migration_installs_database_immutability_triggers(
    migrated: tuple[Engine, Connection, ModuleType, uuid.UUID, uuid.UUID],
) -> None:
    _, connection, _, _, _ = migrated
    triggers = connection.execute(text("SELECT name FROM sqlite_master WHERE type='trigger'")).scalars().all()
    assert "immutable_source_observations_update" in triggers
    connection.execute(
        text(
            "INSERT INTO reconciliation_source_instances (id, source, label) "
            "VALUES ('00000000000000000000000000000001','inventory','synthetic')"
        )
    )
    with pytest.raises(DatabaseError, match="immutable"):
        connection.execute(text("UPDATE reconciliation_source_instances SET label = 'changed'"))


def test_frozen_revision_compiles_for_postgresql_without_identifier_overflow(
    migrated: tuple[Engine, Connection, ModuleType, uuid.UUID, uuid.UUID],
) -> None:
    _, _, migration, _, _ = migrated
    _, tables = migration._schema()
    for table in tables:
        assert str(CreateTable(table).compile(dialect=postgresql.dialect()))


def test_existing_malformed_additive_table_is_rejected(
    migrated: tuple[Engine, Connection, ModuleType, uuid.UUID, uuid.UUID],
) -> None:
    _, connection, migration, _, _ = migrated
    migration.downgrade()
    connection.commit()
    connection.execute(
        text(
            "CREATE TABLE reconciliation_source_instances (id INTEGER NOT NULL PRIMARY KEY, "
            "source VARCHAR(1) NOT NULL, label VARCHAR(1) NOT NULL, UNIQUE(source,label))"
        )
    )
    connection.commit()
    with pytest.raises(RuntimeError, match=r"frozen|schema|type"):
        migration.upgrade()
