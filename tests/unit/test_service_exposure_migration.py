from __future__ import annotations

import importlib.util
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable

from vulnbatch.db.base import Base
from vulnbatch.db.exposure import ExposureNodeFact
from vulnbatch.db.models import Asset, Role, User
from vulnbatch.exposure.service import apply_graph
from vulnbatch.schemas.exposure import ApplyRequest

NEW_TABLES = {
    "exposure_nodes",
    "exposure_relationships",
    "exposure_attributions",
    "exposure_node_facts",
    "exposure_decisions",
    "exposure_versions",
}


def load_migration(connection: Connection) -> ModuleType:
    path = Path("alembic/versions/0003_service_exposure.py")
    spec = importlib.util.spec_from_file_location("exposure_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.op = Operations(MigrationContext.configure(connection))
    return module


@pytest.fixture
def migrated() -> Iterator[tuple[Engine, Connection, ModuleType, uuid.UUID, uuid.UUID]]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(
        engine, tables=[table for table in Base.metadata.sorted_tables if table.name not in NEW_TABLES]
    )
    with Session(engine) as db:
        role = Role(name="administrator")
        asset = Asset(canonical_hostname="preserved.example.test", notes="Immutable original legacy note")
        db.add_all([role, asset])
        db.flush()
        actor = User(
            username="synthetic-migration",
            display_name="Synthetic",
            password_hash=str(uuid.uuid4()),
            role_id=role.id,
        )
        db.add(actor)
        db.commit()
        actor_id, asset_id = actor.id, asset.id
    with engine.connect() as connection:
        # Existing reconciliation protection must survive the additive upgrade.
        old_spec = importlib.util.spec_from_file_location(
            "prior_migration", Path("alembic/versions/0002_persistent_reconciliation.py")
        )
        assert old_spec and old_spec.loader
        prior = importlib.util.module_from_spec(old_spec)
        old_spec.loader.exec_module(prior)
        prior.op = Operations(MigrationContext.configure(connection))
        prior.upgrade()
        module = load_migration(connection)
        module.upgrade()
        connection.commit()
        yield engine, connection, module, actor_id, asset_id
    engine.dispose()


def test_upgrade_empty_rollback_preserves_legacy_and_prior_triggers(
    migrated: tuple[Engine, Connection, ModuleType, uuid.UUID, uuid.UUID],
) -> None:
    _, connection, migration, _, asset_id = migrated
    before = dict(connection.execute(select(Asset.__table__).where(Asset.id == asset_id)).mappings().one())
    migration.upgrade()
    connection.commit()
    assert set(inspect(connection).get_table_names()) >= NEW_TABLES
    migration.downgrade()
    connection.commit()
    after = dict(connection.execute(select(Asset.__table__).where(Asset.id == asset_id)).mappings().one())
    assert before == after
    assert not NEW_TABLES.intersection(inspect(connection).get_table_names())
    triggers = set(connection.execute(text("SELECT name FROM sqlite_master WHERE type='trigger'")).scalars())
    assert "immutable_source_observations_update" in triggers


def test_fresh_create_all_then_migration_matches_frozen_model() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        migration = load_migration(connection)
        migration.upgrade()
        connection.commit()
    engine.dispose()


def test_populated_rollback_refuses_and_all_immutable_tables_have_triggers(
    migrated: tuple[Engine, Connection, ModuleType, uuid.UUID, uuid.UUID],
) -> None:
    engine, connection, migration, actor_id, asset_id = migrated
    with Session(engine) as db:
        request = ApplyRequest.model_validate(
            {
                "request_key": "synthetic",
                "reason": "Reviewed source",
                "expected_revision": 0,
                "confirmed": True,
                "graph": {
                    "source": "synthetic",
                    "instance": "lab",
                    "nodes": [
                        {
                            "ref": "device",
                            "native_id": "appliance-1",
                            "kind": "device",
                            "label": "Appliance",
                            "asset_id": str(asset_id),
                        }
                    ],
                },
            }
        )
        apply_graph(db, request, actor_id, datetime(2026, 10, 2, tzinfo=UTC))
        db.commit()
    with pytest.raises(RuntimeError, match="evidence"):
        migration.downgrade()
    connection.rollback()
    assert connection.scalar(select(ExposureNodeFact.id)) is not None
    metadata, _ = migration._schema()
    for table in migration.IMMUTABLE_TABLES:
        for action in ["UPDATE", "DELETE"]:
            model = metadata.tables[table]
            statement = model.update().values(id=model.c.id) if action == "UPDATE" else model.delete()
            with pytest.raises(DatabaseError, match="immutable"):
                connection.execute(statement)
            connection.rollback()


def test_frozen_schema_compiles_for_postgresql_and_contains_no_live_models(
    migrated: tuple[Engine, Connection, ModuleType, uuid.UUID, uuid.UUID],
) -> None:
    _, _, migration, _, _ = migrated
    _, tables = migration._schema()
    for table in tables:
        assert str(CreateTable(table).compile(dialect=postgresql.dialect()))
    assert "vulnbatch" not in Path("alembic/versions/0003_service_exposure.py").read_text()


def test_incompatible_existing_exposure_schema_is_rejected(
    migrated: tuple[Engine, Connection, ModuleType, uuid.UUID, uuid.UUID],
) -> None:
    _, connection, migration, _, _ = migrated
    migration.downgrade()
    connection.commit()
    connection.execute(text("CREATE TABLE exposure_nodes (id INTEGER PRIMARY KEY, label VARCHAR(1))"))
    connection.commit()
    with pytest.raises(RuntimeError, match="frozen"):
        migration.upgrade()
