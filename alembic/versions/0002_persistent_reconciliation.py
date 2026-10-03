"""Additive immutable offline evidence and versioned assignments. Frozen schema definitions."""

from __future__ import annotations

import re

import sqlalchemy as sa
from alembic import op

revision = "0002_persistent_reconciliation"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None

IMMUTABLE_TABLES = (
    "reconciliation_source_instances",
    "reconciliation_batches",
    "source_observations",
    "observation_locators",
    "observation_native_ids",
    "vulnerability_occurrences",
    "coverage_observations",
    "reconciliation_decisions",
    "asset_assignment_versions",
)


def _schema() -> tuple[sa.MetaData, list[sa.Table]]:
    metadata = sa.MetaData()
    sa.Table("assets", metadata, sa.Column("id", sa.Uuid(), primary_key=True))
    sa.Table("users", metadata, sa.Column("id", sa.Uuid(), primary_key=True))
    tables = []
    table = sa.Table(
        "reconciliation_source_instances",
        metadata,
        sa.Column("source", sa.String(32), nullable=False, primary_key=False),
        sa.Column("label", sa.String(128), nullable=False, primary_key=False),
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False, primary_key=True),
        sa.UniqueConstraint(
            "source", "label", name=sa.schema.conv("uq_reconciliation_source_instances_source")
        ),
    )
    tables.append(table)
    table = sa.Table(
        "reconciliation_state",
        metadata,
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False, primary_key=False),
        sa.CheckConstraint(
            "id = 1 AND revision >= 0", name=sa.schema.conv("ck_reconciliation_state_singleton_revision")
        ),
    )
    tables.append(table)
    table = sa.Table(
        "source_observations",
        metadata,
        sa.Column("fingerprint", sa.String(64), nullable=False, primary_key=False),
        sa.Column(
            "source_instance_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "reconciliation_source_instances.id",
                name=sa.schema.conv(
                    "fk_source_observations_source_instance_id_reconciliation_source_instances"
                ),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column("kind", sa.String(16), nullable=False, primary_key=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True, primary_key=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=True, primary_key=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False, primary_key=False),
        sa.Column("parser_version", sa.String(64), nullable=False, primary_key=False),
        sa.Column("normalized", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False, primary_key=True),
        sa.CheckConstraint(
            "kind IN ('inventory','vulnerability','coverage')",
            name=sa.schema.conv("ck_source_observations_observation_kind"),
        ),
        sa.UniqueConstraint("fingerprint", name=sa.schema.conv("uq_source_observations_fingerprint")),
    )
    sa.Index("ix_source_observations_kind", table.c.kind, unique=False)
    sa.Index("ix_source_observations_import_order", table.c.imported_at, table.c.id, unique=False)
    sa.Index("ix_source_observations_observed_at", table.c.observed_at, unique=False)
    sa.Index("ix_source_observations_source_instance_id", table.c.source_instance_id, unique=False)
    tables.append(table)
    table = sa.Table(
        "asset_observation_assignments",
        metadata,
        sa.Column(
            "observation_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "source_observations.id",
                name=sa.schema.conv("fk_asset_observation_assignments_observation_id_source_observations"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=True,
        ),
        sa.Column(
            "asset_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "assets.id",
                name=sa.schema.conv("fk_asset_observation_assignments_asset_id_assets"),
                ondelete="RESTRICT",
            ),
            nullable=True,
            primary_key=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False, primary_key=False),
        sa.Column("review_status", sa.String(16), nullable=False, primary_key=False),
        sa.Column("rule", sa.String(128), nullable=False, primary_key=False),
        sa.Column("explanation", sa.Text(), nullable=False, primary_key=False),
        sa.Column("confidence", sa.Float(), nullable=False, primary_key=False),
        sa.Column("candidate_ids", sa.JSON(), nullable=False, primary_key=False),
        sa.CheckConstraint(
            "(review_status = 'assigned' AND asset_id IS NOT NULL) OR (review_status <> 'assigned' AND asset_id IS NULL)",
            name=sa.schema.conv("ck_asset_observation_assignments_assignment_status_asset"),
        ),
        sa.CheckConstraint(
            "version >= 1", name=sa.schema.conv("ck_asset_observation_assignments_positive_version")
        ),
        sa.CheckConstraint(
            "review_status IN ('open','deferred','assigned','rejected')",
            name=sa.schema.conv("ck_asset_observation_assignments_review_status"),
        ),
    )
    sa.Index("ix_asset_observation_assignments_asset_id", table.c.asset_id, unique=False)
    sa.Index("ix_asset_observation_assignments_review_status", table.c.review_status, unique=False)
    tables.append(table)
    table = sa.Table(
        "coverage_observations",
        metadata,
        sa.Column(
            "observation_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "source_observations.id",
                name=sa.schema.conv("fk_coverage_observations_observation_id_source_observations"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=True,
        ),
        sa.Column("outcome", sa.String(32), nullable=False, primary_key=False),
        sa.Column("complete", sa.Boolean(), nullable=False, primary_key=False),
        sa.Column("authenticated", sa.Boolean(), nullable=True, primary_key=False),
        sa.Column("evidence", sa.JSON(), nullable=False, primary_key=False),
    )
    sa.Index("ix_coverage_observations_outcome", table.c.outcome, unique=False)
    tables.append(table)
    table = sa.Table(
        "observation_native_ids",
        metadata,
        sa.Column(
            "observation_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "source_observations.id",
                name=sa.schema.conv("fk_observation_native_ids_observation_id_source_observations"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column(
            "source_instance_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "reconciliation_source_instances.id",
                name=sa.schema.conv(
                    "fk_observation_native_ids_source_instance_id_reconciliation_source_instances"
                ),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column("kind", sa.String(128), nullable=False, primary_key=False),
        sa.Column("value", sa.String(512), nullable=False, primary_key=False),
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False, primary_key=True),
        sa.UniqueConstraint(
            "observation_id",
            "source_instance_id",
            "kind",
            "value",
            name=sa.schema.conv("uq_observation_native_ids_observation_id"),
        ),
    )
    sa.Index("ix_observation_native_ids_kind", table.c.kind, unique=False)
    sa.Index("ix_observation_native_ids_observation_id", table.c.observation_id, unique=False)
    sa.Index("ix_observation_native_ids_source_instance_id", table.c.source_instance_id, unique=False)
    sa.Index("ix_observation_native_ids_value", table.c.value, unique=False)
    sa.Index(
        "ix_observation_native_scoped_value",
        table.c.source_instance_id,
        table.c.kind,
        table.c.value,
        unique=False,
    )
    tables.append(table)
    table = sa.Table(
        "reconciliation_batches",
        metadata,
        sa.Column("request_key", sa.String(128), nullable=False, primary_key=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False, primary_key=False),
        sa.Column(
            "actor_user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "users.id",
                name=sa.schema.conv("fk_reconciliation_batches_actor_user_id_users"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False, primary_key=False),
        sa.Column("files", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("result", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False, primary_key=True),
        sa.UniqueConstraint("request_key", name=sa.schema.conv("uq_reconciliation_batches_request_key")),
    )
    tables.append(table)
    table = sa.Table(
        "reconciliation_decisions",
        metadata,
        sa.Column("request_key", sa.String(160), nullable=False, primary_key=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False, primary_key=False),
        sa.Column("action", sa.String(32), nullable=False, primary_key=False),
        sa.Column(
            "actor_user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "users.id",
                name=sa.schema.conv("fk_reconciliation_decisions_actor_user_id_users"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, primary_key=False),
        sa.Column("reason", sa.Text(), nullable=False, primary_key=False),
        sa.Column(
            "undo_of_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "reconciliation_decisions.id",
                name=sa.schema.conv("fk_reconciliation_decisions_undo_of_id_reconciliation_decisions"),
                ondelete="RESTRICT",
            ),
            nullable=True,
            primary_key=False,
        ),
        sa.Column("changes", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("result", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False, primary_key=True),
        sa.UniqueConstraint("request_key", name=sa.schema.conv("uq_reconciliation_decisions_request_key")),
        sa.UniqueConstraint("undo_of_id", name=sa.schema.conv("uq_reconciliation_decisions_undo_of_id")),
    )
    sa.Index("ix_reconciliation_decisions_action", table.c.action, unique=False)
    sa.Index("ix_reconciliation_decisions_occurred_at", table.c.occurred_at, unique=False)
    tables.append(table)
    table = sa.Table(
        "vulnerability_occurrences",
        metadata,
        sa.Column(
            "observation_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "source_observations.id",
                name=sa.schema.conv("fk_vulnerability_occurrences_observation_id_source_observations"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=True,
        ),
        sa.Column("occurrence_key", sa.String(64), nullable=False, primary_key=False),
        sa.Column("native_occurrence_id", sa.String(512), nullable=True, primary_key=False),
        sa.Column("vulnerability_id", sa.String(512), nullable=False, primary_key=False),
        sa.Column("native_status", sa.String(128), nullable=True, primary_key=False),
        sa.Column("evidence", sa.JSON(), nullable=False, primary_key=False),
    )
    sa.Index("ix_vulnerability_occurrences_occurrence_key", table.c.occurrence_key, unique=False)
    sa.Index("ix_vulnerability_occurrences_vulnerability_id", table.c.vulnerability_id, unique=False)
    tables.append(table)
    table = sa.Table(
        "asset_assignment_versions",
        metadata,
        sa.Column(
            "observation_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "source_observations.id",
                name=sa.schema.conv("fk_asset_assignment_versions_observation_id_source_observations"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column(
            "decision_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "reconciliation_decisions.id",
                name=sa.schema.conv("fk_asset_assignment_versions_decision_id_reconciliation_decisions"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            primary_key=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "asset_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "assets.id",
                name=sa.schema.conv("fk_asset_assignment_versions_asset_id_assets"),
                ondelete="RESTRICT",
            ),
            nullable=True,
            primary_key=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False, primary_key=False),
        sa.Column("review_status", sa.String(16), nullable=False, primary_key=False),
        sa.Column("rule", sa.String(128), nullable=False, primary_key=False),
        sa.Column("explanation", sa.Text(), nullable=False, primary_key=False),
        sa.Column("confidence", sa.Float(), nullable=False, primary_key=False),
        sa.Column("candidate_ids", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False, primary_key=True),
        sa.CheckConstraint(
            "version >= 1", name=sa.schema.conv("ck_asset_assignment_versions_history_positive_version")
        ),
        sa.UniqueConstraint(
            "observation_id", "version", name=sa.schema.conv("uq_asset_assignment_versions_observation_id")
        ),
    )
    sa.Index("ix_asset_assignment_versions_asset_id", table.c.asset_id, unique=False)
    sa.Index("ix_asset_assignment_versions_decision_id", table.c.decision_id, unique=False)
    sa.Index("ix_asset_assignment_versions_observation_id", table.c.observation_id, unique=False)
    sa.Index("ix_asset_assignment_versions_review_status", table.c.review_status, unique=False)
    tables.append(table)
    table = sa.Table(
        "observation_locators",
        metadata,
        sa.Column(
            "observation_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "source_observations.id",
                name=sa.schema.conv("fk_observation_locators_observation_id_source_observations"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column(
            "batch_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey(
                "reconciliation_batches.id",
                name=sa.schema.conv("fk_observation_locators_batch_id_reconciliation_batches"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column("file_number", sa.Integer(), nullable=False, primary_key=False),
        sa.Column("record_number", sa.Integer(), nullable=False, primary_key=False),
        sa.Column("filename", sa.String(512), nullable=False, primary_key=False),
        sa.Column("file_sha256", sa.String(64), nullable=False, primary_key=False),
        sa.Column("mapping_sha256", sa.String(64), nullable=False, primary_key=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False, primary_key=False),
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False, primary_key=True),
        sa.UniqueConstraint(
            "batch_id",
            "file_number",
            "record_number",
            name=sa.schema.conv("uq_observation_locators_batch_id"),
        ),
    )
    sa.Index("ix_observation_locators_batch_id", table.c.batch_id, unique=False)
    sa.Index("ix_observation_locators_observation_id", table.c.observation_id, unique=False)
    tables.append(table)
    return metadata, tables


def _lock_tables(tables: list[sa.Table]) -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        existing = set(sa.inspect(connection).get_table_names())
        # All application writers acquire state first. Exclusive table locks also exclude
        # a waiting writer from inserting evidence between downgrade's check and DROP.
        order = ["reconciliation_state"] + sorted(t.name for t in tables if t.name != "reconciliation_state")
        for name in order:
            if name in existing:
                connection.execute(sa.text(f'LOCK TABLE "{name}" IN ACCESS EXCLUSIVE MODE'))


def _type_name(column: sa.Column, connection: sa.Connection) -> str:
    name = connection.dialect.type_compiler.process(column.type).upper()
    return "DOUBLE PRECISION" if name == "FLOAT" and connection.dialect.name == "postgresql" else name


def _check_expression(value: str) -> str:
    value = re.sub(r"::(?:character varying|text)(?:\[\])?", "", value.lower())
    value = re.sub(r'[\s()"]', "", value)
    return re.sub(r"(\w+)=anyarray\[([^]]*)\]", r"\1in\2", value)


def upgrade() -> None:
    metadata, tables = _schema()
    connection = op.get_bind()
    _lock_tables(tables)
    for table in tables:
        table.create(connection, checkfirst=True)
        inspector = sa.inspect(connection)
        columns = {c["name"]: c for c in inspector.get_columns(table.name)}
        if set(columns) != set(table.columns.keys()) or any(
            columns[c.name]["nullable"] != c.nullable
            or _type_name(sa.Column(c.name, columns[c.name]["type"]), connection) != _type_name(c, connection)
            for c in table.columns
        ):
            raise RuntimeError(
                "Existing additive table differs from the frozen migration; inspect and restore safely"
            )
        expected_unique = {
            tuple(c.name for c in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, sa.UniqueConstraint)
        }
        actual_unique = {
            tuple(constraint["column_names"]) for constraint in inspector.get_unique_constraints(table.name)
        }
        expected_checks = {
            connection.dialect.identifier_preparer.truncate_and_render_constraint_name(
                constraint.name, _alembic_quote=False
            ): _check_expression(str(constraint.sqltext))
            for constraint in table.constraints
            if isinstance(constraint, sa.CheckConstraint)
        }
        actual_checks = {
            constraint["name"]: _check_expression(constraint["sqltext"])
            for constraint in inspector.get_check_constraints(table.name)
        }
        expected_fks = {
            (
                tuple(constraint.column_keys),
                constraint.referred_table.name,
                tuple(element.column.name for element in constraint.elements),
                constraint.ondelete,
            )
            for constraint in table.foreign_key_constraints
        }
        actual_fks = {
            (
                tuple(constraint["constrained_columns"]),
                constraint["referred_table"],
                tuple(constraint["referred_columns"]),
                constraint["options"].get("ondelete"),
            )
            for constraint in inspector.get_foreign_keys(table.name)
        }
        if (
            not expected_unique <= actual_unique
            or any(actual_checks.get(name) != value for name, value in expected_checks.items())
            or expected_fks != actual_fks
            or tuple(inspector.get_pk_constraint(table.name)["constrained_columns"])
            != tuple(c.name for c in table.primary_key.columns)
        ):
            raise RuntimeError(
                "Existing additive constraints differ from the frozen migration; no evidence was removed"
            )
        for index in table.indexes:
            index.create(connection, checkfirst=True)
        actual_indexes = {
            index["name"]: tuple(index["column_names"])
            for index in sa.inspect(connection).get_indexes(table.name)
        }
        if any(
            actual_indexes.get(index.name) != tuple(c.name for c in index.columns) for index in table.indexes
        ):
            raise RuntimeError("Existing additive indexes differ from the frozen migration")
    state = metadata.tables["reconciliation_state"]
    if connection.scalar(sa.select(state.c.id).where(state.c.id == 1)) is None:
        connection.execute(state.insert().values(id=1, revision=0))
    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text(
                "CREATE OR REPLACE FUNCTION vwb_reconciliation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Persistent reconciliation evidence and history are immutable'; END; $$"
            )
        )
        for name in IMMUTABLE_TABLES:
            connection.execute(sa.text(f'DROP TRIGGER IF EXISTS immutable_{name} ON "{name}"'))
            connection.execute(
                sa.text(
                    f'CREATE TRIGGER immutable_{name} BEFORE UPDATE OR DELETE ON "{name}" FOR EACH ROW EXECUTE FUNCTION vwb_reconciliation_immutable()'
                )
            )
    elif connection.dialect.name == "sqlite":
        for name in IMMUTABLE_TABLES:
            for action in ("UPDATE", "DELETE"):
                connection.execute(
                    sa.text(
                        f'CREATE TRIGGER IF NOT EXISTS immutable_{name}_{action.lower()} BEFORE {action} ON "{name}" BEGIN SELECT RAISE(ABORT, "Persistent reconciliation evidence and history are immutable"); END'
                    )
                )


def downgrade() -> None:
    _, tables = _schema()
    connection = op.get_bind()
    _lock_tables(tables)
    existing = set(sa.inspect(connection).get_table_names())
    for table in tables:
        if (
            table.name != "reconciliation_state"
            and table.name in existing
            and connection.scalar(sa.select(sa.func.count()).select_from(table))
        ):
            raise RuntimeError(
                "Persistent evidence exists: retain additive tables for application rollback or restore a verified backup; downgrade will not delete evidence"
            )
    for table in reversed(tables):
        table.drop(connection, checkfirst=True)
    if connection.dialect.name == "postgresql":
        connection.execute(sa.text("DROP FUNCTION IF EXISTS vwb_reconciliation_immutable()"))
