"""Additive immutable service exposure evidence. Frozen schema definitions."""

from __future__ import annotations

import re

import sqlalchemy as sa
from alembic import op

revision = "0003_service_exposure"
down_revision = "0002_persistent_reconciliation"
branch_labels = None
depends_on = None

IMMUTABLE_TABLES = ("exposure_decisions", "exposure_node_facts", "exposure_versions")


def _schema() -> tuple[sa.MetaData, list[sa.Table]]:
    metadata = sa.MetaData()
    for name in ("assets", "users", "source_observations"):
        sa.Table(name, metadata, sa.Column("id", sa.Uuid(), primary_key=True))
    tables = []
    table = sa.Table(
        "exposure_nodes",
        metadata,
        sa.Column("source", sa.String(length=64), nullable=False, primary_key=False),
        sa.Column("instance", sa.String(length=128), nullable=False, primary_key=False),
        sa.Column("native_id", sa.String(length=512), nullable=False, primary_key=False),
        sa.Column("kind", sa.String(length=16), nullable=False, primary_key=False),
        sa.Column("label", sa.String(length=255), nullable=False, primary_key=False),
        sa.Column(
            "asset_id",
            sa.Uuid(),
            sa.ForeignKey(
                "assets.id", name=sa.schema.conv("fk_exposure_nodes_asset_id_assets"), ondelete="RESTRICT"
            ),
            nullable=True,
            primary_key=False,
        ),
        sa.Column("protocol", sa.String(length=32), nullable=True, primary_key=False),
        sa.Column("port", sa.Integer(), nullable=True, primary_key=False),
        sa.Column("dns_name", sa.String(length=255), nullable=True, primary_key=False),
        sa.Column("sni", sa.String(length=255), nullable=True, primary_key=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True, primary_key=False),
        sa.Column("network_scope", sa.String(length=128), nullable=True, primary_key=False),
        sa.Column("facts", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("provenance", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("active", sa.Boolean(), nullable=False, primary_key=False),
        sa.Column("version", sa.Integer(), nullable=False, primary_key=False),
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.CheckConstraint(
            "kind IN ('host','device','load_balancer','vip','service','endpoint')",
            name=sa.schema.conv("ck_exposure_nodes_node_kind"),
        ),
        sa.CheckConstraint("version >= 1", name=sa.schema.conv("ck_exposure_nodes_positive_version")),
        sa.CheckConstraint(
            "port IS NULL OR (port >= 0 AND port <= 65535)",
            name=sa.schema.conv("ck_exposure_nodes_valid_port"),
        ),
        sa.UniqueConstraint(
            "source", "instance", "native_id", name=sa.schema.conv("uq_exposure_nodes_source")
        ),
    )
    sa.Index("ix_exposure_nodes_active_kind", table.c.active, table.c.kind, table.c.id, unique=False)
    sa.Index("ix_exposure_nodes_asset_id", table.c.asset_id, unique=False)
    sa.Index("ix_exposure_nodes_dns_name", table.c.dns_name, unique=False)
    sa.Index("ix_exposure_nodes_ip_address", table.c.ip_address, unique=False)
    sa.Index("ix_exposure_nodes_kind", table.c.kind, unique=False)
    sa.Index("ix_exposure_nodes_label", table.c.label, unique=False)
    sa.Index("ix_exposure_nodes_network_scope", table.c.network_scope, unique=False)
    tables.append(table)
    table = sa.Table(
        "exposure_decisions",
        metadata,
        sa.Column("request_key", sa.String(length=160), nullable=False, primary_key=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False, primary_key=False),
        sa.Column("action", sa.String(length=16), nullable=False, primary_key=False),
        sa.Column(
            "actor_user_id",
            sa.Uuid(),
            sa.ForeignKey(
                "users.id",
                name=sa.schema.conv("fk_exposure_decisions_actor_user_id_users"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, primary_key=False),
        sa.Column("reason", sa.Text(), nullable=False, primary_key=False),
        sa.Column(
            "undo_of_id",
            sa.Uuid(),
            sa.ForeignKey(
                "exposure_decisions.id",
                name=sa.schema.conv("fk_exposure_decisions_undo_of_id_exposure_decisions"),
                ondelete="RESTRICT",
            ),
            nullable=True,
            primary_key=False,
        ),
        sa.Column("changes", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("result", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.UniqueConstraint("request_key", name=sa.schema.conv("uq_exposure_decisions_request_key")),
        sa.UniqueConstraint("undo_of_id", name=sa.schema.conv("uq_exposure_decisions_undo_of_id")),
    )
    sa.Index("ix_exposure_decisions_occurred_at", table.c.occurred_at, unique=False)
    tables.append(table)
    table = sa.Table(
        "exposure_relationships",
        metadata,
        sa.Column("source", sa.String(length=64), nullable=False, primary_key=False),
        sa.Column("instance", sa.String(length=128), nullable=False, primary_key=False),
        sa.Column("kind", sa.String(length=16), nullable=False, primary_key=False),
        sa.Column(
            "from_node_id",
            sa.Uuid(),
            sa.ForeignKey(
                "exposure_nodes.id",
                name=sa.schema.conv("fk_exposure_relationships_from_node_id_exposure_nodes"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column(
            "to_node_id",
            sa.Uuid(),
            sa.ForeignKey(
                "exposure_nodes.id",
                name=sa.schema.conv("fk_exposure_relationships_to_node_id_exposure_nodes"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column("evidence", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("provenance", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("active", sa.Boolean(), nullable=False, primary_key=False),
        sa.Column("version", sa.Integer(), nullable=False, primary_key=False),
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.CheckConstraint(
            "from_node_id <> to_node_id", name=sa.schema.conv("ck_exposure_relationships_distinct_nodes")
        ),
        sa.CheckConstraint("version >= 1", name=sa.schema.conv("ck_exposure_relationships_positive_version")),
        sa.CheckConstraint(
            "kind IN ('endpoint_of','backed_by','routes_to','hosted_on','management_of')",
            name=sa.schema.conv("ck_exposure_relationships_relationship_kind"),
        ),
        sa.UniqueConstraint(
            "source",
            "instance",
            "kind",
            "from_node_id",
            "to_node_id",
            name=sa.schema.conv("uq_exposure_relationships_source"),
        ),
    )
    sa.Index(
        "ix_exposure_relationship_from_active",
        table.c.from_node_id,
        table.c.active,
        table.c.kind,
        unique=False,
    )
    sa.Index("ix_exposure_relationship_to_active", table.c.to_node_id, table.c.active, unique=False)
    tables.append(table)
    table = sa.Table(
        "exposure_attributions",
        metadata,
        sa.Column(
            "observation_id",
            sa.Uuid(),
            sa.ForeignKey(
                "source_observations.id",
                name=sa.schema.conv("fk_exposure_attributions_observation_id_source_observations"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=True,
        ),
        sa.Column(
            "node_id",
            sa.Uuid(),
            sa.ForeignKey(
                "exposure_nodes.id",
                name=sa.schema.conv("fk_exposure_attributions_node_id_exposure_nodes"),
                ondelete="RESTRICT",
            ),
            nullable=True,
            primary_key=False,
        ),
        sa.Column("status", sa.String(length=16), nullable=False, primary_key=False),
        sa.Column("reason", sa.Text(), nullable=False, primary_key=False),
        sa.Column("evidence", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("provenance", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("version", sa.Integer(), nullable=False, primary_key=False),
        sa.CheckConstraint(
            "status IN ('attributed','review_needed')",
            name=sa.schema.conv("ck_exposure_attributions_attribution_status"),
        ),
        sa.CheckConstraint("version >= 1", name=sa.schema.conv("ck_exposure_attributions_positive_version")),
        sa.CheckConstraint(
            "(status = 'attributed' AND node_id IS NOT NULL) "
            "OR (status = 'review_needed' AND node_id IS NULL)",
            name=sa.schema.conv("ck_exposure_attributions_status_node"),
        ),
    )
    sa.Index("ix_exposure_attributions_node_id", table.c.node_id, unique=False)
    sa.Index("ix_exposure_attributions_status", table.c.status, unique=False)
    tables.append(table)
    table = sa.Table(
        "exposure_node_facts",
        metadata,
        sa.Column(
            "node_id",
            sa.Uuid(),
            sa.ForeignKey(
                "exposure_nodes.id",
                name=sa.schema.conv("fk_exposure_node_facts_node_id_exposure_nodes"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column(
            "decision_id",
            sa.Uuid(),
            sa.ForeignKey(
                "exposure_decisions.id",
                name=sa.schema.conv("fk_exposure_node_facts_decision_id_exposure_decisions"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True, primary_key=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False, primary_key=False),
        sa.Column("facts_sha256", sa.String(length=64), nullable=False, primary_key=False),
        sa.Column("payload", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("provenance", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.UniqueConstraint("node_id", "decision_id", name=sa.schema.conv("uq_exposure_node_facts_node_id")),
    )
    sa.Index("ix_exposure_node_facts_decision_id", table.c.decision_id, unique=False)
    sa.Index("ix_exposure_node_facts_node_id", table.c.node_id, unique=False)
    sa.Index("ix_exposure_node_facts_observed_at", table.c.observed_at, unique=False)
    tables.append(table)
    table = sa.Table(
        "exposure_versions",
        metadata,
        sa.Column("entity_type", sa.String(length=16), nullable=False, primary_key=False),
        sa.Column("entity_id", sa.Uuid(), nullable=False, primary_key=False),
        sa.Column("version", sa.Integer(), nullable=False, primary_key=False),
        sa.Column(
            "decision_id",
            sa.Uuid(),
            sa.ForeignKey(
                "exposure_decisions.id",
                name=sa.schema.conv("fk_exposure_versions_decision_id_exposure_decisions"),
                ondelete="RESTRICT",
            ),
            nullable=False,
            primary_key=False,
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, primary_key=False),
        sa.Column("snapshot", sa.JSON(), nullable=False, primary_key=False),
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.CheckConstraint(
            "entity_type IN ('node','relationship','attribution')",
            name=sa.schema.conv("ck_exposure_versions_entity_type"),
        ),
        sa.CheckConstraint("version >= 1", name=sa.schema.conv("ck_exposure_versions_positive_version")),
        sa.UniqueConstraint(
            "entity_type", "entity_id", "version", name=sa.schema.conv("uq_exposure_versions_entity_type")
        ),
    )
    sa.Index(
        "ix_exposure_version_entity", table.c.entity_type, table.c.entity_id, table.c.version, unique=False
    )
    sa.Index("ix_exposure_versions_decision_id", table.c.decision_id, unique=False)
    tables.append(table)
    return metadata, tables


def _lock_tables(tables: list[sa.Table]) -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        existing = set(sa.inspect(connection).get_table_names())
        # All application writers acquire state first. Exclusive table locks also exclude
        # a waiting writer from inserting evidence between downgrade's check and DROP.
        order = ["reconciliation_state", *sorted(t.name for t in tables if t.name != "reconciliation_state")]
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
    _metadata, tables = _schema()
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
    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text(
                "CREATE OR REPLACE FUNCTION vwb_exposure_immutable() RETURNS trigger LANGUAGE plpgsql "
                "AS $$ BEGIN RAISE EXCEPTION 'Exposure evidence and history are immutable'; END; $$"
            )
        )
        for name in IMMUTABLE_TABLES:
            connection.execute(sa.text(f'DROP TRIGGER IF EXISTS immutable_{name} ON "{name}"'))
            connection.execute(
                sa.text(
                    f'CREATE TRIGGER immutable_{name} BEFORE UPDATE OR DELETE ON "{name}" '
                    "FOR EACH ROW EXECUTE FUNCTION vwb_exposure_immutable()"
                )
            )
    elif connection.dialect.name == "sqlite":
        for name in IMMUTABLE_TABLES:
            for action in ("UPDATE", "DELETE"):
                connection.execute(
                    sa.text(
                        f'CREATE TRIGGER IF NOT EXISTS immutable_{name}_{action.lower()} '
                        f'BEFORE {action} ON "{name}" BEGIN '
                        'SELECT RAISE(ABORT, "Exposure evidence and history are immutable"); END'
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
                "Service exposure evidence exists: retain additive tables for application rollback "
                "or restore a verified backup; downgrade will not delete evidence"
            )
    for table in reversed(tables):
        table.drop(connection, checkfirst=True)
    if connection.dialect.name == "postgresql":
        connection.execute(sa.text("DROP FUNCTION IF EXISTS vwb_exposure_immutable()"))
