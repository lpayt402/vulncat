"""Additive exposure projections and immutable facts, decisions, and versions."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Mapped, Mapper, mapped_column

from vulnbatch.db.base import Base, UUIDPrimaryKeyMixin


class ExposureDecision(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "exposure_decisions"
    request_key: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    undo_of_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("exposure_decisions.id", ondelete="RESTRICT"), unique=True
    )
    changes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ExposureNode(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "exposure_nodes"
    __table_args__ = (
        UniqueConstraint("source", "instance", "native_id"),
        CheckConstraint(
            "kind IN ('host','device','load_balancer','vip','service','endpoint')", name="node_kind"
        ),
        CheckConstraint("version >= 1", name="positive_version"),
        CheckConstraint("port IS NULL OR (port >= 0 AND port <= 65535)", name="valid_port"),
        Index("ix_exposure_nodes_active_kind", "active", "kind", "id"),
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    instance: Mapped[str] = mapped_column(String(128), nullable=False)
    native_id: Mapped[str] = mapped_column(String(512), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    label: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"), index=True
    )
    protocol: Mapped[str | None] = mapped_column(String(32))
    port: Mapped[int | None] = mapped_column(Integer)
    dns_name: Mapped[str | None] = mapped_column(String(255), index=True)
    sni: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(64), index=True)
    network_scope: Mapped[str | None] = mapped_column(String(128), index=True)
    facts: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)


class ExposureNodeFact(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "exposure_node_facts"
    __table_args__ = (UniqueConstraint("node_id", "decision_id"),)
    node_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("exposure_nodes.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    decision_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("exposure_decisions.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    facts_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ExposureRelationship(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "exposure_relationships"
    __table_args__ = (
        UniqueConstraint("source", "instance", "kind", "from_node_id", "to_node_id"),
        CheckConstraint(
            "kind IN ('endpoint_of','backed_by','routes_to','hosted_on','management_of')",
            name="relationship_kind",
        ),
        CheckConstraint("from_node_id <> to_node_id", name="distinct_nodes"),
        CheckConstraint("version >= 1", name="positive_version"),
        Index("ix_exposure_relationship_from_active", "from_node_id", "active", "kind"),
        Index("ix_exposure_relationship_to_active", "to_node_id", "active"),
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    instance: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    from_node_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("exposure_nodes.id", ondelete="RESTRICT"), nullable=False
    )
    to_node_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("exposure_nodes.id", ondelete="RESTRICT"), nullable=False
    )
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)


class ExposureAttribution(Base):
    __tablename__ = "exposure_attributions"
    __table_args__ = (
        CheckConstraint("version >= 1", name="positive_version"),
        CheckConstraint("status IN ('attributed','review_needed')", name="attribution_status"),
        CheckConstraint(
            "(status = 'attributed' AND node_id IS NOT NULL) "
            "OR (status = 'review_needed' AND node_id IS NULL)",
            name="status_node",
        ),
    )
    observation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("source_observations.id", ondelete="RESTRICT"), primary_key=True
    )
    node_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("exposure_nodes.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)


class ExposureVersion(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "exposure_versions"
    __table_args__ = (
        UniqueConstraint("entity_type", "entity_id", "version"),
        CheckConstraint("entity_type IN ('node','relationship','attribution')", name="entity_type"),
        CheckConstraint("version >= 1", name="positive_version"),
        Index("ix_exposure_version_entity", "entity_type", "entity_id", "version"),
    )
    entity_type: Mapped[str] = mapped_column(String(16), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    decision_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("exposure_decisions.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


IMMUTABLE_MODELS = (ExposureDecision, ExposureNodeFact, ExposureVersion)


def _immutable(_: Mapper[Any], __: Connection, ___: object) -> None:
    raise ValueError("Exposure evidence and history are immutable")


for _model in IMMUTABLE_MODELS:
    event.listen(_model, "before_update", _immutable)
    event.listen(_model, "before_delete", _immutable)
