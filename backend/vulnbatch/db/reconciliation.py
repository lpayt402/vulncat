"""Additive offline evidence and versioned assignment tables; legacy findings stay independent."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
    func,
)
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Mapped, Mapper, mapped_column

from vulnbatch.db.base import Base, UUIDPrimaryKeyMixin


class ReconciliationState(Base):
    __tablename__ = "reconciliation_state"
    __table_args__ = (CheckConstraint("id = 1 AND revision >= 0", name="singleton_revision"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class SourceInstance(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "reconciliation_source_instances"
    __table_args__ = (UniqueConstraint("source", "label"),)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)


class ReconciliationBatch(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "reconciliation_batches"
    request_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    files: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class SourceObservation(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "source_observations"
    __table_args__ = (
        CheckConstraint("kind IN ('inventory','vulnerability','coverage')", name="observation_kind"),
        Index("ix_source_observations_import_order", "imported_at", "id"),
    )
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    source_instance_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reconciliation_source_instances.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    first_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    parser_version: Mapped[str] = mapped_column(String(64), nullable=False)
    normalized: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ObservationLocator(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "observation_locators"
    __table_args__ = (UniqueConstraint("batch_id", "file_number", "record_number"),)
    observation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("source_observations.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    batch_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reconciliation_batches.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    file_number: Mapped[int] = mapped_column(Integer, nullable=False)
    record_number: Mapped[int] = mapped_column(Integer, nullable=False)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    file_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    mapping_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ObservationNativeID(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "observation_native_ids"
    __table_args__ = (
        UniqueConstraint("observation_id", "source_instance_id", "kind", "value"),
        Index("ix_observation_native_scoped_value", "source_instance_id", "kind", "value"),
    )
    observation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("source_observations.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    source_instance_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reconciliation_source_instances.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    kind: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    value: Mapped[str] = mapped_column(String(512), index=True, nullable=False)


class VulnerabilityOccurrence(Base):
    __tablename__ = "vulnerability_occurrences"
    observation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("source_observations.id", ondelete="RESTRICT"), primary_key=True
    )
    occurrence_key: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    native_occurrence_id: Mapped[str | None] = mapped_column(String(512))
    vulnerability_id: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    native_status: Mapped[str | None] = mapped_column(String(128))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class CoverageObservation(Base):
    __tablename__ = "coverage_observations"
    observation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("source_observations.id", ondelete="RESTRICT"), primary_key=True
    )
    outcome: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    complete: Mapped[bool] = mapped_column(Boolean, nullable=False)
    authenticated: Mapped[bool | None] = mapped_column(Boolean)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ReconciliationDecision(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "reconciliation_decisions"
    request_key: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    actor_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    undo_of_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("reconciliation_decisions.id", ondelete="RESTRICT"), unique=True
    )
    changes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class AssignmentFields:
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"), index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    review_status: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    rule: Mapped[str] = mapped_column(String(128), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    candidate_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)


class CurrentAssignment(AssignmentFields, Base):
    __tablename__ = "asset_observation_assignments"
    __table_args__ = (
        CheckConstraint("version >= 1", name="positive_version"),
        CheckConstraint("review_status IN ('open','deferred','assigned','rejected')", name="review_status"),
        CheckConstraint(
            "(review_status = 'assigned' AND asset_id IS NOT NULL) "
            "OR (review_status <> 'assigned' AND asset_id IS NULL)",
            name="assignment_status_asset",
        ),
    )
    observation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("source_observations.id", ondelete="RESTRICT"), primary_key=True
    )


class AssignmentVersion(AssignmentFields, UUIDPrimaryKeyMixin, Base):
    __tablename__ = "asset_assignment_versions"
    __table_args__ = (
        UniqueConstraint("observation_id", "version"),
        CheckConstraint("version >= 1", name="history_positive_version"),
    )
    observation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("source_observations.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    decision_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reconciliation_decisions.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


IMMUTABLE_MODELS = (
    SourceInstance,
    ReconciliationBatch,
    SourceObservation,
    ObservationLocator,
    ObservationNativeID,
    VulnerabilityOccurrence,
    CoverageObservation,
    ReconciliationDecision,
    AssignmentVersion,
)


def _immutable(_: Mapper[Any], __: Connection, ___: object) -> None:
    raise ValueError("Persistent reconciliation evidence and history are immutable")


for _model in IMMUTABLE_MODELS:
    event.listen(_model, "before_update", _immutable)
    event.listen(_model, "before_delete", _immutable)
