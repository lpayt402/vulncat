from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vulnbatch.db import exposure as exposure_models  # noqa: F401
from vulnbatch.db import reconciliation as reconciliation_models  # noqa: F401
from vulnbatch.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

asset_tags = Table(
    "asset_tags",
    Base.metadata,
    Column("asset_id", Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", Uuid(as_uuid=True), ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class Role(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    role: Mapped[Role] = relationship(lazy="joined")


class UserSession(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "user_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True, nullable=False)
    csrf_token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    client_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(lazy="joined")


class LoginAttempt(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "login_attempts"

    username: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    client_ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True, nullable=False
    )


class ApplicationSetting(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "application_settings"

    key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    value: Mapped[Any] = mapped_column(JSON, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class AuditEvent(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "audit_events"

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True, nullable=False
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(64), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(128), index=True)
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    client_ip: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(32), default="success", nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "assets"

    canonical_hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    canonical_name_pinned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    merged_into_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"), index=True
    )
    operating_system: Mapped[str | None] = mapped_column(String(512), index=True)
    system_owner: Mapped[str | None] = mapped_column(String(255), index=True)
    administrative_team: Mapped[str | None] = mapped_column(String(255), index=True)
    technical_owner: Mapped[str | None] = mapped_column(String(255), index=True)
    environment: Mapped[str | None] = mapped_column(String(128), index=True)
    data_center: Mapped[str | None] = mapped_column(String(128), index=True)
    business_service: Mapped[str | None] = mapped_column(String(255), index=True)
    server_role: Mapped[str | None] = mapped_column(String(255), index=True)
    maintenance_group: Mapped[str | None] = mapped_column(String(128), index=True)
    patch_group: Mapped[str | None] = mapped_column(String(128), index=True)
    notes: Mapped[str | None] = mapped_column(Text)
    identity_confidence: Mapped[float | None] = mapped_column(Float, index=True)
    last_scan_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    identifiers: Mapped[list[AssetIdentifier]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )
    tags: Mapped[list[Tag]] = relationship(secondary=asset_tags, lazy="selectin")


class AssetIdentifier(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "asset_identifiers"
    __table_args__ = (
        UniqueConstraint("asset_id", "identifier_type", "normalized_value"),
        Index("ix_asset_identifier_lookup", "identifier_type", "normalized_value"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    identifier_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    original_value: Mapped[str] = mapped_column(String(1024), nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    source_import_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("imports.id", ondelete="SET NULL"))
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    manually_verified: Mapped[bool] = mapped_column(Boolean, default=False, index=True, nullable=False)
    manual_override: Mapped[bool] = mapped_column(Boolean, default=False, index=True, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    shared_or_non_identifying: Mapped[bool] = mapped_column(
        Boolean, default=False, index=True, nullable=False
    )
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    asset: Mapped[Asset] = relationship(back_populates="identifiers")
    observations: Mapped[list[AssetIdentifierObservation]] = relationship(
        back_populates="identifier", cascade="all, delete-orphan"
    )


class AssetIdentifierObservation(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "asset_identifier_observations"
    __table_args__ = (UniqueConstraint("identifier_id", "import_id", "import_record_id"),)

    identifier_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset_identifiers.id", ondelete="CASCADE"), index=True
    )
    import_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("imports.id", ondelete="CASCADE"), index=True)
    import_record_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("import_records.id", ondelete="SET NULL"), index=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    matching_rule: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    identifier: Mapped[AssetIdentifier] = relationship(back_populates="observations")


class Tag(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "tags"

    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))


class IdentityReviewItem(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "identity_review_items"

    status: Mapped[str] = mapped_column(String(32), default="open", index=True, nullable=False)
    source_import_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("imports.id", ondelete="CASCADE"), index=True
    )
    import_record_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("import_records.id", ondelete="SET NULL"), index=True
    )
    incoming_identifiers: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    candidate_asset_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    conflicting_evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    matching_rule: Mapped[str] = mapped_column(String(128), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    first_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolution: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class IdentityEvent(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "identity_events"

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True, nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    primary_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"), index=True
    )
    secondary_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"), index=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    reversible: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    undone_by_event_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("identity_events.id", ondelete="SET NULL")
    )


class SourceFile(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "source_files"

    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(255))
    source_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(1024), unique=True, nullable=False)
    uploaded_by_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    immutable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ImportProfile(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "import_profiles"
    __table_args__ = (UniqueConstraint("owner_user_id", "name"),)

    owner_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    shared: Mapped[bool] = mapped_column(Boolean, default=False, index=True, nullable=False)
    source_signature: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mapping: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class ImportRun(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "imports"

    source_file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("source_files.id", ondelete="RESTRICT"), index=True
    )
    importing_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    import_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("import_profiles.id", ondelete="SET NULL")
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("jobs.id", ondelete="SET NULL"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True, nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    force_reprocess: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    complete_comparable_scope: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    scan_scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    mapping: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_reason: Mapped[str | None] = mapped_column(Text)
    total_records: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    included_records: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    skipped_records: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    severity_counts: Mapped[dict[str, int]] = mapped_column(JSON, default=dict, nullable=False)
    unique_assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    new_assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    matched_assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ambiguous_assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    new_findings: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    updated_findings: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    parse_warnings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    mapping_warnings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)


class ImportRecord(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "import_records"
    __table_args__ = (
        UniqueConstraint(
            "import_id",
            "record_number",
            name="uq_import_records_import_record_number",
        ),
        UniqueConstraint(
            "import_id",
            "content_hash",
            name="uq_import_records_import_content_hash",
        ),
    )

    import_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("imports.id", ondelete="CASCADE"), index=True)
    record_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_record: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    normalized_record: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    warnings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("asset_findings.id", ondelete="SET NULL"), index=True
    )
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class VulnerabilityDefinition(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "vulnerability_definitions"
    __table_args__ = (UniqueConstraint("scanner_source", "plugin_id"),)

    scanner_source: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    plugin_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    plugin_name: Mapped[str | None] = mapped_column(String(1024))
    plugin_family: Mapped[str | None] = mapped_column(String(255), index=True)
    synopsis: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    solution: Mapped[str | None] = mapped_column(Text)
    cves: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    plugin_publication_date: Mapped[date | None] = mapped_column(Date)
    plugin_modification_date: Mapped[date | None] = mapped_column(Date)
    cve_publication_date: Mapped[date | None] = mapped_column(Date)
    vendor_advisory_date: Mapped[date | None] = mapped_column(Date)
    exploit_available: Mapped[bool | None] = mapped_column(Boolean)
    exploited_by_malware: Mapped[bool | None] = mapped_column(Boolean)
    known_exploited: Mapped[bool | None] = mapped_column(Boolean, index=True)


class AssetFinding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "asset_findings"
    __table_args__ = (
        UniqueConstraint("asset_id", "scanner_source", "plugin_id", "port", "protocol"),
        CheckConstraint("times_observed >= 1", name="times_observed_positive"),
        Index("ix_asset_findings_filter", "severity", "status", "maturity_status", "sla_status"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), index=True)
    vulnerability_definition_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vulnerability_definitions.id", ondelete="RESTRICT"), index=True
    )
    scanner_source: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    plugin_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=0, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(32), default="general", nullable=False, index=True)
    service: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(64), default="open", index=True, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    first_found_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_found_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    times_observed: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    current_evidence: Mapped[str | None] = mapped_column(Text)
    current_solution: Mapped[str | None] = mapped_column(Text)
    risk_factor: Mapped[str | None] = mapped_column(String(64))
    cvss_v2: Mapped[float | None] = mapped_column(Float)
    cvss_v3: Mapped[float | None] = mapped_column(Float)
    vpr: Mapped[float | None] = mapped_column(Float)
    epss: Mapped[float | None] = mapped_column(Float)
    maturity_date: Mapped[date | None] = mapped_column(Date, index=True)
    maturity_date_source: Mapped[str | None] = mapped_column(String(64))
    maturity_gate_date: Mapped[date | None] = mapped_column(Date, index=True)
    maturity_status: Mapped[str | None] = mapped_column(String(64), index=True)
    sla_due_date: Mapped[date | None] = mapped_column(Date, index=True)
    sla_status: Mapped[str | None] = mapped_column(String(64), index=True)
    reopened_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_source_import_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("imports.id", ondelete="SET NULL"), index=True
    )


class FindingObservation(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "finding_observations"
    __table_args__ = (UniqueConstraint("finding_id", "import_id", "import_record_id"),)

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset_findings.id", ondelete="CASCADE"), index=True
    )
    import_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("imports.id", ondelete="CASCADE"), index=True)
    import_record_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("import_records.id", ondelete="SET NULL"), index=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    scan_name: Mapped[str | None] = mapped_column(String(512))
    scan_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    solution: Mapped[str | None] = mapped_column(Text)
    raw_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class FindingStatusHistory(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "finding_status_history"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset_findings.id", ondelete="CASCADE"), index=True
    )
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True, nullable=False
    )
    changed_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    source_import_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("imports.id", ondelete="SET NULL"))
    previous_status: Mapped[str | None] = mapped_column(String(64))
    new_status: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class FindingNote(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "finding_notes"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset_findings.id", ondelete="CASCADE"), index=True
    )
    author_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)


class SavedView(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "saved_views"
    __table_args__ = (UniqueConstraint("owner_user_id", "name"),)

    owner_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    shared: Mapped[bool] = mapped_column(Boolean, default=False, index=True, nullable=False)
    query_schema_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    query_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class Job(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint("progress >= 0 AND progress <= 100", name="progress_range"),
        Index("ix_jobs_claim", "status", "available_at", "job_type"),
    )

    job_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    unique_key: Mapped[str | None] = mapped_column(String(255), unique=True)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_token: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), index=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)


class ExportJob(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "export_jobs"

    requested_by_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("jobs.id", ondelete="RESTRICT"), unique=True)
    scope_mode: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    saved_view_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("saved_views.id", ondelete="SET NULL"))
    saved_view_revision: Mapped[int | None] = mapped_column(Integer)
    saved_view_name: Mapped[str | None] = mapped_column(String(255))
    original_query_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    normalized_query_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    query_schema_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    finding_scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    output_format: Mapped[str] = mapped_column(String(16), nullable=False)
    matched_host_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    matched_finding_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    data_as_of: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_import_cutoff: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True, nullable=False)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    output_path: Mapped[str | None] = mapped_column(String(1024))
    output_sha256: Mapped[str | None] = mapped_column(String(64))
    output_byte_size: Mapped[int | None] = mapped_column(BigInteger)
    app_version: Mapped[str] = mapped_column(String(64), nullable=False)


class ExportAssetSnapshot(Base):
    __tablename__ = "export_asset_snapshots"

    export_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("export_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"), primary_key=True
    )
    snapshot_order: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ExportFindingSnapshot(Base):
    __tablename__ = "export_finding_snapshots"

    export_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("export_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset_findings.id", ondelete="RESTRICT"), primary_key=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), index=True)
    snapshot_order: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
