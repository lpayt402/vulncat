from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictImportModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


SourceType = Literal["tenable_csv", "tenable_json", "nessus_xml", "generic_csv"]


class GenericPreviewResponse(StrictImportModel):
    source_file_id: uuid.UUID
    duplicate: bool
    previous_import_id: uuid.UUID | None
    headers: list[str]
    records: list[dict[str, Any]]
    mapping_warnings: list[dict[str, Any]]
    unmapped_columns: list[str]
    truncated: bool


class GenericCommitRequest(StrictImportModel):
    source_file_id: uuid.UUID
    mapping: dict[str, str]
    profile_name: str | None = Field(default=None, max_length=255)
    share_profile: bool = False
    complete_comparable_scope: bool = False
    force_reprocess: bool = False


class ImportResponse(StrictImportModel):
    id: uuid.UUID
    source_file_id: uuid.UUID
    source_type: str
    status: str
    duplicate_of_import_id: uuid.UUID | None = None
    force_reprocess: bool
    complete_comparable_scope: bool
    requested_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    failed_at: datetime | None
    failure_reason: str | None
    total_records: int
    included_records: int
    skipped_records: int
    severity_counts: dict[str, int]
    unique_assets: int
    new_assets: int
    matched_assets: int
    ambiguous_assets: int
    new_findings: int
    updated_findings: int
    parse_warnings: list[dict[str, Any]]
    mapping_warnings: list[dict[str, Any]]
