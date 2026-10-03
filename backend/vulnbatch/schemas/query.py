from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DateRange(StrictModel):
    start: date | datetime | None = None
    end: date | datetime | None = None

    @model_validator(mode="after")
    def validate_order(self) -> DateRange:
        if self.start is not None and self.end is not None:
            start = self.start.date() if isinstance(self.start, datetime) else self.start
            end = self.end.date() if isinstance(self.end, datetime) else self.end
            if start > end:
                raise ValueError("Range start must not be after range end.")
        return self


class NumericRange(StrictModel):
    minimum: int | None = Field(default=None, ge=0)
    maximum: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_order(self) -> NumericRange:
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("Range minimum must not exceed maximum.")
        return self


class FloatRange(StrictModel):
    minimum: float | None = Field(default=None, ge=0.0, le=1.0)
    maximum: float | None = Field(default=None, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_order(self) -> FloatRange:
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("Range minimum must not exceed maximum.")
        return self


class TagFilter(StrictModel):
    values: list[str] = Field(min_length=1, max_length=100)
    match: Literal["any", "all"] = "any"


class SortClause(StrictModel):
    field: Literal[
        "canonical_hostname",
        "operating_system",
        "system_owner",
        "administrative_team",
        "environment",
        "maintenance_group",
        "last_scan_observed_at",
        "open_medium_count",
        "open_low_count",
        "mature_backlog_count",
        "new_deferred_count",
        "overdue_count",
        "oldest_open_finding",
        "identity_confidence",
    ]
    direction: Literal["asc", "desc"] = "asc"


class HostQueryV1(StrictModel):
    schema_version: Literal[1] = 1
    q: str | None = Field(default=None, min_length=1, max_length=200)
    canonical_hostnames: list[str] = Field(default_factory=list, max_length=100)
    aliases: list[str] = Field(default_factory=list, max_length=100)
    ip_addresses: list[str] = Field(default_factory=list, max_length=100)
    ip_scope: Literal["current", "history", "both"] = "current"
    tenable_asset_uuids: list[str] = Field(default_factory=list, max_length=100)
    agent_uuids: list[str] = Field(default_factory=list, max_length=100)
    nessus_host_ids: list[str] = Field(default_factory=list, max_length=100)
    hardware_uuids: list[str] = Field(default_factory=list, max_length=100)
    mac_addresses: list[str] = Field(default_factory=list, max_length=100)
    operating_systems: list[str] = Field(default_factory=list, max_length=100)
    system_owners: list[str] = Field(default_factory=list, max_length=100)
    administrative_teams: list[str] = Field(default_factory=list, max_length=100)
    technical_owners: list[str] = Field(default_factory=list, max_length=100)
    environments: list[str] = Field(default_factory=list, max_length=100)
    data_centers: list[str] = Field(default_factory=list, max_length=100)
    business_services: list[str] = Field(default_factory=list, max_length=100)
    server_roles: list[str] = Field(default_factory=list, max_length=100)
    maintenance_groups: list[str] = Field(default_factory=list, max_length=100)
    patch_groups: list[str] = Field(default_factory=list, max_length=100)
    tags: TagFilter | None = None
    last_scan_observation: DateRange | None = None
    identity_confidence: FloatRange | None = None
    identity_review_state: Literal["include_unresolved", "exclude_unresolved", "only_unresolved"] = (
        "include_unresolved"
    )
    open_medium_count: NumericRange | None = None
    open_low_count: NumericRange | None = None
    mature_backlog_count: NumericRange | None = None
    new_deferred_count: NumericRange | None = None
    overdue_count: NumericRange | None = None
    oldest_open_finding: DateRange | None = None
    open_severities: list[Literal["informational", "low", "medium", "high", "critical"]] = Field(
        default_factory=list
    )
    finding_statuses: list[
        Literal[
            "open",
            "new_or_maturity_deferred",
            "planned",
            "in_progress",
            "not_observed",
            "remediated",
            "risk_accepted",
            "false_positive",
            "not_applicable",
        ]
    ] = Field(default_factory=list)
    maturity_states: list[Literal["deferred", "mature", "unknown"]] = Field(default_factory=list)
    sla_states: list[Literal["not_due", "approaching", "overdue", "unknown", "not_applicable"]] = Field(
        default_factory=list
    )
    plugin_ids: list[str] = Field(default_factory=list, max_length=100)
    plugin_families: list[str] = Field(default_factory=list, max_length=100)
    cves: list[str] = Field(default_factory=list, max_length=100)
    exploit_indicator: bool | None = None
    ports: list[int] = Field(default_factory=list, max_length=100)
    protocols: list[str] = Field(default_factory=list, max_length=100)
    sort: list[SortClause] = Field(
        default_factory=lambda: [
            SortClause(
                field=cast(Any, "canonical_hostname"),
                direction=cast(Any, "asc"),
            )
        ],
        max_length=5,
    )


class FindingScopeV1(StrictModel):
    schema_version: Literal[1] = 1
    severities: list[Literal["informational", "low", "medium", "high", "critical"]] = Field(
        default_factory=lambda: [cast(Any, "medium"), cast(Any, "low")]
    )
    maturity_states: list[Literal["deferred", "mature", "unknown"]] = Field(default_factory=list)
    sla_states: list[Literal["not_due", "approaching", "overdue", "unknown", "not_applicable"]] = Field(
        default_factory=list
    )
    statuses: list[
        Literal[
            "open",
            "new_or_maturity_deferred",
            "planned",
            "in_progress",
            "not_observed",
            "remediated",
            "risk_accepted",
            "false_positive",
            "not_applicable",
        ]
    ] = Field(
        default_factory=lambda: [
            cast(Any, "open"),
            cast(Any, "new_or_maturity_deferred"),
            cast(Any, "planned"),
            cast(Any, "in_progress"),
        ]
    )
    plugin_ids: list[str] = Field(default_factory=list, max_length=100)
    cves: list[str] = Field(default_factory=list, max_length=100)
    ports: list[int] = Field(default_factory=list, max_length=100)
    protocols: list[str] = Field(default_factory=list, max_length=100)
    exploit_indicator: bool | None = None
    owners: list[str] = Field(default_factory=list, max_length=100)
    teams: list[str] = Field(default_factory=list, max_length=100)
    first_found: DateRange | None = None
    last_found: DateRange | None = None


class SelectedAssetsScope(StrictModel):
    mode: Literal["selected_assets"]
    asset_ids: list[uuid.UUID] = Field(min_length=1, max_length=50_000)


class HostQueryScope(StrictModel):
    mode: Literal["host_query"]
    query: HostQueryV1


class SavedViewScope(StrictModel):
    mode: Literal["saved_view"]
    saved_view_id: uuid.UUID


AssetScope = Annotated[
    SelectedAssetsScope | HostQueryScope | SavedViewScope,
    Field(discriminator="mode"),
]


class HostQueryPreviewRequest(StrictModel):
    query: HostQueryV1
    finding_scope: FindingScopeV1 = Field(default_factory=FindingScopeV1)


class HostListRequest(StrictModel):
    query: HostQueryV1 = Field(default_factory=HostQueryV1)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class HostSummary(StrictModel):
    id: uuid.UUID
    canonical_hostname: str | None
    current_ip_addresses: list[str]
    known_aliases: list[str]
    operating_system: str | None
    system_owner: str | None
    administrative_team: str | None
    technical_owner: str | None
    environment: str | None
    data_center: str | None
    business_service: str | None
    server_role: str | None
    maintenance_group: str | None
    patch_group: str | None
    tags: list[str]
    open_medium_count: int
    open_low_count: int
    mature_backlog_count: int
    new_deferred_count: int
    overdue_count: int
    oldest_open_finding: datetime | None
    last_scan_observed_at: datetime | None
    identity_confidence: float | None
    unresolved_identity: bool


class HostListResponse(StrictModel):
    normalized_query: dict[str, Any]
    page: int
    page_size: int
    total: int
    items: list[HostSummary]


class HostQueryPreviewResponse(StrictModel):
    normalized_query: dict[str, Any]
    matching_host_count: int
    sample_hosts: list[HostSummary]
    estimated_matching_finding_count: int
    warnings: list[str]


class ExportCreateRequest(StrictModel):
    asset_scope: AssetScope
    finding_scope: FindingScopeV1 = Field(default_factory=FindingScopeV1)
    format: Literal["xlsx", "csv", "html"]
    confirm_large_export: bool = False


class ExportResponse(StrictModel):
    id: uuid.UUID
    scope_mode: str
    output_format: str
    status: str
    progress: int
    matched_host_count: int
    matched_finding_count: int
    data_as_of: datetime
    requested_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    failed_at: datetime | None
    expires_at: datetime | None
    failure_reason: str | None
    output_sha256: str | None
    output_byte_size: int | None
    download_ready: bool


class SavedViewCreate(StrictModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    shared: bool = False
    query: HostQueryV1


class SavedViewUpdate(SavedViewCreate):
    pass


class SavedViewResponse(StrictModel):
    id: uuid.UUID
    owner_user_id: uuid.UUID
    name: str
    description: str | None
    shared: bool
    query_schema_version: int
    query: dict[str, Any]
    revision: int
    created_at: datetime
    updated_at: datetime
