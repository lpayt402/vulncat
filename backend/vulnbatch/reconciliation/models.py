from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

Source = Literal["crowdstrike", "pdq_connect", "nessus", "netbox", "active_directory", "inventory"]
InputFormat = Literal["csv", "json", "ndjson", "nessus_xml"]
CANONICAL_FIELDS = (
    "native_id",
    "native_id_kind",
    "hardware_uuid",
    "hostname",
    "fqdn",
    "short_hostname",
    "ip",
    "mac_address",
    "operating_system",
    "observed_at",
    "first_observed_at",
    "kind",
    "vulnerability_id",
    "occurrence_id",
    "title",
    "severity",
    "cves",
    "package",
    "package_version",
    "port",
    "protocol",
    "native_status",
    "coverage_outcome",
    "complete",
    "authenticated",
)
NETBOX_ASSET_ID_KINDS = frozenset({"dcim.device", "virtualization.virtualmachine"})


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SourceOptions(Contract):
    source: Source
    instance: str = Field(min_length=1, max_length=128, pattern=r"\S")
    format: InputFormat
    network_scope: str | None = Field(default=None, max_length=128)
    mapping: dict[str, str] = Field(default_factory=dict)
    records_path: str | None = Field(default=None, max_length=256)
    time_meaning: Literal["source_observed", "record_updated", "last_logon", "export_snapshot", "unknown"] = (
        "unknown"
    )

    @model_validator(mode="after")
    def validate_mapping_and_format(self) -> Self:
        if any(
            "\x00" in value
            for value in [
                self.instance,
                self.network_scope or "",
                self.records_path or "",
                *self.mapping.values(),
            ]
        ):
            raise ValueError("Source configuration cannot contain NUL characters")
        unknown = set(self.mapping) - set(CANONICAL_FIELDS)
        if unknown:
            raise ValueError("Unknown mapping fields: " + ", ".join(sorted(unknown)))
        if any(not path.strip() for path in self.mapping.values()):
            raise ValueError("Every configured mapping path must be nonempty; omit unused mappings")
        if self.records_path is not None:
            if self.format != "json":
                raise ValueError("records_path applies only to JSON; omit it for other formats")
            if not self.records_path.strip():
                raise ValueError("records_path must be nonempty when provided; omit it for a JSON array")
        if self.format == "nessus_xml" and (self.source != "nessus" or self.mapping):
            raise ValueError("Nessus XML requires source nessus and its fixed field adapter")
        return self


class IdentityEvidence(Contract):
    source: Source
    instance: str
    kind: str = Field(max_length=128)
    value: str = Field(max_length=512)

    @property
    def key(self) -> tuple[str, ...]:
        return ("native", self.source, self.instance, self.kind, self.value)


class AssetEvidence(Contract):
    native_ids: tuple[IdentityEvidence, ...] = ()
    hardware_uuid: str | None = None
    fqdn: str | None = Field(default=None, max_length=255)
    short_hostname: str | None = Field(default=None, max_length=255)
    ip_addresses: tuple[str, ...] = ()
    mac_address: str | None = None
    operating_system: str | None = Field(default=None, max_length=512)
    network_scope: str | None = None


class VulnerabilityEvidence(Contract):
    vulnerability_id: str = Field(max_length=512)
    occurrence_id: str | None = Field(default=None, max_length=512)
    title: str | None = None
    cves: tuple[str, ...] = ()
    severity: str | None = None
    package: str | None = None
    package_version: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    native_status: str | None = Field(default=None, max_length=128)


class CoverageEvidence(Contract):
    outcome: Literal["successful", "failed", "unreachable", "dns_failed", "partial", "unknown"]
    complete: bool = False
    authenticated: bool | None = None
    native_status: str | None = Field(default=None, max_length=128)


class Provenance(Contract):
    source: Source
    instance: str
    file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_number: int = Field(ge=1)
    imported_at: datetime
    parser_version: str = "offline-v2"
    mapping_sha256: str
    schema_support: str = "configured_mapping_unverified_export"
    time_meaning: str = "unknown"


class Observation(Contract):
    fingerprint: str
    kind: Literal["inventory", "vulnerability", "coverage"]
    asset: AssetEvidence
    observed_at: datetime | None
    first_observed_at: datetime | None = None
    provenance: Provenance
    vulnerability: VulnerabilityEvidence | None = None
    coverage: CoverageEvidence | None = None
    native_status: str | None = Field(default=None, max_length=128)
    raw: dict[str, Any]
    warnings: tuple[str, ...] = ()


class ParsedRow(Contract):
    record_number: int
    file_sha256: str | None = None
    instance: str | None = None
    observation: Observation | None = None
    error: str | None = None


class Candidate(Contract):
    asset_id: str
    evidence: AssetEvidence
    observed_at: datetime | None


class Decision(Contract):
    action: Literal["match", "review", "create", "retain"]
    rule: str
    explanation: str
    confidence: float
    candidate_ids: tuple[str, ...] = ()
    matched_keys: tuple[tuple[str, ...], ...] = ()


class PreviewItem(Contract):
    observation: Observation
    decision: Decision
    current_assignment: dict[str, Any] | None = None


class Preview(Contract):
    total_rows: int
    valid_rows: int
    error_rows: int
    duplicate_rows: int
    total: int
    offset: int
    limit: int
    truncated: bool
    items: tuple[PreviewItem, ...]
    errors: tuple[ParsedRow, ...]
    errors_truncated: bool
    action_counts: dict[str, int]
    candidate_checks: int
    persisted: bool = False
    revision: int | None = None
    preview_token: str | None = None
