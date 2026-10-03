from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ImportParseError(ValueError):
    """Raised when an import cannot be parsed safely or deterministically."""


class UnsafeXmlError(ImportParseError):
    """Raised when XML contains prohibited entities, DTDs, or related constructs."""


class ParseWarning(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str
    field: str | None = None
    source_value: str | None = None


class NormalizedAsset(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenable_asset_uuid: str | None = None
    nessus_host_id: str | None = None
    agent_uuid: str | None = None
    hardware_uuid: str | None = None
    mac_address: str | None = None
    fqdn: str | None = None
    short_hostname: str | None = None
    ipv4_address: str | None = None
    ipv6_address: str | None = None
    operating_system: str | None = None
    asset_tags: tuple[str, ...] = ()
    scanner_repository: str | None = None
    scan_zone: str | None = None
    scan_target: str | None = None
    scanner_source: str
    first_observed: datetime | None = None
    last_observed: datetime | None = None


class NormalizedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plugin_id: str | None = None
    plugin_name: str | None = None
    plugin_family: str | None = None
    severity: str | None = None
    risk_factor: str | None = None
    cvss_v2_score: float | None = None
    cvss_v3_score: float | None = None
    vpr_score: float | None = None
    epss_score: float | None = None
    cves: tuple[str, ...] = ()
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    synopsis: str | None = None
    description: str | None = None
    solution: str | None = None
    plugin_output: str | None = None
    first_found: datetime | None = None
    last_found: datetime | None = None
    plugin_publication_date: date | None = None
    plugin_modification_date: date | None = None
    cve_publication_date: date | None = None
    vendor_advisory_date: date | None = None
    exploit_available: bool | None = None
    exploited_by_malware: bool | None = None
    known_exploited: bool | None = None
    scan_name: str | None = None
    scan_time: datetime | None = None
    source_import_id: str | None = None


class NormalizedImportRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    record_number: int = Field(ge=1)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    asset: NormalizedAsset
    finding: NormalizedFinding
    included_in_inventory: bool
    raw_record: dict[str, Any]
    warnings: tuple[ParseWarning, ...] = ()
