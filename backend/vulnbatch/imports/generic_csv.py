from __future__ import annotations

import csv
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import TextIO

from pydantic import BaseModel, ConfigDict, Field

from vulnbatch.imports.common import build_normalized_record, normalized_header
from vulnbatch.imports.models import ImportParseError, NormalizedImportRecord, ParseWarning

CANONICAL_GENERIC_FIELDS = frozenset(
    {
        "tenable_asset_uuid",
        "nessus_host_id",
        "agent_uuid",
        "hardware_uuid",
        "mac_address",
        "fqdn",
        "short_hostname",
        "host",
        "ip_address",
        "ipv4_address",
        "ipv6_address",
        "operating_system",
        "asset_tags",
        "scanner_repository",
        "scan_zone",
        "scan_target",
        "first_observed",
        "last_observed",
        "plugin_id",
        "plugin_name",
        "plugin_family",
        "severity",
        "risk_factor",
        "cvss_v2_score",
        "cvss_v3_score",
        "vpr_score",
        "epss_score",
        "cves",
        "port",
        "protocol",
        "service",
        "synopsis",
        "description",
        "solution",
        "plugin_output",
        "first_found",
        "last_found",
        "plugin_publication_date",
        "plugin_modification_date",
        "cve_publication_date",
        "vendor_advisory_date",
        "exploit_available",
        "exploited_by_malware",
        "known_exploited",
        "scan_name",
        "scan_time",
        "source_import_id",
    }
)


class GenericCsvPreview(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    headers: tuple[str, ...]
    records: tuple[NormalizedImportRecord, ...]
    mapping_warnings: tuple[ParseWarning, ...]
    unmapped_columns: tuple[str, ...]
    truncated: bool
    preview_limit: int = Field(ge=1)


def validate_generic_mapping(
    headers: Sequence[str],
    mapping: Mapping[str, str],
) -> tuple[ParseWarning, ...]:
    warnings: list[ParseWarning] = []
    header_lookup: dict[str, str] = {}
    for header in headers:
        key = normalized_header(header)
        if key in header_lookup:
            warnings.append(
                ParseWarning(
                    code="duplicate_normalized_header",
                    message="More than one source column normalizes to the same name.",
                    field=header,
                )
            )
        else:
            header_lookup[key] = header

    for canonical, source_column in mapping.items():
        if canonical not in CANONICAL_GENERIC_FIELDS:
            warnings.append(
                ParseWarning(
                    code="unknown_canonical_field",
                    message="The mapping target is not an allowed canonical import field.",
                    field=canonical,
                    source_value=source_column,
                )
            )
            continue
        if normalized_header(source_column) not in header_lookup:
            warnings.append(
                ParseWarning(
                    code="missing_source_column",
                    message="The mapped source column is not present in the CSV header.",
                    field=canonical,
                    source_value=source_column,
                )
            )

    if "plugin_id" not in mapping:
        warnings.append(
            ParseWarning(
                code="missing_required_mapping",
                message="Generic CSV mapping requires a Plugin ID column.",
                field="plugin_id",
            )
        )
    if "severity" not in mapping and "risk_factor" not in mapping:
        warnings.append(
            ParseWarning(
                code="missing_required_mapping",
                message="Generic CSV mapping requires Severity or Risk Factor.",
                field="severity",
            )
        )
    return tuple(warnings)


def parse_generic_csv(
    stream: TextIO,
    *,
    mapping: Mapping[str, str],
    scanner_source: str = "generic_csv",
    tracked_severities: Iterable[str] = ("medium", "low"),
) -> Iterator[NormalizedImportRecord]:
    reader = csv.DictReader(stream)
    if reader.fieldnames is None:
        raise ImportParseError("Generic CSV is missing a header row")
    prepared_mapping, warnings = _prepare_mapping(reader.fieldnames, mapping)
    blocking = {
        "unknown_canonical_field",
        "missing_source_column",
        "missing_required_mapping",
        "duplicate_normalized_header",
    }
    if any(warning.code in blocking for warning in warnings):
        messages = "; ".join(warning.message for warning in warnings if warning.code in blocking)
        raise ImportParseError(f"Invalid generic CSV mapping: {messages}")

    for record_number, row in enumerate(reader, start=1):
        values = {canonical: row.get(source_column) for canonical, source_column in prepared_mapping.items()}
        yield build_normalized_record(
            values,
            raw_record={str(key): value for key, value in row.items()},
            record_number=record_number,
            scanner_source=scanner_source,
            tracked_severities=tracked_severities,
        )


def preview_generic_csv(
    stream: TextIO,
    *,
    mapping: Mapping[str, str],
    scanner_source: str = "generic_csv",
    tracked_severities: Iterable[str] = ("medium", "low"),
    limit: int = 20,
) -> GenericCsvPreview:
    if limit < 1:
        raise ValueError("limit must be positive")
    reader = csv.DictReader(stream)
    if reader.fieldnames is None:
        raise ImportParseError("Generic CSV is missing a header row")
    headers = tuple(reader.fieldnames)
    prepared_mapping, warnings = _prepare_mapping(headers, mapping)
    records: list[NormalizedImportRecord] = []
    truncated = False
    for record_number, row in enumerate(reader, start=1):
        if record_number > limit:
            truncated = True
            break
        values = {canonical: row.get(source_column) for canonical, source_column in prepared_mapping.items()}
        records.append(
            build_normalized_record(
                values,
                raw_record={str(key): value for key, value in row.items()},
                record_number=record_number,
                scanner_source=scanner_source,
                tracked_severities=tracked_severities,
            )
        )
    mapped_headers = set(prepared_mapping.values())
    return GenericCsvPreview(
        headers=headers,
        records=tuple(records),
        mapping_warnings=warnings,
        unmapped_columns=tuple(header for header in headers if header not in mapped_headers),
        truncated=truncated,
        preview_limit=limit,
    )


def _prepare_mapping(
    headers: Sequence[str],
    mapping: Mapping[str, str],
) -> tuple[dict[str, str], tuple[ParseWarning, ...]]:
    warnings = validate_generic_mapping(headers, mapping)
    header_lookup: dict[str, str] = {}
    for header in headers:
        header_lookup.setdefault(normalized_header(header), header)
    prepared = {
        canonical: header_lookup[normalized_header(source)]
        for canonical, source in mapping.items()
        if canonical in CANONICAL_GENERIC_FIELDS and normalized_header(source) in header_lookup
    }
    return prepared, warnings
