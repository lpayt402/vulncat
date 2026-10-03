from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Iterator, Mapping
from io import TextIOBase
from typing import Any, TextIO

from vulnbatch.imports.common import (
    build_normalized_record,
    clean_mapping,
    first_value,
    normalized_header,
)
from vulnbatch.imports.models import ImportParseError, NormalizedImportRecord

_ALIASES: dict[str, tuple[str, ...]] = {
    "tenable_asset_uuid": ("asset uuid", "asset_uuid", "asset.uuid", "asset id"),
    "agent_uuid": ("agent uuid", "agent_uuid", "asset.agent_uuid"),
    "hardware_uuid": ("hardware uuid", "bios uuid", "asset.bios_uuid", "asset.hardware_uuid"),
    "mac_address": ("mac address", "mac", "asset.mac_address"),
    "fqdn": ("fqdn", "dns name", "asset.fqdn"),
    "short_hostname": ("netbios name", "short hostname", "asset.netbios_name"),
    "host": ("host", "hostname", "asset.hostname", "asset.name"),
    "ip_address": ("ip address", "ip", "host ip", "asset.ipv4", "asset.ip"),
    "ipv6_address": ("ipv6 address", "ipv6", "asset.ipv6"),
    "operating_system": ("operating system", "os", "asset.operating_system"),
    "asset_tags": ("asset tags", "tags", "asset.tags"),
    "scanner_repository": ("repository", "scanner repository", "repository name"),
    "scan_zone": ("scan zone", "zone"),
    "scan_target": ("scan target", "target"),
    "first_observed": ("asset first seen", "asset first observed", "asset.first_observed"),
    "last_observed": (
        "asset last seen",
        "asset last observed",
        "last observed",
        "asset.last_observed",
    ),
    "plugin_id": ("plugin id", "plugin_id", "plugin.id", "id"),
    "plugin_name": ("plugin name", "name", "plugin.name"),
    "plugin_family": ("plugin family", "family", "plugin.family"),
    "severity": ("severity", "finding.severity"),
    "risk_factor": ("risk factor", "risk_factor", "finding.risk_factor"),
    "cvss_v2_score": ("cvss v2.0 base score", "cvss v2 base score", "cvss_base_score"),
    "cvss_v3_score": ("cvss v3.0 base score", "cvss v3 base score", "cvss3_base_score"),
    "vpr_score": ("vpr score", "vpr", "vpr_score"),
    "epss_score": ("epss score", "epss", "epss_score"),
    "cves": ("cve", "cves", "finding.cves"),
    "port": ("port", "finding.port"),
    "protocol": ("protocol", "finding.protocol"),
    "service": ("service", "svc_name", "finding.service"),
    "synopsis": ("synopsis", "finding.synopsis"),
    "description": ("description", "finding.description"),
    "solution": ("solution", "finding.solution"),
    "plugin_output": ("plugin output", "plugin_output", "finding.plugin_output", "output"),
    "first_found": ("first found", "first discovered", "finding.first_found"),
    "last_found": ("last found", "last seen", "finding.last_found"),
    "plugin_publication_date": (
        "plugin publication date",
        "plugin published",
        "plugin_publication_date",
    ),
    "plugin_modification_date": (
        "plugin modification date",
        "plugin modified",
        "plugin_modification_date",
    ),
    "cve_publication_date": ("cve publication date", "cve_publication_date"),
    "vendor_advisory_date": ("vendor advisory date", "patch release date"),
    "exploit_available": ("exploit available", "exploit?", "exploit_available"),
    "exploited_by_malware": (
        "exploited by malware",
        "exploited_by_malware",
        "malware exploitable",
    ),
    "known_exploited": (
        "known exploited",
        "known exploited vulnerability",
        "cisa known exploited",
        "cisa_known_exploited",
    ),
    "scan_name": ("scan name", "scan", "source scan"),
    "scan_time": ("scan time", "scan date", "scan completed", "last observed"),
}


def parse_tenable_csv(
    stream: TextIO,
    *,
    tracked_severities: Iterable[str] = ("medium", "low"),
) -> Iterator[NormalizedImportRecord]:
    reader = csv.DictReader(stream)
    if reader.fieldnames is None:
        raise ImportParseError("Tenable CSV is missing a header row")
    if not any(normalized_header(name) in _alias_keys("plugin_id") for name in reader.fieldnames):
        raise ImportParseError("Tenable CSV does not contain a recognized Plugin ID column")
    for record_number, row in enumerate(reader, start=1):
        normalized_row = clean_mapping(row)
        values = _canonical_values(normalized_row)
        yield build_normalized_record(
            values,
            raw_record={str(key): value for key, value in row.items()},
            record_number=record_number,
            scanner_source="tenable_vm",
            tracked_severities=tracked_severities,
        )


def parse_tenable_json(
    stream: TextIO,
    *,
    tracked_severities: Iterable[str] = ("medium", "low"),
) -> Iterator[NormalizedImportRecord]:
    for record_number, item in enumerate(_iter_json_records(stream), start=1):
        flattened = _flatten_mapping(item)
        values = _canonical_values(flattened)
        yield build_normalized_record(
            values,
            raw_record=item,
            record_number=record_number,
            scanner_source="tenable_vm",
            tracked_severities=tracked_severities,
        )


def _canonical_values(normalized_values: Mapping[str, Any]) -> dict[str, Any]:
    return {canonical: first_value(normalized_values, aliases) for canonical, aliases in _ALIASES.items()}


def _alias_keys(canonical: str) -> frozenset[str]:
    return frozenset(normalized_header(alias) for alias in _ALIASES[canonical])


def _flatten_mapping(item: Mapping[str, Any]) -> dict[str, Any]:
    flattened: dict[str, Any] = {}

    def visit(prefix: str, value: Any) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                visit(path, child)
            return
        normalized_path = normalized_header(prefix)
        leaf = normalized_header(prefix.rsplit(".", 1)[-1])
        flattened[normalized_path] = value
        flattened.setdefault(leaf, value)

    visit("", item)
    return flattened


def _iter_json_records(stream: TextIO) -> Iterator[dict[str, Any]]:
    if not isinstance(stream, TextIOBase) and not hasattr(stream, "read"):
        raise TypeError("stream must be a text file-like object")
    text = stream.read()
    if not text.strip():
        raise ImportParseError("Tenable JSON is empty")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        yield from _iter_ndjson(text)
        return
    yield from _records_from_payload(payload)


def _iter_ndjson(text: str) -> Iterator[dict[str, Any]]:
    found = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        found = True
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ImportParseError(f"Invalid Tenable JSON on line {line_number}: {exc.msg}") from exc
        if not isinstance(item, dict):
            raise ImportParseError(f"Tenable JSON line {line_number} must contain an object")
        yield item
    if not found:
        raise ImportParseError("Tenable JSON is empty")


def _records_from_payload(payload: Any) -> Iterator[dict[str, Any]]:
    if isinstance(payload, list):
        for index, item in enumerate(payload, start=1):
            if not isinstance(item, dict):
                raise ImportParseError(f"Tenable JSON record {index} must contain an object")
            yield item
        return
    if isinstance(payload, dict):
        for key in ("findings", "vulnerabilities", "results", "items"):
            records = payload.get(key)
            if isinstance(records, list):
                for index, item in enumerate(records, start=1):
                    if not isinstance(item, dict):
                        raise ImportParseError(f"Tenable JSON {key} record {index} must contain an object")
                    yield item
                return
        yield payload
        return
    raise ImportParseError("Tenable JSON must contain an object or an array of objects")
