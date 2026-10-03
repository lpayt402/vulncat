from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, date, datetime
from typing import Any

from vulnbatch.identity.normalization import (
    clean_text,
    infer_host_identifier,
    normalize_hostname,
    normalize_identifier,
    normalize_ip,
    normalize_mac,
)
from vulnbatch.imports.models import (
    NormalizedAsset,
    NormalizedFinding,
    NormalizedImportRecord,
    ParseWarning,
)

_SEVERITY_NUMBERS = {
    "0": "informational",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}
_SEVERITY_NAMES = {
    "info": "informational",
    "informational": "informational",
    "none": "informational",
    "low": "low",
    "medium": "medium",
    "med": "medium",
    "high": "high",
    "critical": "critical",
    "crit": "critical",
}
_TRUE_VALUES = frozenset({"1", "true", "yes", "y", "available", "enabled"})
_FALSE_VALUES = frozenset({"0", "false", "no", "n", "unavailable", "disabled"})
_DATE_FORMATS = (
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%m/%d/%Y",
    "%b %d, %Y",
    "%a %b %d %H:%M:%S %Y",
)
_DATETIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%a %b %d %H:%M:%S %Y",
)
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def normalized_header(value: object) -> str:
    text = clean_text(value) or ""
    return re.sub(r"[^a-z0-9]+", "", text.casefold())


def clean_mapping(values: Mapping[str, Any]) -> dict[str, Any]:
    return {normalized_header(key): value for key, value in values.items()}


def first_value(values: Mapping[str, Any], aliases: Iterable[str]) -> Any:
    for alias in aliases:
        key = normalized_header(alias)
        if key in values and clean_text(values[key]) is not None:
            return values[key]
    return None


def parse_datetime(value: object) -> datetime | None:
    text = clean_text(value)
    if text is None:
        return None
    iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(iso_text)
    except ValueError:
        parsed = None
    if parsed is None:
        for fmt in _DATETIME_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        parsed_date = parse_date(text)
        if parsed_date is None:
            return None
        parsed = datetime.combine(parsed_date, datetime.min.time())
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def parse_date(value: object) -> date | None:
    text = clean_text(value)
    if text is None:
        return None
    iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        return datetime.fromisoformat(iso_text).date()
    except ValueError:
        pass
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def parse_bool(value: object) -> bool | None:
    text = clean_text(value)
    if text is None:
        return None
    normalized = text.casefold()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return None


def parse_float(value: object) -> float | None:
    text = clean_text(value)
    if text is None:
        return None
    try:
        return float(text.rstrip("%"))
    except ValueError:
        return None


def parse_int(value: object) -> int | None:
    text = clean_text(value)
    if text is None:
        return None
    try:
        parsed = int(float(text))
    except ValueError:
        return None
    return parsed


def normalize_severity(value: object, *, risk_factor: object = None) -> str | None:
    text = clean_text(value)
    if text is not None:
        normalized = text.casefold()
        if normalized in _SEVERITY_NUMBERS:
            return _SEVERITY_NUMBERS[normalized]
        if normalized in _SEVERITY_NAMES:
            return _SEVERITY_NAMES[normalized]
    risk = clean_text(risk_factor)
    return _SEVERITY_NAMES.get(risk.casefold()) if risk is not None else None


def split_values(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    raw_values: Iterable[object]
    if isinstance(value, (list, tuple, set, frozenset)):
        raw_values = value
    else:
        text = clean_text(value)
        if text is None:
            return ()
        raw_values = re.split(r"[,;|\n]+", text)
    cleaned = [text for item in raw_values if (text := clean_text(item)) is not None]
    return tuple(dict.fromkeys(cleaned))


def split_cves(value: object) -> tuple[str, ...]:
    if isinstance(value, (list, tuple, set, frozenset)):
        joined = " ".join(str(item) for item in value)
    else:
        joined = clean_text(value) or ""
    return tuple(dict.fromkeys(match.upper() for match in _CVE_PATTERN.findall(joined)))


def build_normalized_record(
    values: Mapping[str, Any],
    *,
    raw_record: Mapping[str, Any],
    record_number: int,
    scanner_source: str,
    tracked_severities: Iterable[str] = ("medium", "low"),
) -> NormalizedImportRecord:
    warnings: list[ParseWarning] = []
    source = clean_text(scanner_source)
    if source is None:
        raise ValueError("scanner_source is required")
    source = source.casefold()

    host_values: dict[str, str] = {}
    host = values.get("host")
    if host is not None:
        host_values.update(infer_host_identifier(host))

    ipv4 = normalize_ip(values.get("ipv4_address") or values.get("ip_address"), version=4)
    ipv6 = normalize_ip(values.get("ipv6_address") or values.get("ip_address"), version=6)
    if ipv4 is not None:
        host_values["ipv4"] = ipv4
    if ipv6 is not None:
        host_values["ipv6"] = ipv6

    asset = NormalizedAsset(
        tenable_asset_uuid=_identifier_or_warning(
            "tenable_asset_uuid", values.get("tenable_asset_uuid"), warnings
        ),
        nessus_host_id=_identifier_or_warning("nessus_host_id", values.get("nessus_host_id"), warnings),
        agent_uuid=_identifier_or_warning("agent_uuid", values.get("agent_uuid"), warnings),
        hardware_uuid=_identifier_or_warning("hardware_uuid", values.get("hardware_uuid"), warnings),
        mac_address=_mac_or_warning(values.get("mac_address"), warnings),
        fqdn=normalize_hostname(values.get("fqdn")) or host_values.get("fqdn"),
        short_hostname=normalize_hostname(values.get("short_hostname")) or host_values.get("short_hostname"),
        ipv4_address=host_values.get("ipv4"),
        ipv6_address=host_values.get("ipv6"),
        operating_system=clean_text(values.get("operating_system")),
        asset_tags=split_values(values.get("asset_tags")),
        scanner_repository=clean_text(values.get("scanner_repository")),
        scan_zone=clean_text(values.get("scan_zone")),
        scan_target=clean_text(values.get("scan_target")),
        scanner_source=source,
        first_observed=parse_datetime(values.get("first_observed")),
        last_observed=parse_datetime(values.get("last_observed")),
    )

    plugin_id = clean_text(values.get("plugin_id"))
    if plugin_id is None:
        warnings.append(
            ParseWarning(
                code="missing_plugin_id",
                message="The record cannot enter the finding inventory without a plugin ID.",
                field="plugin_id",
            )
        )
    severity = normalize_severity(values.get("severity"), risk_factor=values.get("risk_factor"))
    if severity is None:
        warnings.append(
            ParseWarning(
                code="missing_or_unknown_severity",
                message="Severity was missing or not recognized.",
                field="severity",
                source_value=clean_text(values.get("severity")),
            )
        )

    port = parse_int(values.get("port"))
    if port is not None and not 0 <= port <= 65_535:
        warnings.append(
            ParseWarning(
                code="invalid_port",
                message="Port must be between 0 and 65535; the source value remains only in raw evidence.",
                field="port",
                source_value=clean_text(values.get("port")),
            )
        )
        port = None

    finding = NormalizedFinding(
        plugin_id=plugin_id,
        plugin_name=clean_text(values.get("plugin_name")),
        plugin_family=clean_text(values.get("plugin_family")),
        severity=severity,
        risk_factor=clean_text(values.get("risk_factor")),
        cvss_v2_score=parse_float(values.get("cvss_v2_score")),
        cvss_v3_score=parse_float(values.get("cvss_v3_score")),
        vpr_score=parse_float(values.get("vpr_score")),
        epss_score=parse_float(values.get("epss_score")),
        cves=split_cves(values.get("cves")),
        port=port,
        protocol=_lower_text(values.get("protocol")),
        service=clean_text(values.get("service")),
        synopsis=clean_text(values.get("synopsis")),
        description=clean_text(values.get("description")),
        solution=clean_text(values.get("solution")),
        plugin_output=clean_text(values.get("plugin_output")),
        first_found=parse_datetime(values.get("first_found")),
        last_found=parse_datetime(values.get("last_found")),
        plugin_publication_date=parse_date(values.get("plugin_publication_date")),
        plugin_modification_date=parse_date(values.get("plugin_modification_date")),
        cve_publication_date=parse_date(values.get("cve_publication_date")),
        vendor_advisory_date=parse_date(values.get("vendor_advisory_date")),
        exploit_available=parse_bool(values.get("exploit_available")),
        exploited_by_malware=parse_bool(values.get("exploited_by_malware")),
        known_exploited=parse_bool(values.get("known_exploited")),
        scan_name=clean_text(values.get("scan_name")),
        scan_time=parse_datetime(values.get("scan_time")),
        source_import_id=clean_text(values.get("source_import_id")),
    )
    tracked = frozenset(item.casefold() for item in tracked_severities)
    included = plugin_id is not None and severity in tracked
    raw = dict(raw_record)
    content_hash = hashlib.sha256(
        json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
    return NormalizedImportRecord(
        record_number=record_number,
        content_hash=content_hash,
        asset=asset,
        finding=finding,
        included_in_inventory=included,
        raw_record=raw,
        warnings=tuple(warnings),
    )


def _identifier_or_warning(
    identifier_type: str,
    value: object,
    warnings: list[ParseWarning],
) -> str | None:
    original = clean_text(value)
    normalized = normalize_identifier(identifier_type, value)
    if original is not None and normalized is None:
        warnings.append(
            ParseWarning(
                code="invalid_identifier",
                message=f"The {identifier_type} value was invalid and was treated as missing.",
                field=identifier_type,
                source_value=original,
            )
        )
    return normalized


def _mac_or_warning(value: object, warnings: list[ParseWarning]) -> str | None:
    original = clean_text(value)
    normalized = normalize_mac(value)
    if original is not None and normalized is None:
        warnings.append(
            ParseWarning(
                code="invalid_mac_address",
                message="The MAC address was invalid and was treated as missing.",
                field="mac_address",
                source_value=original,
            )
        )
    return normalized


def _lower_text(value: object) -> str | None:
    text = clean_text(value)
    return text.casefold() if text is not None else None
