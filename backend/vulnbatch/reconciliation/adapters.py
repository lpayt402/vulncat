from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from ipaddress import ip_interface
from typing import Any, TextIO

from pydantic import ValidationError

from vulnbatch.identity.normalization import (
    clean_text,
    infer_host_identifier,
    normalize_hostname,
    normalize_mac,
)
from vulnbatch.reconciliation.models import (
    CANONICAL_FIELDS,
    NETBOX_ASSET_ID_KINDS,
    AssetEvidence,
    CoverageEvidence,
    IdentityEvidence,
    Observation,
    ParsedRow,
    Provenance,
    SourceOptions,
    VulnerabilityEvidence,
)

FIELDS = CANONICAL_FIELDS
MISSING = object()
VULNERABILITY_FIELDS = frozenset(
    {
        "vulnerability_id",
        "occurrence_id",
        "title",
        "severity",
        "cves",
        "package",
        "package_version",
        "port",
        "protocol",
    }
)
COVERAGE_FIELDS = frozenset({"coverage_outcome", "complete", "authenticated"})
DEFAULT_ID_KINDS = {
    "crowdstrike": "aid",
    "pdq_connect": "device_id",
    "netbox": "unspecified_object_type",
    "active_directory": "object_guid",
    "inventory": "inventory_id",
    "nessus": "host_id",
}


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    ).hexdigest()


def _text(value: object) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, (str, int, float, bool)):
        raise ValueError("Mapped scalar field contains an object or list")
    text = str(value).strip()
    if "\x00" in text:
        raise ValueError("Mapped scalar strings cannot contain NUL characters")
    return text or None


def _identifier(value: object) -> str | None:
    if isinstance(value, bool):
        raise ValueError("Native/hardware asset identifiers cannot be booleans")
    text = clean_text(_text(value))
    if text is None:
        return None
    compact = text.casefold().strip("{}").replace("-", "")
    if compact in {"0" * 32, "f" * 32, "to be filled by o.e.m.", "default string", "nan", "undefined"}:
        return None
    return text


def _at(row: Mapping[str, Any], path: str) -> Any:
    # Exact CSV headers win over dotted JSON paths.
    if path in row:
        return row[path]
    value: Any = row
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return MISSING
        value = value[part]
    return value


def _time(value: object, field: str) -> datetime | None:
    text = _text(value)
    if text is None:
        return None
    try:
        result = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} requires an ISO 8601 timestamp with timezone") from exc
    if result.tzinfo is None:
        raise ValueError(f"{field} requires a timezone; mapping must not guess local time")
    try:
        return result.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{field} is outside the supported UTC timestamp range") from exc


def _bool(value: object, field: str) -> bool | None:
    text = _text(value)
    if text is None:
        return None
    if text.casefold() in {"true", "yes", "1"}:
        return True
    if text.casefold() in {"false", "no", "0"}:
        return False
    raise ValueError(f"{field} requires true or false")


def _populated(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True  # False and port zero are real supplied evidence.


def _cves(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        members = [member.strip() for member in value.replace(",", ";").split(";") if member.strip()]
    elif isinstance(value, list) and all(isinstance(member, str) and member.strip() for member in value):
        members = value
    else:
        raise ValueError("cves requires a string or a list of nonempty strings; flatten objects explicitly")
    return tuple(sorted({member.strip().upper() for member in members}))


def normalize_row(
    raw: dict[str, Any],
    options: SourceOptions,
    *,
    file_hash: str,
    record_number: int,
    imported_at: datetime,
    schema_support: str = "configured_mapping_unverified_export",
) -> Observation:
    mapping = options.mapping or {field: field for field in FIELDS}
    values: dict[str, Any] = {}
    for field, path in mapping.items():
        value = _at(raw, path)
        if value is MISSING:
            if options.mapping:
                raise ValueError(f"Mapped field {field} has an unresolved source path: {path}")
            continue
        if field not in {"ip", "cves"}:
            try:
                _text(value)
            except ValueError as exc:
                raise ValueError(f"{field}: {exc}") from exc
        values[field] = value
    cves = _cves(values.get("cves"))
    native = _identifier(values.get("native_id"))
    native_kind = _text(values.get("native_id_kind")) or DEFAULT_ID_KINDS[options.source]
    if options.source == "netbox" and native_kind not in NETBOX_ASSET_ID_KINDS | {"unspecified_object_type"}:
        raise ValueError(
            "Unsupported NetBox native_id_kind; only dcim.device and virtualization.virtualmachine "
            "identify assets. IP/interface objects require explicit device/VM join evidence."
        )
    native_ids = (
        ()
        if native is None
        else (
            IdentityEvidence(
                source=options.source,
                instance=options.instance,
                kind=native_kind,
                value=native,
            ),
        )
    )
    for field in ("fqdn", "hostname", "short_hostname"):
        supplied = _text(values.get(field))
        if supplied is not None and len(supplied) > 255:
            raise ValueError(f"{field} must be 255 characters or shorter")
    inferred = infer_host_identifier(_text(values.get("fqdn")) or _text(values.get("hostname")))
    fqdn = inferred.get("fqdn")
    hostname = fqdn or inferred.get("short_hostname")
    short = normalize_hostname(_text(values.get("short_hostname"))) or (
        hostname.split(".")[0] if hostname else None
    )
    raw_ips = values.get("ip")
    ip_values = raw_ips if isinstance(raw_ips, list) else ((_text(raw_ips) or "").split(";"))
    target_ip = inferred.get("ipv4") or inferred.get("ipv6")
    ips = tuple(
        sorted(
            {
                str(ip_interface(str(ip).strip()).ip)
                for ip in (*ip_values, target_ip)
                if ip is not None and str(ip).strip()
            }
        )
    )
    mac_raw = _text(values.get("mac_address"))
    mac = normalize_mac(mac_raw)
    if mac_raw and not mac:
        raise ValueError("Invalid MAC address")
    hardware = _identifier(values.get("hardware_uuid"))
    asset = AssetEvidence(
        native_ids=native_ids,
        hardware_uuid=hardware.casefold() if hardware else None,
        fqdn=fqdn,
        short_hostname=short,
        ip_addresses=ips,
        mac_address=mac,
        operating_system=_text(values.get("operating_system")),
        network_scope=options.network_scope,
    )
    if not (native_ids or hostname or short or ips or mac or hardware):
        raise ValueError("No usable asset identifier; configure an ID, hostname, IP or hardware mapping")
    observed = _time(values.get("observed_at"), "observed_at")
    first = _time(values.get("first_observed_at"), "first_observed_at")
    if first and observed and first > observed:
        raise ValueError("first_observed_at is later than observed_at")
    vuln_id = _text(values.get("vulnerability_id"))
    kind = _text(values.get("kind"))
    if "kind" in values and kind is None:
        raise ValueError("kind must be inventory, vulnerability or coverage when present or mapped")
    vulnerability_present = any(_populated(values.get(field)) for field in VULNERABILITY_FIELDS)
    coverage_present = any(_populated(values.get(field)) for field in COVERAGE_FIELDS)
    if kind is None:
        vulnerability_declared = vulnerability_present or bool(set(options.mapping) & VULNERABILITY_FIELDS)
        coverage_declared = coverage_present or bool(set(options.mapping) & COVERAGE_FIELDS)
        if vulnerability_declared and coverage_declared:
            raise ValueError("Vulnerability and coverage fields conflict; split them into separate records")
        kind = "vulnerability" if vulnerability_declared else "coverage" if coverage_declared else "inventory"
    if (kind != "vulnerability" and vulnerability_present) or (kind != "coverage" and coverage_present):
        raise ValueError(
            "Mapped evidence conflicts with kind; split inventory, vulnerability and coverage records"
        )
    native_status = _text(values.get("native_status"))
    vulnerability = None
    coverage = None
    if kind == "vulnerability":
        if not vuln_id:
            raise ValueError("Vulnerability row needs vulnerability_id, distinct from native asset ID")
        vulnerability = VulnerabilityEvidence(
            vulnerability_id=vuln_id,
            occurrence_id=_text(values.get("occurrence_id")),
            title=_text(values.get("title")),
            severity=_text(values.get("severity")),
            cves=cves,
            package=_text(values.get("package")),
            package_version=_text(values.get("package_version")),
            port=values.get("port") if values.get("port") != "" else None,
            protocol=_text(values.get("protocol")),
            native_status=native_status,
        )
    elif kind == "coverage":
        outcome = _text(values.get("coverage_outcome"))
        if outcome is None:
            raise ValueError("Coverage row needs coverage_outcome; use unknown explicitly if it is unknown")
        coverage = CoverageEvidence.model_validate(
            {
                "outcome": outcome,
                "complete": _bool(values.get("complete"), "complete") or False,
                "authenticated": _bool(values.get("authenticated"), "authenticated"),
                "native_status": native_status,
            }
        )
        if coverage.complete and coverage.outcome != "successful":
            raise ValueError("Failed or partial coverage cannot be complete")
    elif kind != "inventory":
        raise ValueError("kind must be inventory, vulnerability or coverage")
    warnings = []
    if observed is None:
        warnings.append("missing_observed_at")
    if options.time_meaning != "source_observed":
        warnings.append("timestamp_does_not_establish_scan_or_reachability")
    if ips and not options.network_scope:
        warnings.append("missing_network_scope")
    if vulnerability and not vulnerability.occurrence_id:
        warnings.append("missing_native_occurrence_id")
    provenance = Provenance(
        source=options.source,
        instance=options.instance,
        file_sha256=file_hash,
        record_number=record_number,
        imported_at=imported_at,
        mapping_sha256=digest(options.model_dump(mode="json")),
        schema_support=schema_support,
        time_meaning=options.time_meaning,
    )
    event = {
        "source": options.source,
        "instance": options.instance,
        "parser": provenance.parser_version,
        "mapping": provenance.mapping_sha256,
        "raw": raw,
    }
    return Observation.model_validate(
        {
            "fingerprint": digest(event),
            "kind": kind,
            "asset": asset,
            "observed_at": observed,
            "first_observed_at": first,
            "vulnerability": vulnerability,
            "coverage": coverage,
            "native_status": native_status,
            "provenance": provenance,
            "raw": raw,
            "warnings": tuple(warnings),
        }
    )


def _raw_rows(stream: TextIO, options: SourceOptions) -> Iterator[dict[str, Any] | str]:
    if options.format == "csv":
        reader = csv.DictReader(stream)
        headers = reader.fieldnames or []
        if not headers:
            raise ValueError("CSV header is missing")
        if len(headers) != len(set(headers)):
            raise ValueError("Duplicate CSV headers are ambiguous")
        missing = set(options.mapping.values()) - set(headers)
        if missing:
            raise ValueError(f"Mapped columns absent from CSV: {', '.join(sorted(missing))}")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                yield "CSV row width differs from header"
            else:
                yield row
    elif options.format == "ndjson":
        for line in stream:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                yield row if isinstance(row, dict) else "JSON record must be an object"
            except ValueError:
                yield "Malformed NDJSON record"
    elif options.format == "json":
        # Arrays are deliberately bounded by the HTTP upload limit; NDJSON streams.
        try:
            data = json.load(stream)
        except ValueError as exc:
            raise ValueError("Malformed JSON document") from exc
        if options.records_path:
            if not isinstance(data, dict):
                raise ValueError("records_path requires a JSON object envelope")
            data = _at(data, options.records_path)
        if not isinstance(data, list):
            raise ValueError("JSON must be an array; select records_path for an envelope")
        for row in data:
            yield row if isinstance(row, dict) else "JSON record must be an object"
    else:
        raise ValueError("Use the Nessus XML adapter for nessus_xml")


def parse_rows(
    stream: TextIO,
    options: SourceOptions,
    *,
    file_hash: str,
    imported_at: datetime,
) -> Iterator[ParsedRow]:
    if set(options.mapping) - set(FIELDS):
        raise ValueError("Unknown mapping fields: " + ", ".join(sorted(set(options.mapping) - set(FIELDS))))
    for number, raw in enumerate(_raw_rows(stream, options), 1):
        if isinstance(raw, str):
            yield ParsedRow(record_number=number, file_sha256=file_hash, instance=options.instance, error=raw)
            continue
        try:
            yield ParsedRow(
                record_number=number,
                file_sha256=file_hash,
                instance=options.instance,
                observation=normalize_row(
                    raw,
                    options,
                    file_hash=file_hash,
                    record_number=number,
                    imported_at=imported_at,
                ),
            )
        except (ValueError, ValidationError) as exc:
            yield ParsedRow(
                record_number=number, file_sha256=file_hash, instance=options.instance, error=str(exc)[:500]
            )
