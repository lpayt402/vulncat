from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, BinaryIO

from defusedxml import ElementTree  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]

from vulnbatch.identity.normalization import infer_host_identifier
from vulnbatch.imports.models import ImportParseError, UnsafeXmlError
from vulnbatch.imports.nessus import _element_evidence, _host_properties, _local_name, _report_item_values
from vulnbatch.reconciliation.adapters import normalize_row
from vulnbatch.reconciliation.models import ParsedRow, SourceOptions


def _timestamp(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text), UTC).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    try:
        time = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return time.isoformat() if time.tzinfo else None


def _raw_element(element: Any) -> dict[str, Any]:
    # Keep names, attributes, repeated tags and text independently of the field adapter.
    return {
        "tag": str(element.tag),
        "attributes": dict(element.attrib),
        "text": element.text,
        "tail": element.tail,
        "children": [_raw_element(child) for child in element],
    }


def parse_nessus_observations(
    stream: BinaryIO,
    options: SourceOptions,
    *,
    file_hash: str,
    imported_at: datetime,
) -> Iterator[ParsedRow]:
    if options.source != "nessus" or options.mapping:
        raise ValueError("Nessus XML requires source nessus and its fixed field adapter")
    record_number = 0
    try:
        context = ElementTree.iterparse(
            stream,
            events=("end",),
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
        for _, host in context:
            if _local_name(host.tag) != "ReportHost":
                continue
            props = _host_properties(host)
            fallback = infer_host_identifier(host.get("name"))
            base: dict[str, Any] = {
                "nessus_report_host": {
                    "attributes": dict(host.attrib),
                    "host_properties": [
                        _raw_element(child) for child in host if _local_name(child.tag) == "HostProperties"
                    ],
                },
                "native_id": props.get("nessus_host_id"),
                "hostname": props.get("fqdn") or fallback.get("fqdn"),
                "short_hostname": props.get("short_hostname") or fallback.get("short_hostname"),
                "ip": props.get("ip_address") or fallback.get("ipv4") or fallback.get("ipv6"),
                "mac_address": props.get("mac_address"),
                "hardware_uuid": props.get("hardware_uuid"),
                "operating_system": props.get("operating_system"),
                "observed_at": _timestamp(props.get("last_observed")),
                "first_observed_at": _timestamp(props.get("first_observed")),
            }
            items = [item for item in host if _local_name(item.tag) == "ReportItem"]
            all_values = [base]
            for item in items:
                finding = _report_item_values(item)
                all_values.append(
                    {
                        **base,
                        "kind": "vulnerability",
                        "vulnerability_id": finding.get("plugin_id"),
                        "title": finding.get("plugin_name"),
                        "severity": finding.get("severity"),
                        "port": finding.get("port"),
                        "protocol": finding.get("protocol"),
                        "cves": finding.get("cves"),
                        "report_item": _element_evidence(item),
                    }
                )
            for values in all_values:
                record_number += 1
                values["nessus_host_properties"] = props
                try:
                    observation = normalize_row(
                        values,
                        options,
                        file_hash=file_hash,
                        record_number=record_number,
                        imported_at=imported_at,
                        schema_support="nessus_reporthost_reportitem_subset",
                    )
                    warnings = list(observation.warnings)
                    if not items:
                        warnings.append("no_report_items_not_proof_of_clean_scan")
                    if props.get("last_observed") and base["observed_at"] is None:
                        warnings.append("nessus_timestamp_timezone_unknown_or_invalid")
                    observation = observation.model_copy(update={"warnings": tuple(warnings)})
                    yield ParsedRow(
                        record_number=record_number,
                        file_sha256=file_hash,
                        instance=options.instance,
                        observation=observation,
                    )
                except ValueError as exc:
                    yield ParsedRow(
                        record_number=record_number,
                        file_sha256=file_hash,
                        instance=options.instance,
                        error=str(exc)[:500],
                    )
            host.clear()
        if record_number == 0:
            raise ImportParseError("Nessus XML contains no ReportHost observations")
    except DefusedXmlException as exc:
        raise UnsafeXmlError(f"Unsafe Nessus XML was rejected: {exc}") from exc
    except ElementTree.ParseError as exc:
        raise ImportParseError("Malformed Nessus XML") from exc
