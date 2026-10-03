from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any, BinaryIO, TextIO

from defusedxml import ElementTree  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]

from vulnbatch.imports.common import build_normalized_record
from vulnbatch.imports.models import ImportParseError, NormalizedImportRecord, UnsafeXmlError

_HOST_PROPERTY_FIELDS = {
    "host-ip": "ip_address",
    "host-fqdn": "fqdn",
    "netbios-name": "short_hostname",
    "operating-system": "operating_system",
    "mac-address": "mac_address",
    "host-uuid": "nessus_host_id",
    "agent-uuid": "agent_uuid",
    "bios-uuid": "hardware_uuid",
    "hardware-uuid": "hardware_uuid",
    "host_start": "first_observed",
    "host_end": "last_observed",
}
_ITEM_FIELDS = {
    "risk_factor": "risk_factor",
    "cvss_base_score": "cvss_v2_score",
    "cvss3_base_score": "cvss_v3_score",
    "vpr_score": "vpr_score",
    "epss_score": "epss_score",
    "synopsis": "synopsis",
    "description": "description",
    "solution": "solution",
    "plugin_output": "plugin_output",
    "plugin_publication_date": "plugin_publication_date",
    "plugin_modification_date": "plugin_modification_date",
    "exploit_available": "exploit_available",
    "exploited_by_malware": "exploited_by_malware",
    "cisa_known_exploited": "known_exploited",
}


def parse_nessus_xml(
    stream: BinaryIO | TextIO,
    *,
    tracked_severities: Iterable[str] = ("medium", "low"),
) -> Iterator[NormalizedImportRecord]:
    record_number = 0
    try:
        context = ElementTree.iterparse(
            stream,
            events=("end",),
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
        for _event, element in context:
            if _local_name(element.tag) != "ReportHost":
                continue
            host_properties = _host_properties(element)
            host_name = element.attrib.get("name")
            if host_name and not any(
                host_properties.get(field) for field in ("ip_address", "fqdn", "short_hostname")
            ):
                host_properties["host"] = host_name

            for report_item in element:
                if _local_name(report_item.tag) != "ReportItem":
                    continue
                record_number += 1
                values = dict(host_properties)
                values.update(_report_item_values(report_item))
                values["scan_time"] = host_properties.get("last_observed")
                raw_record = {
                    "report_host": host_name,
                    "host_properties": dict(host_properties),
                    "report_item": _element_evidence(report_item),
                }
                yield build_normalized_record(
                    values,
                    raw_record=raw_record,
                    record_number=record_number,
                    scanner_source="nessus",
                    tracked_severities=tracked_severities,
                )
            element.clear()
    except DefusedXmlException as exc:
        raise UnsafeXmlError(f"Unsafe Nessus XML was rejected: {exc}") from exc
    except ElementTree.ParseError as exc:
        raise ImportParseError(f"Malformed Nessus XML: {exc}") from exc

    if record_number == 0:
        raise ImportParseError("Nessus XML did not contain any ReportItem findings")


def _host_properties(report_host: Any) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for child in report_host:
        if _local_name(child.tag) != "HostProperties":
            continue
        for tag in child:
            if _local_name(tag.tag) != "tag":
                continue
            name = (tag.attrib.get("name") or "").casefold()
            canonical = _HOST_PROPERTY_FIELDS.get(name)
            if canonical is not None:
                values[canonical] = tag.text
        break
    return values


def _report_item_values(report_item: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "plugin_id": report_item.attrib.get("pluginID"),
        "plugin_name": report_item.attrib.get("pluginName"),
        "plugin_family": report_item.attrib.get("pluginFamily"),
        "severity": report_item.attrib.get("severity"),
        "port": report_item.attrib.get("port"),
        "protocol": report_item.attrib.get("protocol"),
        "service": report_item.attrib.get("svc_name"),
    }
    cves: list[str] = []
    for child in report_item:
        name = _local_name(child.tag)
        if name == "cve" and child.text:
            cves.append(child.text)
            continue
        canonical = _ITEM_FIELDS.get(name)
        if canonical is not None:
            values[canonical] = child.text
    values["cves"] = cves
    return values


def _element_evidence(element: Any) -> dict[str, Any]:
    children: dict[str, Any] = {}
    for child in element:
        key = _local_name(child.tag)
        text = child.text
        if key in children:
            current = children[key]
            if isinstance(current, list):
                current.append(text)
            else:
                children[key] = [current, text]
        else:
            children[key] = text
    return {"attributes": dict(element.attrib), "children": children}


def _local_name(tag: object) -> str:
    text = str(tag)
    return text.rsplit("}", 1)[-1]
