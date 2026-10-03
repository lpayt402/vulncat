from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest

from vulnbatch.imports import (
    ImportParseError,
    UnsafeXmlError,
    parse_generic_csv,
    parse_nessus_xml,
    parse_tenable_csv,
    parse_tenable_json,
    preview_generic_csv,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_tenable_csv_normalizes_evidence_and_tracks_only_medium_low() -> None:
    with (FIXTURES / "tenable_vm.csv").open(encoding="utf-8", newline="") as stream:
        records = list(parse_tenable_csv(stream))

    assert len(records) == 2
    first = records[0]
    assert first.included_in_inventory is True
    assert first.asset.fqdn == "app-01.example.test"
    assert first.asset.ipv4_address == "192.0.2.10"
    assert first.asset.mac_address == "00:11:22:33:44:55"
    assert first.finding.plugin_id == "10001"
    assert first.finding.cves == ("CVE-2025-10001", "CVE-2025-10002")
    assert first.finding.port == 443
    assert first.raw_record["Plugin Name"] == "Example TLS Setting"
    assert records[1].finding.severity == "high"
    assert records[1].included_in_inventory is False
    assert records[0].content_hash != records[1].content_hash


def test_tenable_json_supports_nested_findings() -> None:
    with (FIXTURES / "tenable_vm.json").open(encoding="utf-8") as stream:
        records = list(parse_tenable_json(stream))

    assert len(records) == 1
    record = records[0]
    assert record.asset.tenable_asset_uuid == "33333333-3333-4333-8333-333333333333"
    assert record.asset.fqdn == "db-01.example.test"
    assert record.finding.plugin_id == "20001"
    assert record.finding.plugin_name == "Example Package Advisory"
    assert record.finding.severity == "low"
    assert record.included_in_inventory is True


def test_nessus_xml_uses_defused_parser_and_normalizes_report_item() -> None:
    with (FIXTURES / "sample.nessus").open("rb") as stream:
        records = list(parse_nessus_xml(stream))

    assert len(records) == 1
    record = records[0]
    assert record.asset.nessus_host_id == "nessus-example-host-42"
    assert record.asset.short_hostname == "web-02"
    assert record.asset.ipv4_address == "203.0.113.42"
    assert record.finding.plugin_id == "30001"
    assert record.finding.severity == "medium"
    assert record.finding.port == 22
    assert record.finding.plugin_output == "Safe synthetic plugin evidence."


def test_nessus_xml_rejects_external_entities() -> None:
    malicious = """<?xml version="1.0"?>
    <!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///synthetic-secret">]>
    <NessusClientData_v2><Report><ReportHost name="example">
      <HostProperties><tag name="host-ip">192.0.2.1</tag></HostProperties>
      <ReportItem pluginID="1" severity="2"><description>&xxe;</description></ReportItem>
    </ReportHost></Report></NessusClientData_v2>"""

    with pytest.raises(UnsafeXmlError):
        list(parse_nessus_xml(StringIO(malicious)))


def test_generic_csv_preview_reports_unmapped_columns_and_commit_is_deterministic() -> None:
    mapping = {
        "fqdn": "Server Name",
        "ip_address": "Address",
        "plugin_id": "Check",
        "severity": "Rating",
        "first_found": "First Seen",
        "solution": "Fix",
    }
    with (FIXTURES / "generic.csv").open(encoding="utf-8", newline="") as stream:
        preview = preview_generic_csv(stream, mapping=mapping, limit=1)
    assert preview.truncated is True
    assert preview.unmapped_columns == ("Unused Column",)
    assert preview.records[0].asset.fqdn == "batch-01.example.test"

    with (FIXTURES / "generic.csv").open(encoding="utf-8", newline="") as stream:
        records = list(parse_generic_csv(stream, mapping=mapping))
    assert [record.finding.plugin_id for record in records] == ["40001", "40002"]
    assert all(record.included_in_inventory for record in records)


def test_generic_csv_rejects_missing_required_mapping() -> None:
    with (
        (FIXTURES / "generic.csv").open(encoding="utf-8", newline="") as stream,
        pytest.raises(ImportParseError, match="Plugin ID"),
    ):
        list(parse_generic_csv(stream, mapping={"severity": "Rating"}))
