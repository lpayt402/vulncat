from __future__ import annotations

import json
from datetime import UTC, datetime
from io import BytesIO, StringIO
from pathlib import Path

import pytest

from vulnbatch.reconciliation.adapters import parse_rows
from vulnbatch.reconciliation.matching import EvidenceIndex
from vulnbatch.reconciliation.models import (
    AssetEvidence,
    Candidate,
    IdentityEvidence,
    ParsedRow,
    SourceOptions,
)
from vulnbatch.reconciliation.preview import summarize

NOW = datetime(2026, 10, 1, tzinfo=UTC)


def options(**changes: object) -> SourceOptions:
    return SourceOptions.model_validate(
        {
            "source": "inventory",
            "instance": "synthetic-csv",
            "format": "csv",
            **changes,
        }
    )


def rows(text: str, **changes: object) -> list[ParsedRow]:
    return list(parse_rows(StringIO(text), options(**changes), file_hash="a" * 64, imported_at=NOW))


def candidate(asset_id: str, **changes: object) -> Candidate:
    return Candidate(asset_id=asset_id, evidence=AssetEvidence.model_validate(changes), observed_at=NOW)


def test_inventory_does_not_require_vulnerability_and_missing_time_stays_unknown() -> None:
    result = rows("native_id,hostname,ip\ninv-1,Renamed.Example.Test.,192.0.2.10\n")[0]
    assert result.observation is not None
    assert result.observation.kind == "inventory"
    assert result.observation.vulnerability is None
    assert result.observation.observed_at is None
    assert result.observation.asset.fqdn == "renamed.example.test"
    assert "missing_observed_at" in result.observation.warnings


def test_mapping_errors_are_reported_per_row_without_losing_supported_rows() -> None:
    result = rows(
        "ID,Address,Seen\nx,not-ip,wrong\ny,192.0.2.3,2026-10-01T00:00:00Z\n",
        mapping={"native_id": "ID", "ip": "Address", "observed_at": "Seen"},
    )
    assert result[0].error is not None
    assert result[0].record_number == 1
    assert result[1].observation is not None


def test_import_time_and_file_position_do_not_change_event_fingerprint() -> None:
    text = "native_id,observed_at\na,2026-10-01T00:00:00Z\n"
    first = rows(text)[0].observation
    again = next(
        parse_rows(
            StringIO(text), options(), file_hash="b" * 64, imported_at=datetime(2026, 10, 2, tzinfo=UTC)
        )
    ).observation
    assert first is not None and again is not None
    assert first.fingerprint == again.fingerprint
    assert first.provenance.file_sha256 != again.provenance.file_sha256


def test_source_instance_and_mapping_are_part_of_fingerprint() -> None:
    text = "native_id\na\n"
    first = rows(text)[0].observation
    other = rows(text, instance="other")[0].observation
    assert first is not None and other is not None
    assert first.fingerprint != other.fingerprint


def test_ndjson_keeps_bad_row_and_later_good_row() -> None:
    result = rows('{"native_id":"a"}\ninvalid\n{"native_id":"b"}\n', format="ndjson")
    assert len(result) == 3
    assert result[1].error is not None
    assert result[2].observation is not None


def test_duplicate_csv_headers_are_rejected() -> None:
    with pytest.raises(ValueError, match="Duplicate"):
        rows("native_id,native_id\na,b\n")


def test_coverage_failure_and_native_closed_status_never_become_resolution() -> None:
    record = rows("native_id,kind,coverage_outcome,native_status\na,coverage,unreachable,offline\n")[0]
    assert record.observation is not None
    assert record.observation.coverage is not None
    assert record.observation.coverage.outcome == "unreachable"
    assert not record.observation.coverage.complete
    record = rows(
        "native_id,vulnerability_id,native_status\na,CVE-2026-12345,closed\n", source="crowdstrike"
    )[0]
    assert record.observation is not None
    assert record.observation.vulnerability is not None
    assert record.observation.vulnerability.native_status == "closed"
    assert record.observation.kind == "vulnerability"


@pytest.mark.parametrize(
    "field,value", [("fqdn", "app.example.test"), ("short_hostname", "app"), ("ip_addresses", ["192.0.2.4"])]
)
def test_weak_identifiers_always_require_review(field: str, value: object) -> None:
    evidence = AssetEvidence.model_validate({field: value})
    index = EvidenceIndex([candidate("a", **{field: value})])
    decision = index.resolve(evidence, observed_at=NOW, now=NOW)
    assert decision.action == "review"
    assert decision.candidate_ids == ("a",)


def test_unique_native_id_matches_only_in_its_source_instance() -> None:
    native = IdentityEvidence(source="pdq_connect", instance="fleet-a", kind="device_id", value="1")
    index = EvidenceIndex([candidate("a", native_ids=[native])])
    assert index.resolve(AssetEvidence(native_ids=(native,)), observed_at=NOW, now=NOW).action == "match"
    other = native.model_copy(update={"instance": "fleet-b"})
    assert index.resolve(AssetEvidence(native_ids=(other,)), observed_at=NOW, now=NOW).action == "create"


def test_duplicate_native_id_and_reimage_conflict_are_reviewed() -> None:
    native = IdentityEvidence(source="crowdstrike", instance="fleet", kind="device_id", value="agent-a")
    incoming = AssetEvidence(native_ids=(native,), hardware_uuid="hardware-new")
    index = EvidenceIndex([candidate("a", native_ids=[native], hardware_uuid="hardware-old")])
    assert index.resolve(incoming, observed_at=NOW, now=NOW).rule == "conflicting_stable_evidence"
    index.add(candidate("b", native_ids=[native]))
    assert index.resolve(incoming, observed_at=NOW, now=NOW).action == "review"


def test_unknown_stale_and_future_observations_do_not_auto_match() -> None:
    evidence = AssetEvidence(hardware_uuid="hardware-a")
    index = EvidenceIndex([candidate("a", hardware_uuid="hardware-a")])
    for observed in (None, datetime(2020, 1, 1, tzinfo=UTC), datetime(2030, 1, 1, tzinfo=UTC)):
        assert index.resolve(evidence, observed_at=observed, now=NOW).action == "review"


def test_network_scopes_prevent_private_subnet_collisions() -> None:
    index = EvidenceIndex([candidate("a", ip_addresses=["192.0.2.4"], network_scope="vrf-a")])
    evidence = AssetEvidence(ip_addresses=("192.0.2.4",), network_scope="vrf-b")
    assert index.resolve(evidence, observed_at=NOW, now=NOW).action == "create"


def test_summary_accounts_for_errors_duplicates_and_bounded_pages() -> None:
    result = rows("native_id,ip\na,192.0.2.1\na,192.0.2.1\nb,bad-ip\nc,192.0.2.3\n")
    summary = summarize(result, EvidenceIndex([]), now=NOW, offset=0, limit=1)
    assert summary.total_rows == 4
    assert summary.valid_rows == 3
    assert summary.error_rows == 1
    assert summary.duplicate_rows == 1
    assert summary.total == 2
    assert len(summary.items) == 1
    assert summary.truncated


def test_netbox_object_id_without_object_type_cannot_auto_match() -> None:
    result = rows("native_id,observed_at\n1,2026-10-01T00:00:00Z\n", source="netbox")
    observation = result[0].observation
    assert observation is not None
    index = EvidenceIndex([candidate("device", native_ids=observation.asset.native_ids)])
    assert index.resolve(observation.asset, observed_at=NOW, now=NOW).action == "review"


def test_rename_with_same_native_id_keeps_identity_but_ip_reuse_requires_review() -> None:
    native = IdentityEvidence(source="crowdstrike", instance="fleet", kind="aid", value="agent-a")
    index = EvidenceIndex([candidate("a", native_ids=[native], fqdn="old.example.test")])
    incoming = AssetEvidence(native_ids=(native,), fqdn="renamed.example.test", ip_addresses=("192.0.2.6",))
    assert index.resolve(incoming, observed_at=NOW, now=NOW).action == "match"
    index.add(candidate("b", ip_addresses=["192.0.2.6"]))
    assert index.resolve(incoming, observed_at=NOW, now=NOW).rule == "cross_asset_conflict"


@pytest.mark.parametrize("time", ["2026-10-01", "2026-10-01T00:00:00", "bad"])
def test_no_timezone_is_a_row_error(time: str) -> None:
    assert rows(f"native_id,observed_at\na,{time}\n")[0].error


def test_nessus_empty_host_is_inventory_with_unknown_coverage() -> None:
    from vulnbatch.reconciliation.nessus import parse_nessus_observations

    data = (
        b'<NessusClientData_v2><Report><ReportHost name="empty.example.test" />'
        b"</Report></NessusClientData_v2>"
    )
    result = list(
        parse_nessus_observations(
            BytesIO(data), options(source="nessus", format="nessus_xml"), file_hash="a" * 64, imported_at=NOW
        )
    )
    assert len(result) == 1
    observation = result[0].observation
    assert observation is not None
    assert observation.kind == "inventory"
    assert observation.coverage is None
    assert "no_report_items_not_proof_of_clean_scan" in observation.warnings


def test_nessus_dtd_is_rejected() -> None:
    from vulnbatch.reconciliation.nessus import parse_nessus_observations

    with pytest.raises(ValueError, match="Unsafe"):
        list(
            parse_nessus_observations(
                BytesIO(b"<!DOCTYPE x><NessusClientData_v2/>"),
                options(source="nessus", format="nessus_xml"),
                file_hash="a" * 64,
                imported_at=NOW,
            )
        )


def test_nessus_retains_unmapped_host_attributes_and_repeated_properties() -> None:
    from vulnbatch.reconciliation.nessus import parse_nessus_observations

    def parse(instance: str, marker: str = "one") -> list[ParsedRow]:
        data = (
            f'<NessusClientData_v2><Report><ReportHost name="host.example.test" custom="{marker}">'
            '<HostProperties><tag name="host-fqdn">host.example.test</tag>'
            f'<tag name="aws-instance-id" custom="original">{instance}</tag>'
            '<tag name="aws-instance-id">second-value</tag></HostProperties>'
            '<ReportItem pluginID="100" pluginName="Synthetic" severity="2" port="0" protocol="tcp"/>'
            "</ReportHost></Report></NessusClientData_v2>"
        ).encode()
        return list(
            parse_nessus_observations(
                BytesIO(data),
                options(source="nessus", format="nessus_xml"),
                file_hash="a" * 64,
                imported_at=NOW,
            )
        )

    original, changed, attribute_changed = (
        parse("i-synthetic-a"),
        parse("i-synthetic-b"),
        parse("i-synthetic-a", "two"),
    )
    for before, after, attr_after in zip(original, changed, attribute_changed, strict=True):
        assert before.observation and after.observation and attr_after.observation
        raw_host = before.observation.raw["nessus_report_host"]
        assert raw_host["attributes"] == {"name": "host.example.test", "custom": "one"}
        properties = raw_host["host_properties"][0]["children"]
        assert properties[1]["attributes"] == {"name": "aws-instance-id", "custom": "original"}
        assert [item["text"] for item in properties[1:]] == ["i-synthetic-a", "second-value"]
        assert before.observation.asset == after.observation.asset
        assert before.observation.fingerprint != after.observation.fingerprint
        assert before.observation.fingerprint != attr_after.observation.fingerprint


def test_late_duplicate_agent_conflict_marks_all_observations_for_review() -> None:
    text = (
        "native_id,hardware_uuid,observed_at\n"
        "agent-a,hw-one,2026-10-01T00:00:00Z\n"
        "agent-a,hw-two,2026-10-01T00:00:00Z\n"
    )
    summary = summarize(rows(text, time_meaning="source_observed"), EvidenceIndex([]), now=NOW)
    assert summary.action_counts == {"review": 2}
    assert all(item.decision.rule == "conflicting_ids_within_bundle" for item in summary.items)


def test_record_updated_time_cannot_establish_freshness_for_auto_match() -> None:
    result = rows("native_id,observed_at\na,2026-10-01T00:00:00Z\n", time_meaning="record_updated")
    observation = result[0].observation
    assert observation is not None
    index = EvidenceIndex([candidate("a", native_ids=observation.asset.native_ids)])
    assert summarize(result, index, now=NOW).items[0].decision.action == "review"


def test_duplicate_agent_with_simultaneous_primary_names_is_not_treated_as_a_rename() -> None:
    text = (
        "native_id,hostname,observed_at\n"
        "agent-a,one.example.test,2026-10-01T00:00:00Z\n"
        "agent-a,two.example.test,2026-10-01T00:00:00Z\n"
    )
    summary = summarize(rows(text, time_meaning="source_observed"), EvidenceIndex([]), now=NOW)
    assert summary.action_counts == {"review": 2}


@pytest.mark.parametrize("field", ["native_id", "hardware_uuid"])
@pytest.mark.parametrize(
    "placeholder", ["unknown", "N/A", "not set", "NULL", "00000000-0000-0000-0000-000000000000"]
)
def test_placeholder_identifiers_do_not_propose_an_automatic_merge(field: str, placeholder: str) -> None:
    text = (
        f"{field},hostname,observed_at\n"
        f"{placeholder},one.example.test,2026-10-01T00:00:00Z\n"
        f"{placeholder},two.example.test,2026-09-30T00:00:00Z\n"
    )
    summary = summarize(rows(text, time_meaning="source_observed"), EvidenceIndex([]), now=NOW)
    assert summary.action_counts.get("match", 0) == 0


def test_json_port_zero_is_preserved() -> None:
    observation = rows('{"native_id":"a","vulnerability_id":"plugin-a","port":0}\n', format="ndjson")[
        0
    ].observation
    assert observation is not None and observation.vulnerability is not None
    assert observation.vulnerability.port == 0


def test_simultaneously_duplicated_hardware_uuid_requires_review() -> None:
    text = (
        "hardware_uuid,hostname,observed_at\n"
        "550e8400-e29b-41d4-a716-446655440000,one.example.test,2026-10-01T00:00:00Z\n"
        "550e8400-e29b-41d4-a716-446655440000,two.example.test,2026-10-01T00:00:00Z\n"
    )
    assert summarize(
        rows(text, time_meaning="source_observed"), EvidenceIndex([]), now=NOW
    ).action_counts == {
        "review": 2,
    }


@pytest.mark.parametrize("address", ["192.0.2.2", "2001:db8::2"])
def test_nessus_reporthost_ip_target_is_ip_evidence(address: str) -> None:
    from vulnbatch.reconciliation.nessus import parse_nessus_observations

    data = (
        f'<NessusClientData_v2><Report><ReportHost name="{address}"/></Report></NessusClientData_v2>'.encode()
    )
    observation = next(
        parse_nessus_observations(
            BytesIO(data), options(source="nessus", format="nessus_xml"), file_hash="a" * 64, imported_at=NOW
        )
    ).observation
    assert observation is not None
    assert observation.asset.ip_addresses == (address,)
    assert observation.asset.fqdn is None


def test_numeric_host_target_is_address_evidence_in_its_network_scope() -> None:
    observation = rows("hostname\n192.0.2.3\n", network_scope="vrf-a")[0].observation
    assert observation is not None
    assert observation.asset.ip_addresses == ("192.0.2.3",)
    assert observation.asset.fqdn is None
    assert observation.asset.short_hostname is None


@pytest.mark.parametrize("time", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"])
def test_out_of_range_utc_conversion_is_a_row_error(time: str) -> None:
    assert rows(f"native_id,observed_at\na,{time}\n")[0].error


def test_all_synthetic_source_fixtures_preserve_source_kind_and_row_accounting() -> None:
    from vulnbatch.reconciliation.nessus import parse_nessus_observations

    directory = Path(__file__).parents[2] / "examples" / "offline-reconciliation"
    fixtures: list[ParsedRow] = []
    for profile in json.loads((directory / "profiles.json").read_text(encoding="utf-8")):
        filename = profile.pop("file")
        config = SourceOptions.model_validate(profile)
        data = (directory / filename).read_bytes()
        if config.format == "nessus_xml":
            fixtures.extend(
                parse_nessus_observations(BytesIO(data), config, file_hash="a" * 64, imported_at=NOW)
            )
        else:
            fixtures.extend(
                parse_rows(StringIO(data.decode("utf-8")), config, file_hash="a" * 64, imported_at=NOW)
            )
    result = summarize(fixtures, EvidenceIndex([]), now=NOW)
    assert (result.total_rows, result.valid_rows, result.error_rows, result.duplicate_rows) == (15, 14, 1, 1)
    assert {item.observation.provenance.source for item in result.items} == {
        "crowdstrike",
        "pdq_connect",
        "netbox",
        "active_directory",
        "inventory",
        "nessus",
    }
    assert {item.observation.kind for item in result.items} == {"inventory", "vulnerability", "coverage"}
    assert sum(item.decision.rule == "conflicting_ids_within_bundle" for item in result.items) == 2
    assert not result.persisted
