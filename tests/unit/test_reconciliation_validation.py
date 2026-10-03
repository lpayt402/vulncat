from __future__ import annotations

import json
from datetime import UTC, datetime
from io import StringIO
from typing import Any

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

NOW = datetime(2026, 10, 2, tzinfo=UTC)


def parse(records: list[dict[str, Any]], **changes: Any) -> list[ParsedRow]:
    config = SourceOptions.model_validate(
        {"source": "inventory", "instance": "synthetic-validation", "format": "json", **changes}
    )
    text = (
        "\n".join(json.dumps(record) for record in records)
        if config.format == "ndjson"
        else json.dumps(records)
    )
    return list(parse_rows(StringIO(text), config, file_hash="a" * 64, imported_at=NOW))


@pytest.mark.parametrize("format", ["json", "ndjson"])
def test_unresolved_explicit_mapping_is_a_row_error_and_later_rows_survive(format: str) -> None:
    result = parse(
        [{"id": "a", "finding": {"id": "v1"}}, {"id": "b", "finding": {"typo": "v2"}}],
        format=format,
        mapping={"native_id": "id", "vulnerability_id": "finding.typo"},
    )
    assert result[0].error and "vulnerability_id" in result[0].error and "finding.typo" in result[0].error
    assert result[0].observation is None
    assert result[1].observation is not None and result[1].observation.kind == "vulnerability"


@pytest.mark.parametrize("parent", [None, "scalar", [], {"other": "value"}])
def test_nontraversable_or_absent_nested_mapping_is_not_a_null_leaf(parent: Any) -> None:
    result = parse([{"id": "a", "host": parent}], mapping={"native_id": "id", "observed_at": "host.seen"})
    assert result[0].error and "host.seen" in result[0].error


def test_present_null_optional_leaf_stays_unknown_without_becoming_a_path_error() -> None:
    observation = parse(
        [{"id": "a", "host": {"seen": None}}], mapping={"native_id": "id", "observed_at": "host.seen"}
    )[0].observation
    assert observation is not None and observation.observed_at is None
    assert "missing_observed_at" in observation.warnings


@pytest.mark.parametrize("path", ["", " ", "\t"])
def test_blank_configured_mapping_path_is_rejected(path: str) -> None:
    with pytest.raises(ValueError, match=r"mapping.*nonempty"):
        SourceOptions(source="inventory", instance="synthetic", format="json", mapping={"native_id": path})


@pytest.mark.parametrize("format", ["csv", "ndjson", "nessus_xml"])
@pytest.mark.parametrize("path", ["items", ""])
def test_records_path_is_rejected_for_non_json_formats(format: str, path: str) -> None:
    with pytest.raises(ValueError, match=r"records_path.*JSON"):
        SourceOptions.model_validate(
            {"source": "nessus", "instance": "synthetic", "format": format, "records_path": path}
        )


@pytest.mark.parametrize("path", ["", " "])
def test_json_records_path_must_be_nonempty_when_provided(path: str) -> None:
    with pytest.raises(ValueError, match=r"records_path.*nonempty"):
        SourceOptions(source="inventory", instance="synthetic", format="json", records_path=path)


def test_unknown_mapping_key_is_rejected_during_configuration_validation() -> None:
    with pytest.raises(ValueError, match="Unknown mapping fields: vendor_magic"):
        SourceOptions(source="inventory", instance="synthetic", format="json", mapping={"vendor_magic": "id"})


def test_failed_coverage_without_kind_is_not_downgraded_to_inventory() -> None:
    observation = parse([{"native_id": "a", "coverage_outcome": "failed"}])[0].observation
    assert observation is not None and observation.kind == "coverage"
    assert observation.coverage is not None and observation.coverage.outcome == "failed"


def test_inferred_failed_coverage_cannot_claim_completeness() -> None:
    result = parse([{"native_id": "a", "coverage_outcome": "failed", "complete": True}])[0]
    assert result.observation is None and result.error and "cannot be complete" in result.error


@pytest.mark.parametrize(
    "record",
    [
        {"kind": "inventory", "vulnerability_id": "v1"},
        {"kind": "inventory", "coverage_outcome": "failed"},
        {"kind": "inventory", "complete": False},
        {"kind": "coverage", "coverage_outcome": "failed", "vulnerability_id": "v1"},
        {"kind": "vulnerability", "vulnerability_id": "v1", "coverage_outcome": "failed"},
        {"vulnerability_id": "v1", "coverage_outcome": "failed"},
    ],
)
def test_conflicting_record_kind_fields_are_rejected(record: dict[str, Any]) -> None:
    result = parse([{"native_id": "a", **record}])[0]
    assert result.observation is None and result.error and "conflict" in result.error.casefold()


@pytest.mark.parametrize(
    "record", [{"title": "A vulnerability"}, {"severity": "high"}, {"occurrence_id": "x"}]
)
def test_vulnerability_details_without_a_vulnerability_id_are_rejected(record: dict[str, Any]) -> None:
    result = parse([{"native_id": "a", **record}])[0]
    assert result.observation is None and result.error and "vulnerability_id" in result.error


def test_mapped_null_vulnerability_id_does_not_silently_become_inventory() -> None:
    result = parse(
        [{"id": "a", "finding": None}], mapping={"native_id": "id", "vulnerability_id": "finding"}
    )[0]
    assert result.observation is None and result.error and "vulnerability_id" in result.error


@pytest.mark.parametrize("value", [None, "", " "])
def test_present_kind_must_be_explicitly_valid(value: Any) -> None:
    result = parse([{"native_id": "a", "kind": value}])[0]
    assert result.observation is None and result.error and "kind" in result.error


def test_coverage_requires_an_explicit_outcome_including_unknown() -> None:
    result = parse([{"native_id": "a", "kind": "coverage", "coverage_outcome": None}])[0]
    assert result.observation is None and result.error and "coverage_outcome" in result.error
    good = parse([{"native_id": "b", "kind": "coverage", "coverage_outcome": "unknown"}])[0].observation
    assert good is not None and good.coverage is not None and good.coverage.outcome == "unknown"


@pytest.mark.parametrize(
    "value", [{"id": "CVE-2099-10001"}, [{"id": "CVE-2099-10001"}], [None], [1], [True], [[]], [""]]
)
def test_incompatible_cve_shapes_are_row_errors(value: Any) -> None:
    result = parse([{"native_id": "a", "vulnerability_id": "v1", "cves": value}])[0]
    assert result.observation is None and result.error and "cves" in result.error


@pytest.mark.parametrize("value", [None, "", []])
def test_optional_empty_cve_field_is_allowed(value: Any) -> None:
    observation = parse([{"native_id": "a", "vulnerability_id": "v1", "cves": value}])[0].observation
    assert observation is not None and observation.vulnerability is not None
    assert observation.vulnerability.cves == ()


def test_cve_strings_are_normalized_without_object_coercion() -> None:
    observation = parse(
        [
            {
                "native_id": "a",
                "vulnerability_id": "v1",
                "cves": "cve-2099-10001; CVE-2099-10002,cve-2099-10001",
            }
        ]
    )[0].observation
    assert observation is not None and observation.vulnerability is not None
    assert observation.vulnerability.cves == ("CVE-2099-10001", "CVE-2099-10002")


@pytest.mark.parametrize("kind", ["ipam.ipaddress", "dcim.interface", "unsupported_token"])
def test_unsupported_netbox_asset_namespace_is_a_row_error(kind: str) -> None:
    result = parse([{"native_id": 7, "native_id_kind": kind}], source="netbox")[0]
    assert result.observation is None and result.error and "NetBox" in result.error


@pytest.mark.parametrize("kind", ["ipam.ipaddress", "unsupported_token", "unspecified_object_type"])
def test_matcher_defensively_reviews_unsupported_netbox_identity_even_with_hardware(kind: str) -> None:
    native = IdentityEvidence(source="netbox", instance="synthetic", kind=kind, value="7")
    evidence = AssetEvidence(native_ids=(native,), hardware_uuid="synthetic-hardware")
    index = EvidenceIndex([Candidate(asset_id="a", evidence=evidence, observed_at=NOW)])
    decision = index.resolve(evidence, observed_at=NOW, now=NOW)
    assert decision.action == "review" and decision.rule == "unsupported_netbox_identity"


@pytest.mark.parametrize("kind", ["dcim.device", "virtualization.virtualmachine"])
def test_supported_netbox_asset_namespaces_still_match_with_fresh_evidence(kind: str) -> None:
    observation = parse([{"native_id": 7, "native_id_kind": kind}], source="netbox")[0].observation
    assert observation is not None
    index = EvidenceIndex([Candidate(asset_id="a", evidence=observation.asset, observed_at=NOW)])
    assert index.resolve(observation.asset, observed_at=NOW, now=NOW).action == "match"


def test_new_validation_contract_has_a_new_parser_version() -> None:
    observation = parse([{"native_id": "a"}])[0].observation
    assert observation is not None and observation.provenance.parser_version == "offline-v2"


@pytest.mark.parametrize("field", ["native_id", "hardware_uuid"])
@pytest.mark.parametrize("value", [False, True])
def test_boolean_asset_identifiers_are_rejected(field: str, value: bool) -> None:
    result = parse([{field: value, "hostname": "synthetic.example.test"}])[0]
    assert result.observation is None and result.error and "booleans" in result.error


@pytest.mark.parametrize(
    "field,value", [("cves", {}), ("title", []), ("title", {}), ("port", []), ("complete", {})]
)
@pytest.mark.parametrize("kind", [None, "inventory"])
def test_incompatible_empty_shapes_cannot_hide_in_inventory(field: str, value: Any, kind: str | None) -> None:
    record = {"native_id": "a", field: value}
    if kind:
        record["kind"] = kind
    result = parse([record])[0]
    assert result.observation is None and result.error and field in result.error
