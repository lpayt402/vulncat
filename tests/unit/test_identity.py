from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vulnbatch.identity import (
    AssetCandidate,
    IdentifierAssociation,
    IdentityResolver,
    normalize_hostname,
    normalize_ip,
    normalize_mac,
)

NOW = datetime(2026, 7, 16, tzinfo=UTC)


def association(
    identifier_type: str,
    value: str,
    *,
    verified: bool = False,
    override: bool = False,
    shared: bool = False,
    active: bool = True,
    last_seen: datetime = NOW,
) -> IdentifierAssociation:
    return IdentifierAssociation(
        identifier_type=identifier_type,
        normalized_value=value,
        original_value=value,
        first_observed_at=NOW - timedelta(days=30),
        last_observed_at=last_seen,
        active=active,
        manually_verified=verified,
        manual_override=override,
        shared_or_non_identifying=shared,
    )


def test_identifier_normalization_is_deterministic() -> None:
    assert normalize_hostname(" Server-A.Example.Test. ") == "server-a.example.test"
    assert normalize_ip("2001:0db8:0:0:0:0:0:1") == "2001:db8::1"
    assert normalize_ip("not-an-address") is None
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("not-a-mac") is None


def test_ip_only_observation_matches_one_recent_unambiguous_asset() -> None:
    candidate = AssetCandidate(
        asset_id="asset-a",
        identifiers=(
            association("fqdn", "server-a.example.test"),
            association("ipv4", "192.0.2.40"),
        ),
    )
    decision = IdentityResolver().resolve({"ipv4": "192.0.2.40"}, (candidate,), observed_at=NOW)
    assert decision.action == "match"
    assert decision.asset_id == "asset-a"
    assert decision.matching_rule == "unique_ip_history"


def test_ip_with_different_asset_uuid_creates_review() -> None:
    candidate = AssetCandidate(
        asset_id="asset-a",
        identifiers=(
            association("tenable_asset_uuid", "11111111-1111-4111-8111-111111111111"),
            association("ipv4", "192.0.2.40"),
        ),
    )
    decision = IdentityResolver().resolve(
        {
            "tenable_asset_uuid": "22222222-2222-4222-8222-222222222222",
            "ipv4": "192.0.2.40",
        },
        (candidate,),
        observed_at=NOW,
    )
    assert decision.action == "review"
    assert decision.matching_rule == "ip_conflicts_with_stronger_evidence"
    assert decision.conflicting_evidence[0]["identifier_type"] == "tenable_asset_uuid"


def test_identical_unverified_short_hostnames_do_not_merge() -> None:
    candidates = (
        AssetCandidate(
            asset_id="asset-a",
            identifiers=(
                association("fqdn", "app.example.test"),
                association("short_hostname", "app"),
            ),
        ),
        AssetCandidate(
            asset_id="asset-b",
            identifiers=(
                association("fqdn", "app.other.test"),
                association("short_hostname", "app"),
            ),
        ),
    )
    decision = IdentityResolver().resolve({"short_hostname": "APP"}, candidates, observed_at=NOW)
    assert decision.action == "review"
    assert set(decision.candidate_asset_ids) == {"asset-a", "asset-b"}


def test_manual_override_takes_precedence_on_future_imports() -> None:
    candidate = AssetCandidate(
        asset_id="asset-a",
        identifiers=(association("short_hostname", "batch-01", verified=True, override=True),),
    )
    decision = IdentityResolver().resolve({"short_hostname": "BATCH-01"}, (candidate,), observed_at=NOW)
    assert decision.action == "match"
    assert decision.matching_rule == "manual_override"
    assert decision.confidence == 1.0


def test_shared_ip_is_non_identifying() -> None:
    candidate = AssetCandidate(
        asset_id="asset-a",
        identifiers=(association("ipv4", "198.51.100.5", shared=True),),
    )
    decision = IdentityResolver().resolve({"ipv4": "198.51.100.5"}, (candidate,), observed_at=NOW)
    assert decision.action == "create"
    assert decision.asset_id is None


def test_conflicting_strong_identifiers_never_silently_merge() -> None:
    candidates = (
        AssetCandidate(
            asset_id="asset-a",
            identifiers=(association("tenable_asset_uuid", "11111111-1111-4111-8111-111111111111"),),
        ),
        AssetCandidate(
            asset_id="asset-b",
            identifiers=(association("fqdn", "server-b.example.test"),),
        ),
    )
    decision = IdentityResolver().resolve(
        {
            "tenable_asset_uuid": "11111111-1111-4111-8111-111111111111",
            "fqdn": "server-b.example.test",
        },
        candidates,
        observed_at=NOW,
    )
    assert decision.action == "review"
    assert decision.matching_rule == "conflicting_strong_identifiers"


def test_strong_uuid_match_still_reviews_an_ip_owned_by_another_asset() -> None:
    candidates = (
        AssetCandidate(
            asset_id="asset-a",
            identifiers=(association("ipv4", "192.0.2.90"),),
        ),
        AssetCandidate(
            asset_id="asset-b",
            identifiers=(association("tenable_asset_uuid", "22222222-2222-4222-8222-222222222222"),),
        ),
    )
    decision = IdentityResolver().resolve(
        {
            "tenable_asset_uuid": "22222222-2222-4222-8222-222222222222",
            "ipv4": "192.0.2.90",
        },
        candidates,
        observed_at=NOW,
    )
    assert decision.action == "review"
    assert decision.matching_rule == "strong_identifier_conflict"
    assert set(decision.candidate_asset_ids) == {"asset-a", "asset-b"}


def test_weighted_nessus_host_short_name_and_os_can_match() -> None:
    candidate = AssetCandidate(
        asset_id="asset-a",
        operating_system="Example Server OS",
        identifiers=(
            association("nessus_host_id", "nessus-host-a"),
            association("short_hostname", "server-a"),
        ),
    )
    decision = IdentityResolver().resolve(
        {
            "nessus_host_id": "NESSUS-HOST-A",
            "short_hostname": "SERVER-A",
        },
        (candidate,),
        observed_at=NOW,
        operating_system="example server os",
    )
    assert decision.action == "match"
    assert decision.matching_rule == "weighted_evidence"
    assert decision.confidence == pytest.approx(0.90)
