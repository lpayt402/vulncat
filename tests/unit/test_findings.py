from __future__ import annotations

from datetime import UTC, date, datetime

from vulnbatch.findings import (
    FindingState,
    FindingStatus,
    apply_observation,
    assess_maturity,
    assess_sla,
    normalize_finding_key,
    reconcile_absence,
    select_maturity_date,
)


def test_finding_identity_uses_asset_scanner_plugin_port_protocol() -> None:
    base = normalize_finding_key(
        asset_id="asset-a",
        scanner_source="TENABLE_VM",
        plugin_id="10001",
        port=None,
        protocol=None,
    )
    renamed_plugin_same_key = normalize_finding_key(
        asset_id="asset-a",
        scanner_source="tenable_vm",
        plugin_id="10001",
        port=0,
        protocol="general",
    )
    other_port = normalize_finding_key(
        asset_id="asset-a",
        scanner_source="tenable_vm",
        plugin_id="10001",
        port=443,
        protocol="tcp",
    )
    assert base == renamed_plugin_same_key
    assert base != other_port


def test_observations_preserve_earliest_first_found_and_reopen() -> None:
    first = apply_observation(
        None,
        observed_at=datetime(2026, 3, 1, tzinfo=UTC),
        first_found_at=datetime(2026, 2, 1, tzinfo=UTC),
        last_found_at=datetime(2026, 3, 1, tzinfo=UTC),
    ).state
    remediated = FindingState(
        status=FindingStatus.REMEDIATED,
        first_seen_at=first.first_seen_at,
        last_seen_at=first.last_seen_at,
        first_found_at=first.first_found_at,
        last_found_at=first.last_found_at,
        times_observed=first.times_observed,
    )
    result = apply_observation(
        remediated,
        observed_at=datetime(2026, 7, 1, tzinfo=UTC),
        first_found_at=datetime(2026, 4, 1, tzinfo=UTC),
        last_found_at=datetime(2026, 7, 1, tzinfo=UTC),
    )
    assert result.reopened is True
    assert result.state.status == FindingStatus.OPEN
    assert result.state.reopened_count == 1
    assert result.state.first_found_at == datetime(2026, 2, 1, tzinfo=UTC)
    assert result.state.times_observed == 2
    sla = assess_sla(
        first_found=result.state.first_found_at,
        severity="medium",
        as_of=datetime(2026, 7, 1, tzinfo=UTC),
        medium_days=60,
        low_days=90,
    )
    assert sla.sla_due_date == date(2026, 4, 2)


def test_partial_absence_never_changes_status_but_authoritative_absence_is_not_observed() -> None:
    state = FindingState(
        status=FindingStatus.IN_PROGRESS,
        first_seen_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_seen_at=datetime(2026, 6, 1, tzinfo=UTC),
        first_found_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_found_at=datetime(2026, 6, 1, tzinfo=UTC),
        times_observed=4,
    )
    partial = reconcile_absence(
        state,
        complete_comparable_scope=False,
        asset_was_in_scope=True,
        finding_was_observed=False,
    )
    assert partial.changed is False
    assert partial.state.status == FindingStatus.IN_PROGRESS

    authoritative = reconcile_absence(
        state,
        complete_comparable_scope=True,
        asset_was_in_scope=True,
        finding_was_observed=False,
    )
    assert authoritative.changed is True
    assert authoritative.state.status == FindingStatus.NOT_OBSERVED
    assert authoritative.state.status != FindingStatus.REMEDIATED


def test_maturity_uses_required_source_order_and_optional_first_found_fallback() -> None:
    selection = select_maturity_date(
        cve_publication_date=date(2026, 1, 15),
        vendor_advisory_date=date(2026, 1, 10),
        plugin_publication_date=date(2026, 1, 1),
        first_found=date(2025, 12, 1),
        allow_finding_date_fallback=True,
    )
    assert selection.maturity_date == date(2026, 1, 15)
    assert selection.source == "cve_publication_date"
    assessment = assess_maturity(selection, as_of=date(2026, 2, 14), gate_days=30)
    assert assessment.maturity_gate_date == date(2026, 2, 14)
    assert assessment.maturity_status == "mature"

    no_fallback = select_maturity_date(first_found=date(2025, 12, 1))
    assert no_fallback.maturity_date is None
    assert assess_maturity(no_fallback, as_of=date(2026, 7, 1)).maturity_status == "unknown"


def test_emergency_indicator_bypasses_maturity_gate_without_inventing_a_date() -> None:
    selection = select_maturity_date()
    assessment = assess_maturity(
        selection,
        as_of=date(2026, 7, 1),
        emergency_indicator=True,
    )
    assert assessment.maturity_status == "mature"
    assert assessment.emergency_override is True
    assert assessment.maturity_date is None


def test_sla_clock_uses_first_found_and_severity_specific_duration() -> None:
    medium = assess_sla(
        first_found=date(2026, 1, 1),
        severity="medium",
        as_of=date(2026, 3, 5),
        medium_days=60,
        low_days=90,
    )
    assert medium.sla_due_date == date(2026, 3, 2)
    assert medium.sla_status == "overdue"
    assert medium.days_overdue == 3

    low = assess_sla(
        first_found=date(2026, 1, 1),
        severity="low",
        as_of=date(2026, 3, 5),
        medium_days=60,
        low_days=90,
    )
    assert low.sla_due_date == date(2026, 4, 1)
    assert low.sla_status == "within_sla"
    assert low.days_remaining == 27
