from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Literal

MaturitySource = Literal[
    "cve_publication_date",
    "vendor_advisory_date",
    "plugin_publication_date",
    "plugin_modification_date",
    "first_found",
]
MaturityStatus = Literal["unknown", "new_or_maturity_deferred", "mature"]
SlaStatus = Literal["unknown", "not_applicable", "within_sla", "due_today", "overdue"]


@dataclass(frozen=True, slots=True)
class MaturitySelection:
    maturity_date: date | None
    source: MaturitySource | None


@dataclass(frozen=True, slots=True)
class MaturityAssessment:
    maturity_date: date | None
    maturity_date_source: MaturitySource | None
    vulnerability_age_days: int | None
    maturity_gate_date: date | None
    maturity_status: MaturityStatus
    emergency_override: bool


@dataclass(frozen=True, slots=True)
class SlaAssessment:
    first_found_date: date | None
    sla_due_date: date | None
    sla_age_days: int | None
    days_remaining: int | None
    days_overdue: int | None
    sla_status: SlaStatus


def select_maturity_date(
    *,
    cve_publication_date: date | datetime | None = None,
    vendor_advisory_date: date | datetime | None = None,
    plugin_publication_date: date | datetime | None = None,
    plugin_modification_date: date | datetime | None = None,
    first_found: date | datetime | None = None,
    allow_finding_date_fallback: bool = False,
) -> MaturitySelection:
    ordered: tuple[tuple[MaturitySource, date | datetime | None], ...] = (
        ("cve_publication_date", cve_publication_date),
        ("vendor_advisory_date", vendor_advisory_date),
        ("plugin_publication_date", plugin_publication_date),
        ("plugin_modification_date", plugin_modification_date),
    )
    for source, value in ordered:
        if value is not None:
            return MaturitySelection(_as_date(value), source)
    if allow_finding_date_fallback and first_found is not None:
        return MaturitySelection(_as_date(first_found), "first_found")
    return MaturitySelection(None, None)


def assess_maturity(
    selection: MaturitySelection,
    *,
    as_of: date | datetime,
    gate_days: int = 30,
    emergency_indicator: bool = False,
) -> MaturityAssessment:
    if gate_days < 0:
        raise ValueError("gate_days cannot be negative")
    as_of_date = _as_date(as_of)
    if selection.maturity_date is None:
        return MaturityAssessment(
            maturity_date=None,
            maturity_date_source=None,
            vulnerability_age_days=None,
            maturity_gate_date=None,
            maturity_status="mature" if emergency_indicator else "unknown",
            emergency_override=emergency_indicator,
        )
    gate_date = selection.maturity_date + timedelta(days=gate_days)
    age = (as_of_date - selection.maturity_date).days
    status: MaturityStatus = (
        "mature" if emergency_indicator or as_of_date >= gate_date else "new_or_maturity_deferred"
    )
    return MaturityAssessment(
        maturity_date=selection.maturity_date,
        maturity_date_source=selection.source,
        vulnerability_age_days=age,
        maturity_gate_date=gate_date,
        maturity_status=status,
        emergency_override=emergency_indicator,
    )


def assess_sla(
    *,
    first_found: date | datetime | None,
    severity: object,
    as_of: date | datetime,
    medium_days: int = 60,
    low_days: int = 90,
) -> SlaAssessment:
    if medium_days < 1 or low_days < 1:
        raise ValueError("SLA durations must be positive")
    normalized_severity = str(severity).strip().casefold() if severity is not None else ""
    duration = {"medium": medium_days, "low": low_days}.get(normalized_severity)
    if duration is None:
        return SlaAssessment(
            first_found_date=_as_date(first_found) if first_found is not None else None,
            sla_due_date=None,
            sla_age_days=None,
            days_remaining=None,
            days_overdue=None,
            sla_status="not_applicable",
        )
    if first_found is None:
        return SlaAssessment(
            first_found_date=None,
            sla_due_date=None,
            sla_age_days=None,
            days_remaining=None,
            days_overdue=None,
            sla_status="unknown",
        )
    first_found_date = _as_date(first_found)
    as_of_date = _as_date(as_of)
    due_date = first_found_date + timedelta(days=duration)
    age = (as_of_date - first_found_date).days
    delta = (due_date - as_of_date).days
    if delta < 0:
        status: SlaStatus = "overdue"
    elif delta == 0:
        status = "due_today"
    else:
        status = "within_sla"
    return SlaAssessment(
        first_found_date=first_found_date,
        sla_due_date=due_date,
        sla_age_days=age,
        days_remaining=max(delta, 0),
        days_overdue=max(-delta, 0),
        sla_status=status,
    )


def _as_date(value: date | datetime) -> date:
    return value.date() if isinstance(value, datetime) else value
