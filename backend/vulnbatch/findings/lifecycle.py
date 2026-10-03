from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum


class FindingStatus(StrEnum):
    OPEN = "open"
    NEW_OR_MATURITY_DEFERRED = "new_or_maturity_deferred"
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    NOT_OBSERVED = "not_observed"
    REMEDIATED = "remediated"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class FindingState:
    status: FindingStatus
    first_seen_at: datetime
    last_seen_at: datetime
    first_found_at: datetime | None
    last_found_at: datetime | None
    times_observed: int
    reopened_count: int = 0

    def __post_init__(self) -> None:
        if self.times_observed < 1:
            raise ValueError("times_observed must be at least 1")


@dataclass(frozen=True, slots=True)
class LifecycleResult:
    state: FindingState
    changed: bool
    previous_status: FindingStatus | None
    reason: str
    reopened: bool = False


def apply_observation(
    current: FindingState | None,
    *,
    observed_at: datetime,
    first_found_at: datetime | None = None,
    last_found_at: datetime | None = None,
    initial_status: FindingStatus = FindingStatus.OPEN,
) -> LifecycleResult:
    observed = _aware(observed_at)
    supplied_first_found = _aware(first_found_at) if first_found_at is not None else None
    supplied_last_found = _aware(last_found_at) if last_found_at is not None else None
    if current is None:
        state = FindingState(
            status=initial_status,
            first_seen_at=observed,
            last_seen_at=observed,
            first_found_at=supplied_first_found,
            last_found_at=supplied_last_found,
            times_observed=1,
        )
        return LifecycleResult(
            state=state,
            changed=True,
            previous_status=None,
            reason="Finding instance created from its first normalized observation.",
        )

    reopened = current.status in {FindingStatus.NOT_OBSERVED, FindingStatus.REMEDIATED}
    new_status = FindingStatus.OPEN if reopened else current.status
    state = FindingState(
        status=new_status,
        first_seen_at=min(_aware(current.first_seen_at), observed),
        last_seen_at=max(_aware(current.last_seen_at), observed),
        first_found_at=_earliest(current.first_found_at, supplied_first_found),
        last_found_at=_latest(current.last_found_at, supplied_last_found),
        times_observed=current.times_observed + 1,
        reopened_count=current.reopened_count + (1 if reopened else 0),
    )
    return LifecycleResult(
        state=state,
        changed=True,
        previous_status=current.status if reopened else None,
        reason=(
            "Finding was observed again after a closed/absent state and was reopened."
            if reopened
            else "A new observation updated the existing finding instance without resetting First Found."
        ),
        reopened=reopened,
    )


def reconcile_absence(
    current: FindingState,
    *,
    complete_comparable_scope: bool,
    asset_was_in_scope: bool,
    finding_was_observed: bool,
) -> LifecycleResult:
    if finding_was_observed:
        return LifecycleResult(
            state=current,
            changed=False,
            previous_status=None,
            reason="The finding was observed in this import; absence reconciliation does not apply.",
        )
    if not complete_comparable_scope or not asset_was_in_scope:
        return LifecycleResult(
            state=current,
            changed=False,
            previous_status=None,
            reason=(
                "The import was not proven complete and comparable for this asset; "
                "absence cannot change lifecycle state."
            ),
        )
    if current.status in {
        FindingStatus.REMEDIATED,
        FindingStatus.RISK_ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.NOT_APPLICABLE,
        FindingStatus.NOT_OBSERVED,
    }:
        return LifecycleResult(
            state=current,
            changed=False,
            previous_status=None,
            reason="The current terminal or absent status was preserved.",
        )
    state = replace(current, status=FindingStatus.NOT_OBSERVED)
    return LifecycleResult(
        state=state,
        changed=True,
        previous_status=current.status,
        reason=(
            "An authoritative comparable scan included the asset but did not observe the finding; "
            "the strongest automatic transition is Not Observed, never Remediated."
        ),
    )


def transition_status(current: FindingState, new_status: FindingStatus) -> LifecycleResult:
    if current.status == new_status:
        return LifecycleResult(
            state=current,
            changed=False,
            previous_status=None,
            reason="The finding already has the requested status.",
        )
    return LifecycleResult(
        state=replace(current, status=new_status),
        changed=True,
        previous_status=current.status,
        reason=f"Finding status changed from {current.status.value} to {new_status.value}.",
    )


def _earliest(current: datetime | None, incoming: datetime | None) -> datetime | None:
    if current is None:
        return incoming
    if incoming is None:
        return _aware(current)
    return min(_aware(current), incoming)


def _latest(current: datetime | None, incoming: datetime | None) -> datetime | None:
    if current is None:
        return incoming
    if incoming is None:
        return _aware(current)
    return max(_aware(current), incoming)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
