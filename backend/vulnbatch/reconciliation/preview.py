from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from vulnbatch.reconciliation.conflicts import ConflictKeys
from vulnbatch.reconciliation.matching import EvidenceIndex
from vulnbatch.reconciliation.models import Candidate, Decision, Observation, ParsedRow, Preview, PreviewItem


@dataclass(frozen=True)
class PlannedMatch:
    observation: Observation
    decision: Decision
    asset_id: str | None
    current_assignment: dict[str, Any] | None = None


def resolve_bundle(
    unique: dict[str, Observation],
    index: EvidenceIndex,
    conflicts: ConflictKeys,
    *,
    now: datetime,
    known: dict[str, dict[str, Any]],
    create_id: Callable[[Observation], str],
) -> list[PlannedMatch]:
    # Preview and persistence use this same ordered plan, including historical conflicts
    # and retained decisions. Rejected repeat evidence must not reactivate conflicts.
    for fingerprint, observation in unique.items():
        if fingerprint not in known:
            conflicts.include(observation)
    conflicts.apply(index)
    result = []
    for fingerprint, observation in unique.items():
        retained = known.get(fingerprint)
        if retained is not None:
            asset_id = retained["asset_id"]
            decision = Decision(
                action="retain",
                rule="existing_observation_retained",
                confidence=retained["confidence"],
                explanation=f"Keep saved {retained['review_status']} decision "
                f"at version {retained['version']}. " + retained["explanation"],
                candidate_ids=(asset_id,) if asset_id else tuple(retained["candidate_ids"]),
            )
        else:
            matching_time = (
                observation.observed_at if observation.provenance.time_meaning == "source_observed" else None
            )
            decision = index.resolve(observation.asset, observed_at=matching_time, now=now)
            asset_id = (
                create_id(observation)
                if decision.action == "create"
                else decision.candidate_ids[0]
                if decision.action == "match"
                else None
            )
            if asset_id:
                index.add(Candidate(asset_id=asset_id, evidence=observation.asset, observed_at=matching_time))
        result.append(PlannedMatch(observation, decision, asset_id, retained))
    return result


def summarize(
    rows: Iterable[ParsedRow],
    index: EvidenceIndex,
    *,
    now: datetime,
    offset: int = 0,
    limit: int = 50,
    max_rows: int = 100_000,
    conflicts: ConflictKeys | None = None,
    known: dict[str, dict[str, Any]] | None = None,
) -> Preview:
    if offset < 0 or not 1 <= limit <= 500:
        raise ValueError("offset must be nonnegative and limit between 1 and 500")
    # Check the entire bounded bundle before proposing assignments: later cloned-agent evidence
    # must invalidate earlier suggestions too. Parsers stream; this preview stages at most max_rows.
    staged: list[ParsedRow] = []
    for row in rows:
        if len(staged) >= max_rows:
            raise ValueError(f"Preview exceeds {max_rows} rows; split the export into smaller files")
        staged.append(row)
    retained = known or {}
    unique = {row.observation.fingerprint: row.observation for row in staged if row.observation}
    planned = resolve_bundle(
        unique,
        index,
        conflicts or ConflictKeys(),
        now=now,
        known=retained,
        create_id=lambda observation: "preview:" + observation.fingerprint,
    )
    seen: set[str] = set()
    items: list[PreviewItem] = []
    errors: list[ParsedRow] = []
    counts: Counter[str] = Counter()
    total_rows = valid = error_count = duplicates = total = 0
    for row in staged:
        total_rows += 1
        if total_rows > max_rows:
            raise ValueError(f"Preview exceeds {max_rows} rows; split the export into smaller files")
        observation = row.observation
        if observation is None:
            error_count += 1
            if len(errors) < 50:
                errors.append(row)
            continue
        valid += 1
        if observation.fingerprint in retained or observation.fingerprint in seen:
            duplicates += 1
        if observation.fingerprint in seen:
            continue
        seen.add(observation.fingerprint)
        plan = planned[total]
        decision = plan.decision
        counts[decision.action] += 1
        if offset <= total < offset + limit:
            items.append(
                PreviewItem(
                    observation=observation,
                    decision=decision,
                    current_assignment=plan.current_assignment,
                )
            )
        total += 1
    return Preview(
        total_rows=total_rows,
        valid_rows=valid,
        error_rows=error_count,
        duplicate_rows=duplicates,
        total=total,
        offset=offset,
        limit=limit,
        truncated=offset + len(items) < total,
        items=tuple(items),
        errors=tuple(errors),
        errors_truncated=error_count > len(errors),
        action_counts=dict(counts),
        candidate_checks=index.candidate_checks,
    )
