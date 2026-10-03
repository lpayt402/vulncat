from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vulnbatch.audit.service import record_audit
from vulnbatch.db.exposure import ExposureNode
from vulnbatch.db.models import Asset
from vulnbatch.db.reconciliation import (
    AssignmentVersion,
    CurrentAssignment,
    ReconciliationDecision,
    SourceObservation,
)
from vulnbatch.reconciliation.adapters import digest
from vulnbatch.reconciliation.storage import ReconciliationConflict, advance_revision, lock_mutations
from vulnbatch.schemas.reconciliation import DecisionRequest


def _snapshot(assignment: CurrentAssignment) -> dict[str, Any]:
    return {
        "asset_id": str(assignment.asset_id) if assignment.asset_id else None,
        "version": assignment.version,
        "review_status": assignment.review_status,
        "rule": assignment.rule,
        "explanation": assignment.explanation,
        "confidence": assignment.confidence,
        "candidate_ids": assignment.candidate_ids,
    }


def _active_asset(db: Session, asset_id: uuid.UUID | None) -> uuid.UUID:
    value = db.scalar(
        select(Asset.id)
        .where(Asset.id == asset_id, Asset.active.is_(True), Asset.merged_into_id.is_(None))
        .with_for_update()
    )
    if value is None:
        raise ReconciliationConflict(
            "Target/restoration asset must exist and be active; retired assets cannot receive evidence"
        )
    return value


def guard_legacy_retirement(db: Session, asset_ids: list[uuid.UUID]) -> int:
    previous = lock_mutations(db)
    bound = db.scalar(
        select(func.count()).select_from(ExposureNode).where(ExposureNode.asset_id.in_(asset_ids))
    ) or 0
    if bound:
        raise ReconciliationConflict(
            "These assets are explicitly bound to service exposure nodes; review and remove or rebind "
            "those relationships before retiring the assets"
        )
    count = (
        db.scalar(
            select(func.count())
            .select_from(CurrentAssignment)
            .where(CurrentAssignment.asset_id.in_(asset_ids))
        )
        or 0
    )
    if count:
        raise ReconciliationConflict(
            "These assets have persistent source evidence; use reconciliation merge/split/correction "
            "instead of retiring them through legacy identity operations"
        )
    return previous


def apply_decision(
    db: Session, payload: DecisionRequest, *, actor_id: uuid.UUID, now: datetime
) -> dict[str, Any]:
    previous = lock_mutations(db)
    request_key = "decision:" + payload.request_key
    payload_hash = digest({"actor": str(actor_id), "request": payload.model_dump(mode="json")})
    replay = db.scalar(
        select(ReconciliationDecision).where(ReconciliationDecision.request_key == request_key)
    )
    if replay:
        if replay.payload_sha256 != payload_hash:
            raise ReconciliationConflict(
                "Decision request key was already used with another payload or actor"
            )
        return {**replay.result, "replayed": True}
    if payload.expected_revision != previous:
        raise ReconciliationConflict("Reconciliation revision changed; refresh evidence before deciding")
    action = payload.action
    undo_of: uuid.UUID | None = None
    inverse: dict[uuid.UUID, dict[str, Any]] = {}
    target: uuid.UUID | None = None
    if action == "undo":
        if (
            payload.observation_ids
            or payload.expected_versions
            or payload.source_asset_id
            or payload.target_asset_id
            or not payload.undo_decision_id
        ):
            raise ValueError("Undo requires only undo_decision_id, reason and revision")
        original = db.get(ReconciliationDecision, payload.undo_decision_id)
        if original is None or original.action in {"import", "undo"}:
            raise ReconciliationConflict("This decision is not reversible")
        if db.scalar(
            select(ReconciliationDecision.id).where(ReconciliationDecision.undo_of_id == original.id)
        ):
            raise ReconciliationConflict("This decision has already been undone")
        undo_of = original.id
        ids = [uuid.UUID(change["observation_id"]) for change in original.changes]
        items = list(
            db.scalars(
                select(CurrentAssignment)
                .execution_options(populate_existing=True)
                .where(CurrentAssignment.observation_id.in_(ids))
                .order_by(CurrentAssignment.observation_id)
            )
        )
        by_id = {item.observation_id: item for item in items}
        for change in original.changes:
            observation_id = uuid.UUID(change["observation_id"])
            item = by_id.get(observation_id)
            if item is None or item.version != change["after"]["version"]:
                raise ReconciliationConflict(
                    "An affected assignment version changed; unsafe undo was not applied"
                )
            before = change["before"]
            if before["asset_id"]:
                _active_asset(db, uuid.UUID(before["asset_id"]))
            inverse[observation_id] = before
    elif action == "merge":
        if (
            payload.observation_ids
            or payload.expected_versions
            or payload.undo_decision_id
            or not payload.source_asset_id
            or not payload.target_asset_id
            or payload.source_asset_id == payload.target_asset_id
        ):
            raise ValueError(
                "Merge requires different source and target assets, with no selected observation IDs"
            )
        _active_asset(db, payload.source_asset_id)
        target = _active_asset(db, payload.target_asset_id)
        items = list(
            db.scalars(
                select(CurrentAssignment)
                .execution_options(populate_existing=True)
                .where(CurrentAssignment.asset_id == payload.source_asset_id)
                .order_by(CurrentAssignment.observation_id)
                .limit(5001)
            )
        )
        if not items or len(items) > 5000:
            raise ValueError(
                "Merge requires 1-5000 source observations; split larger operations into bounded corrections"
            )
    else:
        ids = payload.observation_ids
        if (
            not ids
            or len(set(ids)) != len(ids)
            or set(payload.expected_versions) != {str(value) for value in ids}
            or payload.undo_decision_id
        ):
            raise ValueError("Select distinct observations and provide exactly their expected versions")
        items = list(
            db.scalars(
                select(CurrentAssignment)
                .execution_options(populate_existing=True)
                .where(CurrentAssignment.observation_id.in_(ids))
                .order_by(CurrentAssignment.observation_id)
            )
        )
        if len(items) != len(ids):
            raise ReconciliationConflict("Selected source observation is unavailable")
        if any(item.version != payload.expected_versions[str(item.observation_id)] for item in items):
            raise ReconciliationConflict("An assignment version changed; refresh evidence before deciding")
        if action == "assign":
            if payload.source_asset_id or not payload.target_asset_id:
                raise ValueError("Assign requires a target asset, without source_asset_id")
            target = _active_asset(db, payload.target_asset_id)
        elif action == "split":
            if (
                not payload.source_asset_id
                or payload.target_asset_id
                or any(item.asset_id != payload.source_asset_id for item in items)
            ):
                raise ValueError(
                    "Split selects evidence assigned to one source asset and creates a separate asset"
                )
            _active_asset(db, payload.source_asset_id)
        elif payload.source_asset_id or payload.target_asset_id:
            raise ValueError("This action does not accept source/target asset options")
        if action in {"create", "defer"} and any(item.asset_id is not None for item in items):
            raise ValueError(
                "Create/defer requires unassigned observations; use split or correction for assigned evidence"
            )
        if action in {"create", "split"}:
            observation = db.get(SourceObservation, items[0].observation_id)
            assert observation is not None
            evidence = observation.normalized["asset"]
            asset = Asset(
                canonical_hostname=evidence.get("fqdn") or evidence.get("short_hostname"),
                operating_system=evidence.get("operating_system"),
            )
            db.add(asset)
            db.flush()
            target = asset.id
    decision_id = uuid.uuid4()
    changes: list[dict[str, Any]] = []
    for item in items:
        before = _snapshot(item)
        if action == "undo":
            desired = inverse[item.observation_id]
            item.asset_id = uuid.UUID(desired["asset_id"]) if desired["asset_id"] else None
            item.review_status, item.rule = desired["review_status"], desired["rule"]
            item.explanation, item.confidence, item.candidate_ids = (
                desired["explanation"],
                desired["confidence"],
                desired["candidate_ids"],
            )
        else:
            item.asset_id = target
            item.review_status = "assigned" if target else "rejected" if action == "reject" else "deferred"
            item.rule, item.explanation = "manual_" + action, payload.reason
            item.confidence = 1.0 if target else 0.0
        item.version += 1
        changes.append(
            {"observation_id": str(item.observation_id), "before": before, "after": _snapshot(item)}
        )
    result = {
        "id": str(decision_id),
        "revision": previous + 1,
        "action": action,
        "changed_rows": len(items),
        "replayed": False,
    }
    db.add(
        ReconciliationDecision(
            id=decision_id,
            request_key=request_key,
            payload_sha256=payload_hash,
            action=action,
            actor_user_id=actor_id,
            occurred_at=now,
            reason=payload.reason,
            undo_of_id=undo_of,
            changes=changes,
            result=result,
        )
    )
    db.flush()
    for item in items:
        snapshot = _snapshot(item)
        snapshot["asset_id"] = item.asset_id
        db.add(
            AssignmentVersion(
                observation_id=item.observation_id, decision_id=decision_id, occurred_at=now, **snapshot
            )
        )
    advance_revision(db, previous)
    record_audit(
        db,
        event_type="reconciliation." + action,
        actor_user_id=actor_id,
        entity_type="reconciliation_decision",
        entity_id=decision_id,
        details={
            "reason": payload.reason,
            "changed_rows": len(items),
            "undo_of_id": str(undo_of) if undo_of else None,
        },
    )
    db.flush()
    return result
