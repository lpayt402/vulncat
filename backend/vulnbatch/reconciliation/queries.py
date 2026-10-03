from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session, aliased

from vulnbatch.db.models import Asset
from vulnbatch.db.reconciliation import (
    AssignmentVersion,
    CurrentAssignment,
    ObservationLocator,
    ReconciliationDecision,
    SourceInstance,
    SourceObservation,
)
from vulnbatch.reconciliation.storage import revision


def _display_name(asset_id: uuid.UUID, name: str | None) -> str:
    return name or f"Unnamed asset ({str(asset_id)[:8]})"


def _item(
    observation: SourceObservation, assignment: CurrentAssignment, asset_name: str | None = None
) -> dict[str, Any]:
    return {
        "id": str(observation.id),
        "asset_id": str(assignment.asset_id) if assignment.asset_id else None,
        "asset_name": _display_name(assignment.asset_id, asset_name) if assignment.asset_id else None,
        "version": assignment.version,
        "review_status": assignment.review_status,
        "rule": assignment.rule,
        "explanation": assignment.explanation,
        "confidence": assignment.confidence,
        "candidate_ids": assignment.candidate_ids,
        "observation": observation.normalized,
    }


def observations(
    db: Session,
    *,
    review_status: str | None = None,
    asset_id: uuid.UUID | None = None,
    source: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    if offset < 0 or not 1 <= limit <= 500:
        raise ValueError("Invalid page; limit must be 1-500")
    captured_revision = revision(db)
    statement = (
        select(SourceObservation, CurrentAssignment, Asset.canonical_hostname)
        .join(CurrentAssignment, CurrentAssignment.observation_id == SourceObservation.id)
        .join(SourceInstance, SourceInstance.id == SourceObservation.source_instance_id)
        .outerjoin(Asset, Asset.id == CurrentAssignment.asset_id)
        .execution_options(populate_existing=True)
    )
    if review_status:
        statement = statement.where(CurrentAssignment.review_status == review_status)
    if asset_id:
        statement = statement.where(CurrentAssignment.asset_id == asset_id)
    if source:
        statement = statement.where(SourceInstance.source == source)
    total = db.scalar(select(func.count()).select_from(statement.subquery())) or 0
    items = [
        _item(observation, assignment, asset_name)
        for observation, assignment, asset_name in db.execute(
            statement.order_by(SourceObservation.imported_at, SourceObservation.id)
            .offset(offset)
            .limit(limit)
        )
    ]
    return {"revision": captured_revision, "total": total, "offset": offset, "limit": limit, "items": items}


def observation_detail(db: Session, observation_id: uuid.UUID) -> dict[str, Any]:
    observation, assignment = (
        db.get(SourceObservation, observation_id),
        db.get(CurrentAssignment, observation_id, populate_existing=True),
    )
    if observation is None or assignment is None:
        raise LookupError("Source observation not found")
    locators = select(ObservationLocator).where(ObservationLocator.observation_id == observation_id)
    history = select(AssignmentVersion).where(AssignmentVersion.observation_id == observation_id)
    recent = list(db.scalars(history.order_by(AssignmentVersion.version.desc()).limit(200)))
    name = (
        db.scalar(select(Asset.canonical_hostname).where(Asset.id == assignment.asset_id))
        if assignment.asset_id
        else None
    )
    return {
        **_item(observation, assignment, name),
        "locator_total": db.scalar(select(func.count()).select_from(locators.subquery())) or 0,
        "locators": [
            {
                "batch_id": str(item.batch_id),
                "filename": item.filename,
                "file_sha256": item.file_sha256,
                "mapping_sha256": item.mapping_sha256,
                "record_number": item.record_number,
                "imported_at": item.imported_at,
            }
            for item in db.scalars(
                locators.order_by(ObservationLocator.imported_at, ObservationLocator.id).limit(200)
            )
        ],
        "history_total": db.scalar(select(func.count()).select_from(history.subquery())) or 0,
        "history": [
            {
                "version": item.version,
                "asset_id": str(item.asset_id) if item.asset_id else None,
                "review_status": item.review_status,
                "rule": item.rule,
                "explanation": item.explanation,
                "decision_id": str(item.decision_id),
                "occurred_at": item.occurred_at,
            }
            for item in reversed(recent)
        ],
    }


def assets(db: Session, *, q: str = "", offset: int = 0, limit: int = 50) -> dict[str, Any]:
    statement = select(Asset.id, Asset.canonical_hostname).where(
        Asset.active.is_(True), Asset.merged_into_id.is_(None)
    )
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        identifier = func.replace(cast(Asset.id, String), "-", "")
        fallback = "Unnamed asset (" + func.substr(identifier, 1, 8) + ")"
        id_query = escaped.replace("-", "")
        statement = statement.where(
            or_(
                func.coalesce(func.nullif(Asset.canonical_hostname, ""), fallback).ilike(
                    f"%{escaped}%", escape="\\"
                ),
                identifier.ilike(f"%{id_query}%", escape="\\"),
            )
        )
    return {
        "total": db.scalar(select(func.count()).select_from(statement.subquery())) or 0,
        "items": [
            {"id": str(asset_id), "canonical_hostname": name, "display_name": _display_name(asset_id, name)}
            for asset_id, name in db.execute(
                statement.order_by(Asset.canonical_hostname, Asset.id).offset(offset).limit(limit)
            )
        ],
    }


def decisions(db: Session, *, offset: int = 0, limit: int = 50) -> dict[str, Any]:
    captured_revision = revision(db)
    undo = aliased(ReconciliationDecision)
    statement = select(ReconciliationDecision, undo.id).outerjoin(
        undo, undo.undo_of_id == ReconciliationDecision.id
    )
    return {
        "revision": captured_revision,
        "total": db.scalar(select(func.count()).select_from(ReconciliationDecision)) or 0,
        "items": [
            {
                "id": str(item.id),
                "action": item.action,
                "reason": item.reason,
                "actor_user_id": str(item.actor_user_id),
                "occurred_at": item.occurred_at,
                "undo_of_id": str(item.undo_of_id) if item.undo_of_id else None,
                "undone": undo_id is not None,
                "reversible": item.action not in {"import", "undo"} and undo_id is None,
            }
            for item, undo_id in db.execute(
                statement.order_by(ReconciliationDecision.occurred_at.desc(), ReconciliationDecision.id)
                .offset(offset)
                .limit(limit)
            )
        ],
    }


def decision_detail(db: Session, decision_id: uuid.UUID) -> dict[str, Any]:
    item = db.get(ReconciliationDecision, decision_id)
    if item is None:
        raise LookupError("Reconciliation decision not found")
    return {
        "id": str(item.id),
        "action": item.action,
        "reason": item.reason,
        "actor_user_id": str(item.actor_user_id),
        "occurred_at": item.occurred_at,
        "changes": item.changes,
        "result": item.result,
        "undo_of_id": str(item.undo_of_id) if item.undo_of_id else None,
    }
