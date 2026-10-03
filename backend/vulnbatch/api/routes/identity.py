from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from vulnbatch.api.deps import Principal, get_current_principal, request_client_ip, require_admin_csrf
from vulnbatch.audit.service import record_audit
from vulnbatch.core.security import utcnow
from vulnbatch.db.models import (
    Asset,
    AssetFinding,
    AssetIdentifier,
    AssetIdentifierObservation,
    FindingNote,
    FindingObservation,
    FindingStatusHistory,
    IdentityEvent,
    IdentityReviewItem,
    ImportRecord,
    ImportRun,
)
from vulnbatch.db.session import get_db
from vulnbatch.identity.normalization import normalize_hostname
from vulnbatch.imports.models import NormalizedImportRecord
from vulnbatch.imports.processor import (
    _apply_asset_metadata,
    _create_asset,
    _upsert_definition,
    _upsert_finding,
    _upsert_identifiers,
)
from vulnbatch.reconciliation.decisions import guard_legacy_retirement
from vulnbatch.reconciliation.storage import ReconciliationConflict, advance_revision, lock_mutations
from vulnbatch.schemas.identity import (
    IdentityReason,
    IdentityReviewResolution,
    MergeRequest,
    MoveIdentifierRequest,
    PinNameRequest,
    SplitIdentifierRequest,
)

router = APIRouter(prefix="/api/v1/identity", tags=["identity"])


def _review_dict(item: IdentityReviewItem) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "status": item.status,
        "source_import_id": str(item.source_import_id),
        "import_record_id": str(item.import_record_id) if item.import_record_id else None,
        "incoming_identifiers": item.incoming_identifiers,
        "candidate_asset_ids": item.candidate_asset_ids,
        "conflicting_evidence": item.conflicting_evidence,
        "matching_rule": item.matching_rule,
        "explanation": item.explanation,
        "confidence": item.confidence,
        "first_observed_at": item.first_observed_at,
        "last_observed_at": item.last_observed_at,
        "resolution": item.resolution,
        "resolved_at": item.resolved_at,
    }


@router.get("/review")
def list_identity_review(
    review_status: str | None = None,
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    statement = select(IdentityReviewItem)
    if review_status:
        statement = statement.where(IdentityReviewItem.status == review_status)
    else:
        statement = statement.where(IdentityReviewItem.status.in_(("open", "deferred")))
    items = list(
        db.scalars(
            statement.order_by(
                IdentityReviewItem.created_at.asc(),
                IdentityReviewItem.id.asc(),
            ).limit(500)
        )
    )
    return [_review_dict(item) for item in items]


@router.get("/review/{review_id}")
def get_identity_review(
    review_id: uuid.UUID,
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    item = db.get(IdentityReviewItem, review_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity review item not found.")
    candidates = list(
        db.scalars(
            select(Asset)
            .where(Asset.id.in_([uuid.UUID(value) for value in item.candidate_asset_ids]))
            .options(selectinload(Asset.identifiers))
        )
    )
    return {
        **_review_dict(item),
        "candidate_assets": [
            {
                "id": str(asset.id),
                "canonical_hostname": asset.canonical_hostname,
                "operating_system": asset.operating_system,
                "identity_confidence": asset.identity_confidence,
                "identifiers": [
                    {
                        "id": str(identifier.id),
                        "type": identifier.identifier_type,
                        "value": identifier.normalized_value,
                        "active": identifier.active,
                        "verified": identifier.manually_verified,
                        "shared": identifier.shared_or_non_identifying,
                        "first_observed_at": identifier.first_observed_at,
                        "last_observed_at": identifier.last_observed_at,
                    }
                    for identifier in asset.identifiers
                ],
            }
            for asset in candidates
        ],
    }


def _resolve_record_to_asset(
    db: Session,
    *,
    item: IdentityReviewItem,
    asset: Asset,
    principal: Principal,
) -> None:
    if item.import_record_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Identity review item has no normalized import record.",
        )
    import_record = db.get(ImportRecord, item.import_record_id, with_for_update=True)
    import_run = db.get(ImportRun, item.source_import_id, with_for_update=True)
    if import_record is None or import_run is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Import evidence is unavailable.")
    record = NormalizedImportRecord.model_validate(import_record.normalized_record)
    _apply_asset_metadata(db, asset, record)
    _upsert_identifiers(
        db,
        asset=asset,
        record=record,
        import_run=import_run,
        import_record=import_record,
        matching_rule="manual_identity_review",
        confidence=1.0,
    )
    for incoming in item.incoming_identifiers:
        identifier = db.scalar(
            select(AssetIdentifier).where(
                AssetIdentifier.asset_id == asset.id,
                AssetIdentifier.identifier_type == incoming["identifier_type"],
                AssetIdentifier.normalized_value == incoming["normalized_value"],
            )
        )
        if identifier:
            identifier.manually_verified = True
            identifier.manual_override = True
            identifier.confidence = 1.0
    import_record.asset_id = asset.id
    if record.included_in_inventory and import_record.finding_id is None:
        definition = _upsert_definition(db, record)
        finding, created = _upsert_finding(
            db,
            asset=asset,
            definition=definition,
            record=record,
            import_run=import_run,
            import_record=import_record,
        )
        import_record.finding_id = finding.id
        if created:
            import_run.new_findings += 1
        else:
            import_run.updated_findings += 1
    import_run.ambiguous_assets = max(0, import_run.ambiguous_assets - 1)
    import_run.unique_assets = int(
        db.scalar(
            select(func.count(func.distinct(ImportRecord.asset_id))).where(
                ImportRecord.import_id == import_run.id,
                ImportRecord.asset_id.is_not(None),
            )
        )
        or 0
    )
    db.add(
        IdentityEvent(
            event_type="review_match",
            actor_user_id=principal.user.id,
            primary_asset_id=asset.id,
            payload={
                "identity_review_id": str(item.id),
                "import_record_id": str(import_record.id),
                "incoming_identifiers": item.incoming_identifiers,
            },
            reversible=False,
        )
    )


@router.post("/review/{review_id}/resolve")
def resolve_identity_review(
    review_id: uuid.UUID,
    payload: IdentityReviewResolution,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    mutation_revision = lock_mutations(db)
    item = db.get(IdentityReviewItem, review_id, with_for_update=True)
    if item is None or item.status not in {"open", "deferred"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Identity review item is not open.")
    resolved_asset: Asset | None = None
    if payload.action == "match_existing":
        if payload.asset_id is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="asset_id is required."
            )
        resolved_asset = db.get(Asset, payload.asset_id)
        if resolved_asset is None or not resolved_asset.active:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Canonical asset not found.")
        _resolve_record_to_asset(db, item=item, asset=resolved_asset, principal=principal)
    elif payload.action == "create_asset":
        if item.import_record_id is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="Import evidence is unavailable."
            )
        import_record = db.get(ImportRecord, item.import_record_id)
        if import_record is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="Import evidence is unavailable."
            )
        record = NormalizedImportRecord.model_validate(import_record.normalized_record)
        resolved_asset = _create_asset(record, 1.0)
        db.add(resolved_asset)
        db.flush()
        _resolve_record_to_asset(db, item=item, asset=resolved_asset, principal=principal)
    elif payload.action == "mark_shared":
        candidate_ids = [uuid.UUID(value) for value in item.candidate_asset_ids]
        incoming_ips = {
            (value["identifier_type"], value["normalized_value"])
            for value in item.incoming_identifiers
            if value["identifier_type"] in {"ipv4", "ipv6"}
        }
        for identifier in db.scalars(
            select(AssetIdentifier).where(AssetIdentifier.asset_id.in_(candidate_ids))
        ):
            if (identifier.identifier_type, identifier.normalized_value) in incoming_ips:
                identifier.shared_or_non_identifying = True
                identifier.manual_override = True
        item.status = "resolved"
    elif payload.action == "reject":
        item.status = "rejected"
    else:
        item.status = "deferred"

    if payload.action not in {"defer"}:
        item.status = "resolved" if payload.action not in {"reject"} else "rejected"
        item.resolved_by_id = principal.user.id
        item.resolved_at = utcnow()
    item.resolution = {
        "action": payload.action,
        "asset_id": str(resolved_asset.id) if resolved_asset else None,
        "reason": payload.reason,
    }
    record_audit(
        db,
        event_type="identity.review_resolved" if payload.action != "defer" else "identity.review_deferred",
        actor_user_id=principal.user.id,
        entity_type="identity_review",
        entity_id=item.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details=item.resolution,
    )
    advance_revision(db, mutation_revision)
    db.commit()
    return _review_dict(item)


@router.post("/merge/preview")
def merge_preview(
    payload: MergeRequest,
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    source = db.get(Asset, payload.source_asset_id)
    target = db.get(Asset, payload.target_asset_id)
    if source is None or target is None or source.id == target.id:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid merge assets.")
    source_identifiers = list(
        db.scalars(select(AssetIdentifier).where(AssetIdentifier.asset_id == source.id))
    )
    target_identifiers = list(
        db.scalars(select(AssetIdentifier).where(AssetIdentifier.asset_id == target.id))
    )
    target_by_type: dict[str, set[str]] = {}
    for identifier in target_identifiers:
        target_by_type.setdefault(identifier.identifier_type, set()).add(identifier.normalized_value)
    conflicts = [
        {
            "identifier_type": identifier.identifier_type,
            "source_value": identifier.normalized_value,
            "target_values": sorted(target_by_type[identifier.identifier_type]),
        }
        for identifier in source_identifiers
        if identifier.identifier_type in target_by_type
        and identifier.normalized_value not in target_by_type[identifier.identifier_type]
        and identifier.identifier_type
        in {"tenable_asset_uuid", "agent_uuid", "hardware_uuid", "mac_address", "fqdn"}
    ]
    return {
        "source_asset_id": str(source.id),
        "target_asset_id": str(target.id),
        "source_identifier_count": len(source_identifiers),
        "source_finding_count": int(
            db.scalar(select(func.count(AssetFinding.id)).where(AssetFinding.asset_id == source.id)) or 0
        ),
        "target_finding_count": int(
            db.scalar(select(func.count(AssetFinding.id)).where(AssetFinding.asset_id == target.id)) or 0
        ),
        "strong_identifier_conflicts": conflicts,
        "requires_explicit_confirmation": True,
    }


@router.post("/merge")
def merge_assets(
    payload: MergeRequest,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        mutation_revision = guard_legacy_retirement(db, [payload.source_asset_id, payload.target_asset_id])
    except ReconciliationConflict as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc
    source = db.get(Asset, payload.source_asset_id, with_for_update=True)
    target = db.get(Asset, payload.target_asset_id, with_for_update=True)
    if source is None or target is None or source.id == target.id or not source.active or not target.active:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid merge assets.")
    moved_identifier_ids: list[str] = []
    merged_identifiers: list[dict[str, Any]] = []
    for identifier in list(db.scalars(select(AssetIdentifier).where(AssetIdentifier.asset_id == source.id))):
        duplicate_identifier = db.scalar(
            select(AssetIdentifier).where(
                AssetIdentifier.asset_id == target.id,
                AssetIdentifier.identifier_type == identifier.identifier_type,
                AssetIdentifier.normalized_value == identifier.normalized_value,
            )
        )
        if duplicate_identifier:
            observation_ids = [str(observation.id) for observation in identifier.observations]
            merged_identifiers.append(
                {
                    "id": str(identifier.id),
                    "target_identifier_id": str(duplicate_identifier.id),
                    "identifier_type": identifier.identifier_type,
                    "normalized_value": identifier.normalized_value,
                    "original_value": identifier.original_value,
                    "first_observed_at": identifier.first_observed_at.isoformat(),
                    "last_observed_at": identifier.last_observed_at.isoformat(),
                    "source_import_id": (
                        str(identifier.source_import_id) if identifier.source_import_id else None
                    ),
                    "confidence": identifier.confidence,
                    "manually_verified": identifier.manually_verified,
                    "manual_override": identifier.manual_override,
                    "active": identifier.active,
                    "shared_or_non_identifying": identifier.shared_or_non_identifying,
                    "valid_from": identifier.valid_from.isoformat() if identifier.valid_from else None,
                    "valid_to": identifier.valid_to.isoformat() if identifier.valid_to else None,
                    "observation_ids": observation_ids,
                }
            )
            for observation in identifier.observations:
                observation.identifier_id = duplicate_identifier.id
        else:
            identifier.asset_id = target.id
            moved_identifier_ids.append(str(identifier.id))
    moved_findings: list[dict[str, Any]] = []
    for finding in list(db.scalars(select(AssetFinding).where(AssetFinding.asset_id == source.id))):
        duplicate_finding = db.scalar(
            select(AssetFinding).where(
                AssetFinding.asset_id == target.id,
                AssetFinding.scanner_source == finding.scanner_source,
                AssetFinding.plugin_id == finding.plugin_id,
                AssetFinding.port == finding.port,
                AssetFinding.protocol == finding.protocol,
            )
        )
        if duplicate_finding:
            observations = list(
                db.scalars(select(FindingObservation).where(FindingObservation.finding_id == finding.id))
            )
            histories = list(
                db.scalars(select(FindingStatusHistory).where(FindingStatusHistory.finding_id == finding.id))
            )
            notes = list(db.scalars(select(FindingNote).where(FindingNote.finding_id == finding.id)))
            moved_observation_ids = [str(observation.id) for observation in observations]
            moved_history_ids = [str(history.id) for history in histories]
            moved_note_ids = [str(note.id) for note in notes]
            target_before = {
                "first_seen_at": duplicate_finding.first_seen_at.isoformat(),
                "last_seen_at": duplicate_finding.last_seen_at.isoformat(),
                "times_observed": duplicate_finding.times_observed,
                "reopened_count": duplicate_finding.reopened_count,
            }
            for finding_observation in observations:
                finding_observation.finding_id = duplicate_finding.id
            for history in histories:
                history.finding_id = duplicate_finding.id
            for note in notes:
                note.finding_id = duplicate_finding.id
            duplicate_finding.first_seen_at = min(
                duplicate_finding.first_seen_at,
                finding.first_seen_at,
            )
            duplicate_finding.last_seen_at = max(
                duplicate_finding.last_seen_at,
                finding.last_seen_at,
            )
            duplicate_finding.times_observed += finding.times_observed
            duplicate_finding.reopened_count += finding.reopened_count
            moved_findings.append(
                {
                    "mode": "merged",
                    "source_finding_id": str(finding.id),
                    "target_finding_id": str(duplicate_finding.id),
                    "observation_ids": moved_observation_ids,
                    "history_ids": moved_history_ids,
                    "note_ids": moved_note_ids,
                    "target_before": target_before,
                }
            )
        else:
            finding.asset_id = target.id
            moved_findings.append(
                {
                    "mode": "moved",
                    "source_finding_id": str(finding.id),
                    "target_finding_id": None,
                    "observation_ids": [],
                    "history_ids": [],
                    "note_ids": [],
                }
            )
    source.active = False
    source.merged_into_id = target.id
    event = IdentityEvent(
        event_type="merge",
        actor_user_id=principal.user.id,
        primary_asset_id=target.id,
        secondary_asset_id=source.id,
        payload={
            "reason": payload.reason,
            "moved_identifier_ids": moved_identifier_ids,
            "merged_identifiers": merged_identifiers,
            "moved_findings": moved_findings,
            "source_canonical_hostname": source.canonical_hostname,
        },
        reversible=True,
    )
    db.add(event)
    db.flush()
    record_audit(
        db,
        event_type="identity.assets_merged",
        actor_user_id=principal.user.id,
        entity_type="identity_event",
        entity_id=event.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={
            "source_asset_id": str(source.id),
            "target_asset_id": str(target.id),
            "reason": payload.reason,
        },
    )
    advance_revision(db, mutation_revision)
    db.commit()
    return {"event_id": str(event.id), "source_asset_id": str(source.id), "target_asset_id": str(target.id)}


@router.post("/identifiers/{identifier_id}/move")
def move_identifier(
    identifier_id: uuid.UUID,
    payload: MoveIdentifierRequest,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    mutation_revision = lock_mutations(db)
    identifier = db.get(AssetIdentifier, identifier_id, with_for_update=True)
    target = db.get(Asset, payload.target_asset_id)
    if identifier is None or target is None or not target.active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Identifier or target asset not found."
        )
    old_asset_id = identifier.asset_id
    previous_manually_verified = identifier.manually_verified
    previous_manual_override = identifier.manual_override
    previous_confidence = identifier.confidence
    identifier.asset_id = target.id
    identifier.manually_verified = True
    identifier.manual_override = True
    event = IdentityEvent(
        event_type="move_identifier",
        actor_user_id=principal.user.id,
        primary_asset_id=target.id,
        secondary_asset_id=old_asset_id,
        payload={
            "identifier_id": str(identifier.id),
            "from_asset_id": str(old_asset_id),
            "previous_manually_verified": previous_manually_verified,
            "previous_manual_override": previous_manual_override,
            "previous_confidence": previous_confidence,
            "reason": payload.reason,
        },
        reversible=True,
    )
    db.add(event)
    db.flush()
    record_audit(
        db,
        event_type="identity.identifier_moved",
        actor_user_id=principal.user.id,
        entity_type="identity_event",
        entity_id=event.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details=event.payload,
    )
    advance_revision(db, mutation_revision)
    db.commit()
    return {"event_id": str(event.id), "identifier_id": str(identifier.id), "asset_id": str(target.id)}


@router.post("/identifiers/{identifier_id}/split")
def split_identifier(
    identifier_id: uuid.UUID,
    payload: SplitIdentifierRequest,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    mutation_revision = lock_mutations(db)
    identifier = db.get(AssetIdentifier, identifier_id, with_for_update=True)
    if identifier is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identifier not found.")
    old_asset_id = identifier.asset_id
    previous_manually_verified = identifier.manually_verified
    previous_manual_override = identifier.manual_override
    previous_confidence = identifier.confidence
    canonical = normalize_hostname(payload.canonical_hostname) if payload.canonical_hostname else None
    new_asset = Asset(canonical_hostname=canonical or identifier.normalized_value, identity_confidence=1.0)
    db.add(new_asset)
    db.flush()
    identifier.asset_id = new_asset.id
    identifier.manually_verified = True
    identifier.manual_override = True
    event = IdentityEvent(
        event_type="split_identifier",
        actor_user_id=principal.user.id,
        primary_asset_id=new_asset.id,
        secondary_asset_id=old_asset_id,
        payload={
            "identifier_id": str(identifier.id),
            "from_asset_id": str(old_asset_id),
            "created_asset_id": str(new_asset.id),
            "previous_manually_verified": previous_manually_verified,
            "previous_manual_override": previous_manual_override,
            "previous_confidence": previous_confidence,
            "reason": payload.reason,
        },
        reversible=True,
    )
    db.add(event)
    db.flush()
    record_audit(
        db,
        event_type="identity.identifier_split",
        actor_user_id=principal.user.id,
        entity_type="identity_event",
        entity_id=event.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details=event.payload,
    )
    advance_revision(db, mutation_revision)
    db.commit()
    return {"event_id": str(event.id), "new_asset_id": str(new_asset.id)}


@router.post("/assets/{asset_id}/pin-name")
def pin_asset_name(
    asset_id: uuid.UUID,
    payload: PinNameRequest,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    mutation_revision = lock_mutations(db)
    asset = db.get(Asset, asset_id, with_for_update=True)
    normalized = normalize_hostname(payload.canonical_hostname)
    if asset is None or normalized is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid asset or hostname."
        )
    previous = asset.canonical_hostname
    previous_pinned = asset.canonical_name_pinned
    asset.canonical_hostname = normalized
    asset.canonical_name_pinned = True
    event = IdentityEvent(
        event_type="pin_name",
        actor_user_id=principal.user.id,
        primary_asset_id=asset.id,
        payload={
            "previous": previous,
            "previous_pinned": previous_pinned,
            "canonical_hostname": normalized,
            "reason": payload.reason,
        },
        reversible=True,
    )
    db.add(event)
    db.flush()
    record_audit(
        db,
        event_type="identity.name_pinned",
        actor_user_id=principal.user.id,
        entity_type="identity_event",
        entity_id=event.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details=event.payload,
    )
    advance_revision(db, mutation_revision)
    db.commit()
    return {"event_id": str(event.id), "canonical_hostname": normalized}


@router.post("/identifiers/{identifier_id}/verify")
def verify_identifier(
    identifier_id: uuid.UUID,
    payload: IdentityReason,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    mutation_revision = lock_mutations(db)
    identifier = db.get(AssetIdentifier, identifier_id, with_for_update=True)
    if identifier is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identifier not found.")
    previous = {
        "manually_verified": identifier.manually_verified,
        "manual_override": identifier.manual_override,
        "confidence": identifier.confidence,
    }
    identifier.manually_verified = True
    identifier.manual_override = True
    identifier.confidence = 1.0
    event = IdentityEvent(
        event_type="verify_identifier",
        actor_user_id=principal.user.id,
        primary_asset_id=identifier.asset_id,
        payload={"identifier_id": str(identifier.id), "previous": previous, "reason": payload.reason},
        reversible=True,
    )
    db.add(event)
    db.flush()
    record_audit(
        db,
        event_type="identity.identifier_verified",
        actor_user_id=principal.user.id,
        entity_type="identity_event",
        entity_id=event.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details=event.payload,
    )
    advance_revision(db, mutation_revision)
    db.commit()
    return {"event_id": str(event.id), "identifier_id": str(identifier.id)}


@router.post("/identifiers/{identifier_id}/mark-shared")
def mark_identifier_shared(
    identifier_id: uuid.UUID,
    payload: IdentityReason,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    mutation_revision = lock_mutations(db)
    identifier = db.get(AssetIdentifier, identifier_id, with_for_update=True)
    if identifier is None or identifier.identifier_type not in {"ipv4", "ipv6"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="IP identifier not found."
        )
    previous = {
        "shared_or_non_identifying": identifier.shared_or_non_identifying,
        "manual_override": identifier.manual_override,
    }
    identifier.shared_or_non_identifying = True
    identifier.manual_override = True
    event = IdentityEvent(
        event_type="mark_shared",
        actor_user_id=principal.user.id,
        primary_asset_id=identifier.asset_id,
        payload={"identifier_id": str(identifier.id), "previous": previous, "reason": payload.reason},
        reversible=True,
    )
    db.add(event)
    db.flush()
    record_audit(
        db,
        event_type="identity.identifier_marked_shared",
        actor_user_id=principal.user.id,
        entity_type="identity_event",
        entity_id=event.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details=event.payload,
    )
    advance_revision(db, mutation_revision)
    db.commit()
    return {"event_id": str(event.id), "identifier_id": str(identifier.id)}


def _uuid_list(values: list[str]) -> list[uuid.UUID]:
    return [uuid.UUID(value) for value in values]


def _undo_merge(db: Session, event: IdentityEvent) -> None:
    source = db.get(Asset, event.secondary_asset_id, with_for_update=True)
    target = db.get(Asset, event.primary_asset_id, with_for_update=True)
    if source is None or target is None or source.active or source.merged_into_id != target.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The merged assets are no longer in the state required for a safe undo.",
        )
    for identifier_id in _uuid_list(event.payload.get("moved_identifier_ids", [])):
        identifier = db.get(AssetIdentifier, identifier_id, with_for_update=True)
        if identifier is None or identifier.asset_id != target.id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A moved identifier changed after the merge; undo was not applied.",
            )
        identifier.asset_id = source.id
    for merged in event.payload.get("merged_identifiers", []):
        source_identifier = db.get(
            AssetIdentifier,
            uuid.UUID(merged["id"]),
            with_for_update=True,
        )
        if source_identifier is None or source_identifier.asset_id != source.id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A source identifier changed after the merge; undo was not applied.",
            )
        for observation_id in _uuid_list(merged.get("observation_ids", [])):
            observation = db.get(
                AssetIdentifierObservation,
                observation_id,
                with_for_update=True,
            )
            if observation is not None:
                observation.identifier_id = source_identifier.id
    for moved in event.payload.get("moved_findings", []):
        source_finding = db.get(
            AssetFinding,
            uuid.UUID(moved["source_finding_id"]),
            with_for_update=True,
        )
        if source_finding is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A source finding is unavailable; undo was not applied.",
            )
        if moved.get("mode") == "moved":
            if source_finding.asset_id != target.id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A moved finding changed after the merge; undo was not applied.",
                )
            source_finding.asset_id = source.id
            continue
        target_finding_id = moved.get("target_finding_id")
        target_finding = (
            db.get(AssetFinding, uuid.UUID(target_finding_id), with_for_update=True)
            if target_finding_id
            else None
        )
        if target_finding is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A consolidated target finding is unavailable; undo was not applied.",
            )
        for observation_id in _uuid_list(moved.get("observation_ids", [])):
            finding_observation = db.get(
                FindingObservation,
                observation_id,
                with_for_update=True,
            )
            if finding_observation is not None:
                finding_observation.finding_id = source_finding.id
        for history_id in _uuid_list(moved.get("history_ids", [])):
            history = db.get(FindingStatusHistory, history_id, with_for_update=True)
            if history is not None:
                history.finding_id = source_finding.id
        for note_id in _uuid_list(moved.get("note_ids", [])):
            note = db.get(FindingNote, note_id, with_for_update=True)
            if note is not None:
                note.finding_id = source_finding.id
        target_before = moved["target_before"]
        target_finding.first_seen_at = datetime.fromisoformat(target_before["first_seen_at"])
        target_finding.last_seen_at = datetime.fromisoformat(target_before["last_seen_at"])
        target_finding.times_observed = int(target_before["times_observed"])
        target_finding.reopened_count = int(target_before["reopened_count"])
    source.active = True
    source.merged_into_id = None


def _undo_identity_event(db: Session, event: IdentityEvent) -> None:
    payload = event.payload
    if event.event_type == "merge":
        _undo_merge(db, event)
        return
    if event.event_type in {"move_identifier", "split_identifier"}:
        identifier = db.get(
            AssetIdentifier,
            uuid.UUID(payload["identifier_id"]),
            with_for_update=True,
        )
        if identifier is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The identifier is unavailable; undo was not applied.",
            )
        identifier.asset_id = uuid.UUID(payload["from_asset_id"])
        identifier.manually_verified = bool(payload["previous_manually_verified"])
        identifier.manual_override = bool(payload["previous_manual_override"])
        identifier.confidence = float(payload["previous_confidence"])
        if event.event_type == "split_identifier":
            created = db.get(
                Asset,
                uuid.UUID(payload["created_asset_id"]),
                with_for_update=True,
            )
            if created is None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The split asset is unavailable; undo was not applied.",
                )
            remaining_identifiers = int(
                db.scalar(
                    select(func.count(AssetIdentifier.id)).where(
                        AssetIdentifier.asset_id == created.id,
                        AssetIdentifier.id != identifier.id,
                    )
                )
                or 0
            )
            remaining_findings = int(
                db.scalar(select(func.count(AssetFinding.id)).where(AssetFinding.asset_id == created.id)) or 0
            )
            if remaining_identifiers or remaining_findings:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The split asset gained other evidence; undo was not applied.",
                )
            created.active = False
            created.merged_into_id = uuid.UUID(payload["from_asset_id"])
        return
    if event.event_type == "pin_name":
        asset = db.get(Asset, event.primary_asset_id, with_for_update=True)
        if asset is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Asset is unavailable.")
        asset.canonical_hostname = payload.get("previous")
        asset.canonical_name_pinned = bool(payload.get("previous_pinned", False))
        return
    if event.event_type == "verify_identifier":
        identifier = db.get(
            AssetIdentifier,
            uuid.UUID(payload["identifier_id"]),
            with_for_update=True,
        )
        if identifier is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Identifier is unavailable.")
        previous = payload["previous"]
        identifier.manually_verified = bool(previous["manually_verified"])
        identifier.manual_override = bool(previous["manual_override"])
        identifier.confidence = float(previous["confidence"])
        return
    if event.event_type == "mark_shared":
        identifier = db.get(
            AssetIdentifier,
            uuid.UUID(payload["identifier_id"]),
            with_for_update=True,
        )
        if identifier is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Identifier is unavailable.")
        previous = payload["previous"]
        identifier.shared_or_non_identifying = bool(previous["shared_or_non_identifying"])
        identifier.manual_override = bool(previous["manual_override"])
        return
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=f"Identity event type {event.event_type} does not support undo.",
    )


@router.post("/events/{event_id}/undo")
def undo_identity_event(
    event_id: uuid.UUID,
    payload: IdentityReason,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    mutation_revision = lock_mutations(db)
    event = db.get(IdentityEvent, event_id, with_for_update=True)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity event not found.")
    if not event.reversible or event.undone_by_event_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Identity event is not eligible for undo.",
        )
    if event.event_type in {"merge", "split_identifier"}:
        affected = [event.primary_asset_id]
        if event.secondary_asset_id:
            affected.append(event.secondary_asset_id)
        if event.payload.get("created_asset_id"):
            affected.append(uuid.UUID(event.payload["created_asset_id"]))
        try:
            guard_legacy_retirement(db, affected)
        except ReconciliationConflict as exc:
            db.rollback()
            raise HTTPException(409, str(exc)) from exc
    _undo_identity_event(db, event)
    undo_event = IdentityEvent(
        event_type="undo",
        actor_user_id=principal.user.id,
        primary_asset_id=event.primary_asset_id,
        secondary_asset_id=event.secondary_asset_id,
        payload={"original_event_id": str(event.id), "reason": payload.reason},
        reversible=False,
    )
    db.add(undo_event)
    db.flush()
    event.undone_by_event_id = undo_event.id
    record_audit(
        db,
        event_type="identity.event_undone",
        actor_user_id=principal.user.id,
        entity_type="identity_event",
        entity_id=event.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={"undo_event_id": str(undo_event.id), "reason": payload.reason},
    )
    advance_revision(db, mutation_revision)
    db.commit()
    return {"event_id": str(event.id), "undo_event_id": str(undo_event.id)}


@router.get("/events")
def identity_events(
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    events = list(db.scalars(select(IdentityEvent).order_by(IdentityEvent.occurred_at.desc()).limit(500)))
    return [
        {
            "id": str(event.id),
            "occurred_at": event.occurred_at,
            "event_type": event.event_type,
            "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
            "primary_asset_id": str(event.primary_asset_id),
            "secondary_asset_id": str(event.secondary_asset_id) if event.secondary_asset_id else None,
            "payload": event.payload,
            "reversible": event.reversible,
            "undone_by_event_id": str(event.undone_by_event_id) if event.undone_by_event_id else None,
        }
        for event in events
    ]
