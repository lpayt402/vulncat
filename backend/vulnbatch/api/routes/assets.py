from __future__ import annotations

import csv
import io
import uuid
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from vulnbatch.api.deps import (
    Principal,
    get_current_principal,
    request_client_ip,
    require_admin_csrf,
)
from vulnbatch.audit.service import record_audit
from vulnbatch.core.config import Settings, get_settings
from vulnbatch.db.models import (
    Asset,
    AssetFinding,
    IdentityEvent,
    ImportRecord,
    ImportRun,
    SourceFile,
    Tag,
)
from vulnbatch.db.session import get_db
from vulnbatch.exports.generator import formula_safe
from vulnbatch.queries.service import (
    count_findings_for_query,
    count_unresolved_for_query,
    human_query_summary,
    list_hosts,
)
from vulnbatch.schemas.assets import AssetUpdate
from vulnbatch.schemas.query import (
    HostListRequest,
    HostListResponse,
    HostQueryPreviewRequest,
    HostQueryPreviewResponse,
)
from vulnbatch.settings.service import effective_setting

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])

ASSET_METADATA_FIELDS = (
    "system_owner",
    "administrative_team",
    "technical_owner",
    "environment",
    "data_center",
    "business_service",
    "server_role",
    "maintenance_group",
    "patch_group",
    "notes",
)


@router.post("/query", response_model=HostListResponse)
def query_assets(
    payload: HostListRequest,
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> HostListResponse:
    try:
        normalized, total, items = list_hosts(
            db,
            payload.query,
            page=payload.page,
            page_size=payload.page_size,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return HostListResponse(
        normalized_query=normalized.model_dump(mode="json", exclude_none=True),
        page=payload.page,
        page_size=payload.page_size,
        total=total,
        items=items,
    )


@router.post("/query/preview", response_model=HostQueryPreviewResponse)
def preview_assets(
    payload: HostQueryPreviewRequest,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> HostQueryPreviewResponse:
    try:
        normalized, total, sample = list_hosts(db, payload.query, page=1, page_size=5)
        finding_count = count_findings_for_query(db, normalized, payload.finding_scope)
        unresolved_count = count_unresolved_for_query(db, normalized)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    warnings: list[str] = []
    if total == 0:
        warnings.append("No canonical assets match this query. An export cannot be submitted.")
    if unresolved_count:
        warnings.append(f"{unresolved_count} matching hosts have unresolved identity-review items.")
    large_export_threshold = int(
        effective_setting(
            db,
            "large_export_finding_threshold",
            settings.large_export_finding_threshold,
        )
    )
    if finding_count >= large_export_threshold:
        warnings.append(
            f"This scope contains approximately {finding_count} findings and requires explicit confirmation."
        )
    record_audit(
        db,
        event_type="export.previewed",
        actor_user_id=principal.user.id,
        entity_type="host_query",
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={
            "normalized_query": normalized.model_dump(mode="json", exclude_none=True),
            "query_summary": human_query_summary(normalized),
            "finding_scope": payload.finding_scope.model_dump(mode="json", exclude_none=True),
            "matched_host_count": total,
            "estimated_finding_count": finding_count,
        },
    )
    db.commit()
    return HostQueryPreviewResponse(
        normalized_query=normalized.model_dump(mode="json", exclude_none=True),
        matching_host_count=total,
        sample_hosts=sample,
        estimated_matching_finding_count=finding_count,
        warnings=warnings,
    )


def _asset_detail_payload(db: Session, asset: Asset) -> dict[str, Any]:
    findings = list(
        db.scalars(
            select(AssetFinding)
            .where(AssetFinding.asset_id == asset.id)
            .order_by(AssetFinding.severity.desc(), AssetFinding.first_found_at.asc())
        )
    )
    related_import_ids = select(ImportRecord.import_id).where(ImportRecord.asset_id == asset.id).distinct()
    import_rows = db.execute(
        select(ImportRun, SourceFile)
        .join(SourceFile, SourceFile.id == ImportRun.source_file_id)
        .where(ImportRun.id.in_(related_import_ids))
        .order_by(ImportRun.requested_at.desc())
        .limit(100)
    ).all()
    identity_events = list(
        db.scalars(
            select(IdentityEvent)
            .where(
                or_(
                    IdentityEvent.primary_asset_id == asset.id,
                    IdentityEvent.secondary_asset_id == asset.id,
                )
            )
            .order_by(IdentityEvent.occurred_at.desc())
            .limit(100)
        )
    )
    current_ips = sorted(
        identifier.normalized_value
        for identifier in asset.identifiers
        if identifier.active
        and identifier.identifier_type in {"ipv4", "ipv6"}
        and not identifier.shared_or_non_identifying
    )
    historical_ips = sorted(
        identifier.normalized_value
        for identifier in asset.identifiers
        if not identifier.active and identifier.identifier_type in {"ipv4", "ipv6"}
    )
    known_aliases = sorted(
        identifier.normalized_value
        for identifier in asset.identifiers
        if identifier.identifier_type in {"fqdn", "short_hostname", "user_alias", "netbios"}
        and identifier.normalized_value != asset.canonical_hostname
    )
    unresolved_identity = any(
        event.event_type in {"merge", "split_identifier", "move_identifier"}
        and event.undone_by_event_id is None
        for event in identity_events
    )
    return {
        "id": str(asset.id),
        "canonical_hostname": asset.canonical_hostname,
        "canonical_name_pinned": asset.canonical_name_pinned,
        "operating_system": asset.operating_system,
        "system_owner": asset.system_owner,
        "administrative_team": asset.administrative_team,
        "technical_owner": asset.technical_owner,
        "environment": asset.environment,
        "data_center": asset.data_center,
        "business_service": asset.business_service,
        "server_role": asset.server_role,
        "maintenance_group": asset.maintenance_group,
        "patch_group": asset.patch_group,
        "notes": asset.notes,
        "identity_confidence": asset.identity_confidence,
        "identity_review_state": "review_history_present" if unresolved_identity else "clear",
        "last_scan_observed_at": asset.last_scan_observed_at,
        "current_ip_addresses": current_ips,
        "historical_ip_addresses": historical_ips,
        "known_aliases": known_aliases,
        "tags": sorted(tag.name for tag in asset.tags),
        "identifiers": [
            {
                "id": str(identifier.id),
                "identifier_type": identifier.identifier_type,
                "type": identifier.identifier_type,
                "normalized_value": identifier.normalized_value,
                "original_value": identifier.original_value,
                "first_observed_at": identifier.first_observed_at,
                "last_observed_at": identifier.last_observed_at,
                "confidence": identifier.confidence,
                "manually_verified": identifier.manually_verified,
                "active": identifier.active,
                "shared_or_non_identifying": identifier.shared_or_non_identifying,
                "valid_from": identifier.valid_from,
                "valid_to": identifier.valid_to,
            }
            for identifier in asset.identifiers
        ],
        "findings": [
            {
                "id": str(finding.id),
                "plugin_id": finding.plugin_id,
                "severity": finding.severity,
                "status": finding.status,
                "port": finding.port,
                "protocol": finding.protocol,
                "service": finding.service,
                "first_found_at": finding.first_found_at,
                "last_found_at": finding.last_found_at,
                "maturity_date": finding.maturity_date,
                "maturity_date_source": finding.maturity_date_source,
                "maturity_gate_date": finding.maturity_gate_date,
                "maturity_status": finding.maturity_status,
                "sla_due_date": finding.sla_due_date,
                "sla_status": finding.sla_status,
                "reopened_count": finding.reopened_count,
            }
            for finding in findings
        ],
        "import_history": [
            {
                "id": str(import_run.id),
                "status": import_run.status,
                "source_type": import_run.source_type,
                "original_filename": source.original_filename,
                "requested_at": import_run.requested_at,
                "completed_at": import_run.completed_at,
            }
            for import_run, source in import_rows
        ],
        "identity_history": [
            {
                "id": str(event.id),
                "occurred_at": event.occurred_at,
                "event_type": event.event_type,
                "primary_asset_id": str(event.primary_asset_id),
                "secondary_asset_id": str(event.secondary_asset_id) if event.secondary_asset_id else None,
                "payload": event.payload,
                "reversible": event.reversible,
                "undone_by_event_id": str(event.undone_by_event_id) if event.undone_by_event_id else None,
            }
            for event in identity_events
        ],
    }


@router.get("/metadata/export")
def export_asset_metadata(
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "asset_id",
            "canonical_hostname",
            *ASSET_METADATA_FIELDS,
            "tags",
        ]
    )
    for asset in db.scalars(
        select(Asset)
        .where(Asset.active.is_(True), Asset.merged_into_id.is_(None))
        .options(selectinload(Asset.tags))
        .order_by(Asset.canonical_hostname, Asset.id)
    ):
        writer.writerow(
            [
                str(asset.id),
                formula_safe(asset.canonical_hostname),
                *(formula_safe(getattr(asset, field_name)) for field_name in ASSET_METADATA_FIELDS),
                formula_safe(", ".join(sorted(tag.name for tag in asset.tags))),
            ]
        )
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="vulnerability-workbench-asset-metadata.csv"'},
    )


@router.post("/metadata/import")
async def import_asset_metadata(
    request: Request,
    upload: UploadFile = File(),
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    content = await upload.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Metadata CSV exceeds the configured upload limit.",
        )
    if b"\x00" in content:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Metadata CSV may not contain NUL bytes.",
        )
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Metadata CSV must be UTF-8 encoded.",
        ) from exc
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames or not {"asset_id", "canonical_hostname"}.intersection(reader.fieldnames):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Metadata CSV requires asset_id or canonical_hostname.",
        )
    updated = 0
    skipped = 0
    warnings: list[dict[str, Any]] = []
    for row_number, row in enumerate(reader, start=2):
        asset: Asset | None = None
        asset_id = (row.get("asset_id") or "").strip()
        hostname = (row.get("canonical_hostname") or "").strip().lower().rstrip(".")
        if asset_id:
            try:
                asset = db.get(Asset, uuid.UUID(asset_id))
            except ValueError:
                asset = None
        elif hostname:
            matches = list(
                db.scalars(
                    select(Asset).where(
                        Asset.active.is_(True),
                        Asset.merged_into_id.is_(None),
                        Asset.canonical_hostname == hostname,
                    )
                )
            )
            if len(matches) == 1:
                asset = matches[0]
            elif len(matches) > 1:
                warnings.append(
                    {
                        "row": row_number,
                        "message": "Hostname matched multiple assets; row was not applied.",
                    }
                )
        if asset is None or not asset.active or asset.merged_into_id is not None:
            skipped += 1
            warnings.append(
                {"row": row_number, "message": "Canonical active asset was not uniquely identified."}
            )
            continue
        for field_name in ASSET_METADATA_FIELDS:
            if field_name in row:
                value = (row.get(field_name) or "").strip() or None
                setattr(asset, field_name, value)
        if "tags" in row:
            tag_names = sorted(
                {item.strip() for item in (row.get("tags") or "").split(",") if item.strip()},
                key=str.casefold,
            )
            tags: list[Tag] = []
            for name in tag_names:
                tag = db.scalar(select(Tag).where(Tag.name == name))
                if tag is None:
                    tag = Tag(name=name)
                    db.add(tag)
                    db.flush()
                tags.append(tag)
            asset.tags = tags
        updated += 1
    record_audit(
        db,
        event_type="asset.metadata_csv_imported",
        actor_user_id=principal.user.id,
        entity_type="asset",
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={
            "filename": upload.filename,
            "updated": updated,
            "skipped": skipped,
            "warnings": warnings[:100],
        },
    )
    db.commit()
    return {"updated": updated, "skipped": skipped, "warnings": warnings[:100]}


@router.get("/{asset_id}")
def asset_detail(
    asset_id: uuid.UUID,
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    asset = db.scalar(
        select(Asset)
        .where(Asset.id == asset_id, Asset.active.is_(True))
        .options(selectinload(Asset.identifiers), selectinload(Asset.tags))
    )
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
    return _asset_detail_payload(db, asset)


@router.patch("/{asset_id}")
def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    asset = db.scalar(
        select(Asset)
        .where(Asset.id == asset_id, Asset.active.is_(True), Asset.merged_into_id.is_(None))
        .options(selectinload(Asset.identifiers), selectinload(Asset.tags))
        .with_for_update()
    )
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
    changes: dict[str, Any] = {}
    for field_name in ASSET_METADATA_FIELDS:
        if field_name in payload.model_fields_set:
            previous = getattr(asset, field_name)
            incoming = getattr(payload, field_name)
            if previous != incoming:
                changes[field_name] = {"previous": previous, "new": incoming}
                setattr(asset, field_name, incoming)
    if "tags" in payload.model_fields_set and payload.tags is not None:
        previous_tags = sorted(tag.name for tag in asset.tags)
        next_tags: list[Tag] = []
        for name in payload.tags:
            tag = db.scalar(select(Tag).where(Tag.name == name))
            if tag is None:
                tag = Tag(name=name)
                db.add(tag)
                db.flush()
            next_tags.append(tag)
        asset.tags = next_tags
        if previous_tags != payload.tags:
            changes["tags"] = {"previous": previous_tags, "new": payload.tags}
    if changes:
        record_audit(
            db,
            event_type="asset.metadata_updated",
            actor_user_id=principal.user.id,
            entity_type="asset",
            entity_id=asset.id,
            request_id=getattr(request.state, "request_id", None),
            client_ip=request_client_ip(request),
            details={"changes": changes},
        )
    db.commit()
    db.refresh(asset)
    return _asset_detail_payload(db, asset)
