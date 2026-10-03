from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnbatch.api.deps import Principal, get_current_principal, request_client_ip, require_csrf
from vulnbatch.audit.service import record_audit
from vulnbatch.core.config import Settings, get_settings
from vulnbatch.core.security import utcnow
from vulnbatch.db.models import ExportJob, Job
from vulnbatch.db.session import get_db
from vulnbatch.exports.service import create_export_snapshot, export_response
from vulnbatch.schemas.auth import MessageResponse
from vulnbatch.schemas.query import ExportCreateRequest, ExportResponse

router = APIRouter(prefix="/api/v1/exports", tags=["exports"])


def _get_permitted_export(db: Session, export_id: uuid.UUID, principal: Principal) -> ExportJob:
    export = db.get(ExportJob, export_id)
    if export is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export not found.")
    if export.requested_by_id != principal.user.id and principal.user.role.name != "administrator":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export not found.")
    return export


@router.post("", response_model=ExportResponse, status_code=status.HTTP_202_ACCEPTED)
def create_export(
    payload: ExportCreateRequest,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> ExportResponse:
    export = create_export_snapshot(
        db,
        request=payload,
        requesting_user_id=principal.user.id,
    )
    record_audit(
        db,
        event_type="export.submitted",
        actor_user_id=principal.user.id,
        entity_type="export",
        entity_id=export.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={
            "scope_mode": export.scope_mode,
            "saved_view_id": str(export.saved_view_id) if export.saved_view_id else None,
            "saved_view_revision": export.saved_view_revision,
            "original_query": export.original_query_json,
            "normalized_query": export.normalized_query_json,
            "query_schema_version": export.query_schema_version,
            "finding_scope": export.finding_scope_json,
            "output_format": export.output_format,
            "matched_host_count": export.matched_host_count,
            "matched_finding_count": export.matched_finding_count,
            "data_as_of": export.data_as_of.isoformat(),
        },
    )
    db.commit()
    db.refresh(export)
    return export_response(export)


@router.get("", response_model=list[ExportResponse])
def list_exports(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[ExportResponse]:
    statement = select(ExportJob)
    if principal.user.role.name != "administrator":
        statement = statement.where(ExportJob.requested_by_id == principal.user.id)
    exports = list(db.scalars(statement.order_by(ExportJob.requested_at.desc()).limit(200)))
    return [export_response(export) for export in exports]


@router.get("/{export_id}", response_model=ExportResponse)
def get_export(
    export_id: uuid.UUID,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> ExportResponse:
    return export_response(_get_permitted_export(db, export_id, principal))


@router.get("/{export_id}/download")
def download_export(
    export_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> FileResponse:
    export = _get_permitted_export(db, export_id, principal)
    if export.status != "completed" or not export.output_path:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Export is not ready for download.")
    path = Path(export.output_path).resolve()
    report_root = settings.report_dir.resolve()
    if not path.is_relative_to(report_root) or not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_410_GONE, detail="Export artifact is no longer available."
        )
    record_audit(
        db,
        event_type="export.downloaded",
        actor_user_id=principal.user.id,
        entity_type="export",
        entity_id=export.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={"output_sha256": export.output_sha256, "output_byte_size": export.output_byte_size},
    )
    db.commit()
    media_type = {
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "csv": "application/zip",
        "html": "text/html; charset=utf-8",
    }[export.output_format]
    return FileResponse(
        path,
        media_type=media_type,
        filename=path.name,
        headers={"X-Content-SHA256": export.output_sha256 or ""},
    )


@router.post("/{export_id}/cancel", response_model=MessageResponse)
def cancel_export(
    export_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> MessageResponse:
    export = _get_permitted_export(db, export_id, principal)
    job = db.get(Job, export.job_id, with_for_update=True)
    if job is None or export.status != "queued" or job.status != "queued":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Only queued exports may be cancelled."
        )
    now = utcnow()
    job.status = "cancelled"
    job.cancelled_at = now
    export.status = "cancelled"
    record_audit(
        db,
        event_type="export.cancelled",
        actor_user_id=principal.user.id,
        entity_type="export",
        entity_id=export.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
    )
    db.commit()
    return MessageResponse(message="Export cancelled.")


@router.post("/{export_id}/retry", response_model=ExportResponse, status_code=status.HTTP_202_ACCEPTED)
def retry_export(
    export_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> ExportResponse:
    export = _get_permitted_export(db, export_id, principal)
    job = db.get(Job, export.job_id, with_for_update=True)
    if job is None or export.status != "failed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Only failed exports may be retried."
        )
    job.status = "queued"
    job.progress = 0
    job.attempts = 0
    job.available_at = utcnow()
    job.error_message = None
    job.failed_at = None
    export.status = "queued"
    export.progress = 0
    export.started_at = None
    export.completed_at = None
    export.failed_at = None
    export.failure_reason = None
    record_audit(
        db,
        event_type="export.retried",
        actor_user_id=principal.user.id,
        entity_type="export",
        entity_id=export.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
    )
    db.commit()
    db.refresh(export)
    return export_response(export)
