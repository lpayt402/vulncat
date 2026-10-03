from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vulnbatch.api.deps import (
    Principal,
    get_current_principal,
    request_client_ip,
    require_admin_csrf,
)
from vulnbatch.audit.service import record_audit
from vulnbatch.core.config import Settings, get_settings
from vulnbatch.db.models import (
    IdentityReviewItem,
    ImportProfile,
    ImportRun,
    Job,
    SourceFile,
)
from vulnbatch.db.session import get_db
from vulnbatch.imports.generic_csv import preview_generic_csv
from vulnbatch.imports.models import ImportParseError
from vulnbatch.jobs.service import enqueue_job
from vulnbatch.schemas.imports import (
    GenericCommitRequest,
    GenericPreviewResponse,
    ImportResponse,
    SourceType,
)

router = APIRouter(prefix="/api/v1/imports", tags=["imports"])

SOURCE_EXTENSIONS = {
    "tenable_csv": {".csv"},
    "tenable_json": {".json", ".ndjson"},
    "nessus_xml": {".nessus", ".xml"},
    "generic_csv": {".csv"},
}


def _response(import_run: ImportRun, duplicate_of: uuid.UUID | None = None) -> ImportResponse:
    return ImportResponse(
        id=import_run.id,
        source_file_id=import_run.source_file_id,
        source_type=import_run.source_type,
        status=import_run.status,
        duplicate_of_import_id=duplicate_of,
        force_reprocess=import_run.force_reprocess,
        complete_comparable_scope=import_run.complete_comparable_scope,
        requested_at=import_run.requested_at,
        started_at=import_run.started_at,
        completed_at=import_run.completed_at,
        failed_at=import_run.failed_at,
        failure_reason=import_run.failure_reason,
        total_records=import_run.total_records,
        included_records=import_run.included_records,
        skipped_records=import_run.skipped_records,
        severity_counts=import_run.severity_counts,
        unique_assets=import_run.unique_assets,
        new_assets=import_run.new_assets,
        matched_assets=import_run.matched_assets,
        ambiguous_assets=import_run.ambiguous_assets,
        new_findings=import_run.new_findings,
        updated_findings=import_run.updated_findings,
        parse_warnings=import_run.parse_warnings,
        mapping_warnings=import_run.mapping_warnings,
    )


def _validate_signature(source_type: SourceType, suffix: str, prefix: bytes) -> None:
    if suffix not in SOURCE_EXTENSIONS[source_type]:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"File extension {suffix or '(none)'} is not valid for {source_type}.",
        )
    stripped = prefix.lstrip()
    if source_type == "nessus_xml" and not stripped.startswith(b"<"):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Nessus input does not have an XML signature.",
        )
    if source_type in {"tenable_csv", "generic_csv", "tenable_json"} and b"\x00" in prefix:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Text imports may not contain NUL bytes.",
        )
    if source_type == "tenable_json" and stripped[:1] not in {b"{", b"["}:
        first_line = stripped.splitlines()[0] if stripped else b""
        if not first_line.startswith(b"{"):
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Tenable JSON must contain JSON, a JSON array, or newline-delimited JSON.",
            )


async def _save_upload(
    db: Session,
    *,
    upload: UploadFile,
    source_type: SourceType,
    user_id: uuid.UUID,
    settings: Settings,
) -> tuple[SourceFile, bool]:
    filename = Path(upload.filename or "upload").name[:512]
    suffix = Path(filename).suffix.lower()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(prefix=".upload-", dir=settings.upload_dir)
    digest = hashlib.sha256()
    total = 0
    prefix = bytearray()
    try:
        with os.fdopen(handle, "wb") as destination:
            while chunk := await upload.read(1024 * 1024):
                total += len(chunk)
                if total > settings.max_upload_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Upload exceeds the configured {settings.max_upload_bytes}-byte limit.",
                    )
                digest.update(chunk)
                if len(prefix) < 4096:
                    prefix.extend(chunk[: 4096 - len(prefix)])
                destination.write(chunk)
        if total == 0:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Upload is empty.")
        _validate_signature(source_type, suffix, bytes(prefix))
        sha256 = digest.hexdigest()
        existing = db.scalar(select(SourceFile).where(SourceFile.sha256 == sha256))
        if existing is not None:
            existing_path = Path(existing.storage_path)
            if existing_path.is_file():
                Path(temp_name).unlink(missing_ok=True)
            else:
                final_dir = settings.upload_dir / sha256[:2]
                final_dir.mkdir(parents=True, exist_ok=True)
                restored_path = final_dir / f"{sha256}{suffix}"
                os.replace(temp_name, restored_path)
                existing.storage_path = str(restored_path)
            return existing, True
        final_dir = settings.upload_dir / sha256[:2]
        final_dir.mkdir(parents=True, exist_ok=True)
        final_path = final_dir / f"{sha256}{suffix}"
        os.replace(temp_name, final_path)
        source = SourceFile(
            sha256=sha256,
            original_filename=filename,
            content_type=upload.content_type,
            source_type=source_type,
            byte_size=total,
            storage_path=str(final_path),
            uploaded_by_id=user_id,
        )
        db.add(source)
        db.flush()
        return source, False
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def _previous_import(db: Session, source_file_id: uuid.UUID) -> ImportRun | None:
    return db.scalar(
        select(ImportRun)
        .where(ImportRun.source_file_id == source_file_id)
        .order_by(ImportRun.completed_at.desc().nullslast(), ImportRun.requested_at.desc())
        .limit(1)
    )


def _queue_import(
    db: Session,
    *,
    source: SourceFile,
    user_id: uuid.UUID,
    source_type: SourceType,
    force_reprocess: bool,
    complete_comparable_scope: bool,
    mapping: dict[str, str] | None = None,
    profile_id: uuid.UUID | None = None,
) -> ImportRun:
    job = enqueue_job(db, job_type="import", payload={}, max_attempts=3)
    import_run = ImportRun(
        source_file_id=source.id,
        importing_user_id=user_id,
        import_profile_id=profile_id,
        job_id=job.id,
        status="queued",
        source_type=source_type,
        force_reprocess=force_reprocess,
        complete_comparable_scope=complete_comparable_scope,
        mapping=mapping,
    )
    db.add(import_run)
    db.flush()
    job.payload = {"import_id": str(import_run.id)}
    job.unique_key = f"import:{import_run.id}"
    return import_run


@router.post("/upload", response_model=ImportResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_import(
    request: Request,
    upload: Annotated[UploadFile, File()],
    source_type: Annotated[SourceType, Form()],
    force_reprocess: Annotated[bool, Form()] = False,
    complete_comparable_scope: Annotated[bool, Form()] = False,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ImportResponse:
    source, duplicate = await _save_upload(
        db,
        upload=upload,
        source_type=source_type,
        user_id=principal.user.id,
        settings=settings,
    )
    previous = _previous_import(db, source.id)
    if duplicate and previous is not None and not force_reprocess:
        record_audit(
            db,
            event_type="import.duplicate_detected",
            actor_user_id=principal.user.id,
            entity_type="source_file",
            entity_id=source.id,
            request_id=getattr(request.state, "request_id", None),
            client_ip=request_client_ip(request),
            details={"sha256": source.sha256, "previous_import_id": str(previous.id)},
        )
        db.commit()
        return _response(previous, duplicate_of=previous.id)
    import_run = _queue_import(
        db,
        source=source,
        user_id=principal.user.id,
        source_type=source_type,
        force_reprocess=force_reprocess,
        complete_comparable_scope=complete_comparable_scope,
    )
    record_audit(
        db,
        event_type="import.submitted",
        actor_user_id=principal.user.id,
        entity_type="import",
        entity_id=import_run.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={
            "source_file_id": str(source.id),
            "sha256": source.sha256,
            "source_type": source_type,
            "force_reprocess": force_reprocess,
            "complete_comparable_scope": complete_comparable_scope,
        },
    )
    db.commit()
    db.refresh(import_run)
    return _response(import_run)


@router.post("/generic/preview", response_model=GenericPreviewResponse)
async def preview_generic(
    upload: Annotated[UploadFile, File()],
    mapping_json: Annotated[str, Form()],
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> GenericPreviewResponse:
    try:
        mapping = json.loads(mapping_json)
        if not isinstance(mapping, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in mapping.items()
        ):
            raise ValueError
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="mapping_json must be a JSON object of canonical field to source column.",
        ) from exc
    source, duplicate = await _save_upload(
        db,
        upload=upload,
        source_type="generic_csv",
        user_id=principal.user.id,
        settings=settings,
    )
    previous = _previous_import(db, source.id)
    try:
        with Path(source.storage_path).open(
            "r", encoding="utf-8-sig", errors="replace", newline=""
        ) as stream:
            preview = preview_generic_csv(
                stream,
                mapping=mapping,
                tracked_severities=settings.tracked_severities,
                limit=20,
            )
    except ImportParseError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    db.commit()
    return GenericPreviewResponse(
        source_file_id=source.id,
        duplicate=duplicate,
        previous_import_id=previous.id if previous else None,
        headers=list(preview.headers),
        records=[record.model_dump(mode="json") for record in preview.records],
        mapping_warnings=[warning.model_dump(mode="json") for warning in preview.mapping_warnings],
        unmapped_columns=list(preview.unmapped_columns),
        truncated=preview.truncated,
    )


@router.post("/generic/commit", response_model=ImportResponse, status_code=status.HTTP_202_ACCEPTED)
def commit_generic(
    payload: GenericCommitRequest,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ImportResponse:
    source = db.get(SourceFile, payload.source_file_id)
    if source is None or source.source_type != "generic_csv":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Generic CSV source file not found."
        )
    previous = _previous_import(db, source.id)
    if previous is not None and not payload.force_reprocess:
        return _response(previous, duplicate_of=previous.id)
    try:
        with Path(source.storage_path).open(
            "r", encoding="utf-8-sig", errors="replace", newline=""
        ) as stream:
            preview_generic_csv(
                stream,
                mapping=payload.mapping,
                tracked_severities=settings.tracked_severities,
                limit=1,
            )
    except ImportParseError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    profile_id = None
    if payload.profile_name:
        if payload.share_profile and principal.user.role.name != "administrator":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators may create shared import profiles.",
            )
        profile = ImportProfile(
            owner_user_id=principal.user.id,
            name=payload.profile_name.strip(),
            shared=payload.share_profile,
            source_signature=[],
            mapping=payload.mapping,
        )
        db.add(profile)
        db.flush()
        profile_id = profile.id
    import_run = _queue_import(
        db,
        source=source,
        user_id=principal.user.id,
        source_type="generic_csv",
        force_reprocess=payload.force_reprocess,
        complete_comparable_scope=payload.complete_comparable_scope,
        mapping=payload.mapping,
        profile_id=profile_id,
    )
    record_audit(
        db,
        event_type="import.generic_committed",
        actor_user_id=principal.user.id,
        entity_type="import",
        entity_id=import_run.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={
            "source_file_id": str(source.id),
            "mapping": payload.mapping,
            "profile_id": str(profile_id) if profile_id else None,
        },
    )
    db.commit()
    db.refresh(import_run)
    return _response(import_run)


@router.get("", response_model=list[ImportResponse])
def list_imports(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[ImportResponse]:
    del principal
    return [
        _response(import_run)
        for import_run in db.scalars(select(ImportRun).order_by(ImportRun.requested_at.desc()).limit(200))
    ]


@router.get("/{import_id}")
def get_import(
    import_id: uuid.UUID,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del principal
    import_run = db.get(ImportRun, import_id)
    if import_run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Import not found.")
    source = db.get(SourceFile, import_run.source_file_id)
    job = db.get(Job, import_run.job_id) if import_run.job_id else None
    review_count = int(
        db.scalar(
            select(func.count(IdentityReviewItem.id)).where(
                IdentityReviewItem.source_import_id == import_run.id
            )
        )
        or 0
    )
    return {
        **_response(import_run).model_dump(mode="json"),
        "source_file": {
            "id": str(source.id),
            "original_filename": source.original_filename,
            "sha256": source.sha256,
            "content_type": source.content_type,
            "byte_size": source.byte_size,
            "uploaded_at": source.uploaded_at,
        }
        if source
        else None,
        "job": {
            "status": job.status,
            "progress": job.progress,
            "attempts": job.attempts,
            "error_message": job.error_message,
        }
        if job
        else None,
        "identity_review_items": review_count,
    }
