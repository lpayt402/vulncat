from __future__ import annotations

import csv
import uuid
from collections.abc import Callable
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import TypeAdapter
from sqlalchemy.orm import Session

from vulnbatch.api.deps import Principal, get_current_principal, require_admin_csrf
from vulnbatch.api.routes.reconciliation import MAX_FILES, MAX_TOTAL_BYTES, _read
from vulnbatch.core.security import utcnow
from vulnbatch.db.session import get_db
from vulnbatch.reconciliation import queries
from vulnbatch.reconciliation.decisions import apply_decision
from vulnbatch.reconciliation.models import Source, SourceOptions
from vulnbatch.reconciliation.storage import ImportDocument, ReconciliationConflict, persist_bundle
from vulnbatch.schemas.reconciliation import DecisionRequest

router = APIRouter(prefix="/api/v1/reconciliation", tags=["persistent reconciliation"])


def _write(db: Session, action: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        result = action()
        db.commit()
        return result
    except ReconciliationConflict as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc
    except (ValueError, UnicodeError, RecursionError, csv.Error) as exc:
        db.rollback()
        raise HTTPException(422, str(exc)[:500]) from exc
    except Exception:
        db.rollback()
        raise


@router.post("/imports")
def save_import(
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
    uploads: list[UploadFile] = File(),
    options_json: str = Form(),
    request_key: str = Form(min_length=1, max_length=128),
    expected_revision: int | None = Form(default=None, ge=0),
    preview_token: str | None = Form(default=None, max_length=2048),
) -> dict[str, Any]:
    if not 1 <= len(uploads) <= MAX_FILES:
        raise HTTPException(413, "Import supports 1-8 files")
    try:
        options = TypeAdapter(list[SourceOptions]).validate_json(options_json)
        if len(options) != len(uploads):
            raise ValueError("Each file requires exactly one source configuration")
        content = [_read(upload) for upload in uploads]
        if sum(map(len, content)) > MAX_TOTAL_BYTES:
            raise HTTPException(413, "Combined import files must be 30 MiB or smaller")
        documents = [
            ImportDocument(filename=upload.filename or "offline-export", content=data, options=config)
            for upload, data, config in zip(uploads, content, options, strict=True)
        ]
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(422, str(exc)[:500]) from exc
    return _write(
        db,
        lambda: persist_bundle(
            db,
            documents,
            actor_id=principal.user.id,
            request_key=request_key,
            now=utcnow(),
            expected_revision=expected_revision,
            preview_token=preview_token,
        ),
    )


@router.post("/decisions")
def record_decision(
    payload: DecisionRequest,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return _write(db, lambda: apply_decision(db, payload, actor_id=principal.user.id, now=utcnow()))


@router.get("/observations")
def list_observations(
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    review_status: Literal["open", "deferred", "assigned", "rejected"] | None = None,
    asset_id: uuid.UUID | None = None,
    source: Source | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    return queries.observations(
        db, review_status=review_status, asset_id=asset_id, source=source, offset=offset, limit=limit
    )


@router.get("/observations/{observation_id}")
def get_observation(
    observation_id: uuid.UUID, _: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> dict[str, Any]:
    try:
        return queries.observation_detail(db, observation_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/assets")
def list_assets(
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    q: str = Query("", max_length=255, pattern="^[^\\x00]*$"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    return queries.assets(db, q=q, offset=offset, limit=limit)


@router.get("/decisions")
def list_decisions(
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    return queries.decisions(db, offset=offset, limit=limit)


@router.get("/decisions/{decision_id}")
def get_decision(
    decision_id: uuid.UUID, _: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> dict[str, Any]:
    try:
        return queries.decision_detail(db, decision_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
