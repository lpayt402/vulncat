from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from vulnbatch.api.deps import Principal, get_current_principal, request_client_ip, require_csrf
from vulnbatch.audit.service import record_audit
from vulnbatch.db.models import SavedView
from vulnbatch.db.session import get_db
from vulnbatch.queries.service import normalize_host_query
from vulnbatch.schemas.auth import MessageResponse
from vulnbatch.schemas.query import SavedViewCreate, SavedViewResponse, SavedViewUpdate

router = APIRouter(prefix="/api/v1/saved-views", tags=["saved views"])


def _response(view: SavedView) -> SavedViewResponse:
    return SavedViewResponse(
        id=view.id,
        owner_user_id=view.owner_user_id,
        name=view.name,
        description=view.description,
        shared=view.shared,
        query_schema_version=view.query_schema_version,
        query=view.query_json,
        revision=view.revision,
        created_at=view.created_at,
        updated_at=view.updated_at,
    )


def _can_edit(principal: Principal, view: SavedView) -> bool:
    return principal.user.id == view.owner_user_id or principal.user.role.name == "administrator"


@router.get("", response_model=list[SavedViewResponse])
def list_saved_views(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[SavedViewResponse]:
    views = list(
        db.scalars(
            select(SavedView)
            .where(or_(SavedView.owner_user_id == principal.user.id, SavedView.shared.is_(True)))
            .order_by(SavedView.name.asc(), SavedView.id.asc())
        )
    )
    return [_response(view) for view in views]


@router.post("", response_model=SavedViewResponse, status_code=status.HTTP_201_CREATED)
def create_saved_view(
    payload: SavedViewCreate,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> SavedViewResponse:
    if payload.shared and principal.user.role.name != "administrator":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Only administrators may share views."
        )
    try:
        normalized = normalize_host_query(payload.query)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    existing = db.scalar(
        select(SavedView).where(
            SavedView.owner_user_id == principal.user.id,
            SavedView.name == payload.name.strip(),
        )
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A saved view with this name exists."
        )
    view = SavedView(
        owner_user_id=principal.user.id,
        name=payload.name.strip(),
        description=payload.description,
        shared=payload.shared,
        query_schema_version=normalized.schema_version,
        query_json=normalized.model_dump(mode="json", exclude_none=True),
    )
    db.add(view)
    db.flush()
    record_audit(
        db,
        event_type="saved_view.created",
        actor_user_id=principal.user.id,
        entity_type="saved_view",
        entity_id=view.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={"name": view.name, "shared": view.shared, "query": view.query_json},
    )
    db.commit()
    db.refresh(view)
    return _response(view)


@router.get("/{view_id}", response_model=SavedViewResponse)
def get_saved_view(
    view_id: uuid.UUID,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> SavedViewResponse:
    view = db.get(SavedView, view_id)
    if view is None or not (view.shared or view.owner_user_id == principal.user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Saved view not found.")
    return _response(view)


@router.put("/{view_id}", response_model=SavedViewResponse)
def update_saved_view(
    view_id: uuid.UUID,
    payload: SavedViewUpdate,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> SavedViewResponse:
    view = db.get(SavedView, view_id, with_for_update=True)
    if view is None or not _can_edit(principal, view):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Saved view not found.")
    if payload.shared and principal.user.role.name != "administrator":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Only administrators may share views."
        )
    try:
        normalized = normalize_host_query(payload.query)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    view.name = payload.name.strip()
    view.description = payload.description
    view.shared = payload.shared
    view.query_schema_version = normalized.schema_version
    view.query_json = normalized.model_dump(mode="json", exclude_none=True)
    view.revision += 1
    record_audit(
        db,
        event_type="saved_view.updated",
        actor_user_id=principal.user.id,
        entity_type="saved_view",
        entity_id=view.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={
            "name": view.name,
            "revision": view.revision,
            "shared": view.shared,
            "query": view.query_json,
        },
    )
    db.commit()
    db.refresh(view)
    return _response(view)


@router.delete("/{view_id}", response_model=MessageResponse)
def delete_saved_view(
    view_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> MessageResponse:
    view = db.get(SavedView, view_id, with_for_update=True)
    if view is None or not _can_edit(principal, view):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Saved view not found.")
    record_audit(
        db,
        event_type="saved_view.deleted",
        actor_user_id=principal.user.id,
        entity_type="saved_view",
        entity_id=view.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={"name": view.name, "revision": view.revision},
    )
    db.delete(view)
    db.commit()
    return MessageResponse(message="Saved view deleted.")
