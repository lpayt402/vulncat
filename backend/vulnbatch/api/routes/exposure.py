from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from vulnbatch.api.deps import Principal, get_current_principal, require_admin_csrf
from vulnbatch.core.security import utcnow
from vulnbatch.db.session import get_db
from vulnbatch.exposure import queries, service
from vulnbatch.reconciliation.storage import ReconciliationConflict
from vulnbatch.schemas.exposure import ApplyRequest, NodeKind, PreviewRequest, UndoRequest

router = APIRouter(prefix="/api/v1/exposure", tags=["service exposure"])


def _write(db: Session, action: Callable[[], dict[str, Any]], *, commit: bool = True) -> dict[str, Any]:
    try:
        result = action()
        if commit:
            db.commit()
        return result
    except ReconciliationConflict as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc
    except (ValueError, UnicodeError, RecursionError) as exc:
        db.rollback()
        raise HTTPException(422, str(exc)[:500]) from exc
    except Exception:
        db.rollback()
        raise


@router.post("/preview")
def preview(
    payload: PreviewRequest, principal: Principal = Depends(require_admin_csrf), db: Session = Depends(get_db)
) -> dict[str, Any]:
    return _write(db, lambda: service.preview(db, payload.graph, principal.user.id, utcnow()), commit=False)


@router.post("/apply")
def apply(
    payload: ApplyRequest, principal: Principal = Depends(require_admin_csrf), db: Session = Depends(get_db)
) -> dict[str, Any]:
    return _write(db, lambda: service.apply_graph(db, payload, principal.user.id, utcnow()))


@router.post("/undo")
def undo(
    payload: UndoRequest, principal: Principal = Depends(require_admin_csrf), db: Session = Depends(get_db)
) -> dict[str, Any]:
    return _write(db, lambda: service.undo(db, payload, principal.user.id, utcnow()))


@router.get("/nodes")
def nodes(
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    q: str = Query("", max_length=255, pattern="^[^\\x00]*$"),
    kind: NodeKind | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    return queries.nodes(db, q=q, kind=kind, offset=offset, limit=limit, now=utcnow())


@router.get("/nodes/{node_id}")
def node_detail(
    node_id: uuid.UUID,
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    fact_offset: int = Query(0, ge=0),
    fact_limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    try:
        return queries.node_detail(db, node_id, fact_offset=fact_offset, fact_limit=fact_limit, now=utcnow())
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/graph")
def graph(
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    node_id: uuid.UUID | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    relationship_offset: int = Query(0, ge=0),
    relationship_limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    return queries.graph(
        db,
        node_id=node_id,
        offset=offset,
        limit=limit,
        relationship_offset=relationship_offset,
        relationship_limit=relationship_limit,
        now=utcnow(),
    )


@router.get("/report")
def report(
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    node_id: uuid.UUID | None = None,
    observation_kind: Literal["inventory", "vulnerability", "coverage"] | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    return queries.report(
        db, node_id=node_id, observation_kind=observation_kind, offset=offset, limit=limit, now=utcnow()
    )


@router.get("/history")
def history(
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    node_id: uuid.UUID | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    return queries.history(db, node_id=node_id, offset=offset, limit=limit)
