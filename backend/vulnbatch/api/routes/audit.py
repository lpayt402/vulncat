from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vulnbatch.api.deps import Principal, get_current_principal
from vulnbatch.db.models import AuditEvent
from vulnbatch.db.session import get_db

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("")
def list_audit_events(
    event_type: str | None = None,
    entity_type: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    conditions = []
    if event_type:
        conditions.append(AuditEvent.event_type == event_type)
    if entity_type:
        conditions.append(AuditEvent.entity_type == entity_type)
    total = int(db.scalar(select(func.count(AuditEvent.id)).where(*conditions)) or 0)
    events = list(
        db.scalars(
            select(AuditEvent)
            .where(*conditions)
            .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": [
            {
                "id": str(event.id),
                "occurred_at": event.occurred_at,
                "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
                "event_type": event.event_type,
                "entity_type": event.entity_type,
                "entity_id": event.entity_id,
                "outcome": event.outcome,
                "details": event.details,
                "request_id": event.request_id,
            }
            for event in events
        ],
    }
