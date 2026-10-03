from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from vulnbatch.db.models import AuditEvent


def record_audit(
    db: Session,
    *,
    event_type: str,
    actor_user_id: uuid.UUID | None = None,
    entity_type: str | None = None,
    entity_id: str | uuid.UUID | None = None,
    request_id: str | None = None,
    client_ip: str | None = None,
    outcome: str = "success",
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        event_type=event_type,
        actor_user_id=actor_user_id,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        request_id=request_id,
        client_ip=client_ip,
        outcome=outcome,
        details=details or {},
    )
    db.add(event)
    return event
