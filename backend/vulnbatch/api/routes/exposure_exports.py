from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from vulnbatch.api.deps import Principal, get_current_principal
from vulnbatch.core.security import utcnow
from vulnbatch.db.session import get_db
from vulnbatch.exposure import queries
from vulnbatch.reporting import REPORT_COLUMNS, render_payload

router = APIRouter(prefix="/api/v1/exposure", tags=["service exposure"])


@router.get("/report/export")
def export_report(
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    format: Literal["json", "csv", "markdown"] = "json",
    node_id: uuid.UUID | None = None,
    observation_kind: Literal["inventory", "vulnerability", "coverage"] | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> Response:
    """Export exactly one bounded report page with the same renderer as the CLI."""
    payload = queries.report(
        db, node_id=node_id, observation_kind=observation_kind, offset=offset, limit=limit, now=utcnow()
    )
    suffix, media_type = {
        "json": ("json", "application/json"),
        "csv": ("csv", "text/csv"),
        "markdown": ("md", "text/markdown"),
    }[format]
    return Response(
        render_payload(payload, format, REPORT_COLUMNS),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="vulncat-exposure-page.{suffix}"'},
    )
