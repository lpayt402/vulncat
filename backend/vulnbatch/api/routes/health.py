from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from vulnbatch import __version__
from vulnbatch.db.session import get_db

router = APIRouter(tags=["system"])


@router.get("/healthz")
def health() -> dict[str, str]:
    return {"status": "healthy", "version": __version__}


@router.get("/readyz")
def readiness(db: Session = Depends(get_db)) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable.",
        ) from exc
    return {"status": "ready", "database": "ok", "version": __version__}
