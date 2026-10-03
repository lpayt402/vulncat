from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnbatch.core.config import Settings, get_settings
from vulnbatch.core.security import (
    constant_time_equal,
    csrf_token_for_session,
    hash_token,
    utcnow,
)
from vulnbatch.db.models import User, UserSession
from vulnbatch.db.session import get_db


@dataclass
class Principal:
    user: User
    session: UserSession
    raw_session_token: str


def request_client_ip(request: Request) -> str:
    if request.client is None:
        return "unknown"
    return request.client.host


def get_current_principal(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Principal:
    raw_token = request.cookies.get(settings.session_cookie_name)
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    token_hash = hash_token(raw_token)
    session = db.scalar(
        select(UserSession).where(
            UserSession.token_hash == token_hash,
            UserSession.revoked_at.is_(None),
        )
    )
    now = utcnow()
    if session is None or session.expires_at <= now or not session.user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session is invalid or expired.")
    session.last_seen_at = now
    session.expires_at = now + timedelta(minutes=settings.session_timeout_minutes)
    db.commit()
    return Principal(user=session.user, session=session, raw_session_token=raw_token)


def require_admin(principal: Principal = Depends(get_current_principal)) -> Principal:
    if principal.user.role.name != "administrator":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required.")
    return principal


def require_csrf(
    principal: Principal = Depends(get_current_principal),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> Principal:
    expected = csrf_token_for_session(principal.raw_session_token)
    if csrf_header is None or not constant_time_equal(expected, csrf_header):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed.")
    return principal


def require_admin_csrf(principal: Principal = Depends(require_csrf)) -> Principal:
    if principal.user.role.name != "administrator":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required.")
    return principal
