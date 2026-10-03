from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vulnbatch.api.deps import Principal, get_current_principal, request_client_ip, require_csrf
from vulnbatch.audit.service import record_audit
from vulnbatch.core.config import Settings, get_settings
from vulnbatch.core.security import (
    csrf_token_for_session,
    generate_token,
    hash_password,
    hash_token,
    normalize_username,
    password_needs_rehash,
    utcnow,
    validate_password,
    validate_username,
    verify_password,
)
from vulnbatch.db.models import LoginAttempt, Role, User, UserSession
from vulnbatch.db.session import get_db
from vulnbatch.schemas.auth import (
    LoginRequest,
    MessageResponse,
    SessionResponse,
    SetupRequest,
    SetupStatusResponse,
    UserSummary,
)

router = APIRouter(prefix="/api/v1", tags=["authentication"])


def _has_admin(db: Session) -> bool:
    return (
        db.scalar(
            select(func.count(User.id))
            .join(Role, User.role_id == Role.id)
            .where(User.is_active.is_(True), Role.name == "administrator")
        )
        or 0
    ) > 0


def _session_response(user: User, raw_token: str) -> SessionResponse:
    return SessionResponse(
        user=UserSummary(
            id=user.id,
            username=user.username,
            display_name=user.display_name,
            role=user.role.name,
        ),
        csrf_token=csrf_token_for_session(raw_token),
    )


def _set_session_cookie(response: Response, raw_token: str, settings: Settings) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        raw_token,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        max_age=settings.session_timeout_minutes * 60,
        path="/",
    )


def _create_session(
    db: Session,
    *,
    user: User,
    request: Request,
    settings: Settings,
) -> tuple[UserSession, str]:
    raw_token = generate_token()
    csrf_token = csrf_token_for_session(raw_token)
    now = utcnow()
    session = UserSession(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        csrf_token_hash=hash_token(csrf_token),
        expires_at=now + timedelta(minutes=settings.session_timeout_minutes),
        client_ip=request_client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512] or None,
    )
    db.add(session)
    return session, raw_token


@router.get("/system/setup-status", response_model=SetupStatusResponse)
def setup_status(db: Session = Depends(get_db)) -> SetupStatusResponse:
    return SetupStatusResponse(setup_required=not _has_admin(db))


@router.post("/auth/setup", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
def first_run_setup(
    payload: SetupRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> SessionResponse:
    username = normalize_username(payload.username)
    if not validate_username(username):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Username must be 3-64 lowercase letters, numbers, dots, underscores, or hyphens.",
        )
    password_result = validate_password(payload.password, username)
    if not password_result.valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"password": list(password_result.errors)},
        )

    db.execute(text("SELECT pg_advisory_xact_lock(8787)"))
    if _has_admin(db):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="First-run setup is already complete."
        )

    role = db.scalar(select(Role).where(Role.name == "administrator"))
    if role is None:
        role = Role(name="administrator", description="Full administrative access")
        db.add(role)
        db.flush()
    read_only = db.scalar(select(Role).where(Role.name == "read_only"))
    if read_only is None:
        db.add(Role(name="read_only", description="Read-only inventory and report access"))

    user = User(
        username=username,
        display_name=payload.display_name.strip(),
        password_hash=hash_password(payload.password),
        role_id=role.id,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists.") from exc
    _, raw_token = _create_session(db, user=user, request=request, settings=settings)
    record_audit(
        db,
        event_type="auth.first_run_admin_created",
        actor_user_id=user.id,
        entity_type="user",
        entity_id=user.id,
        client_ip=request_client_ip(request),
        request_id=getattr(request.state, "request_id", None),
        details={"username": username, "role": "administrator"},
    )
    db.commit()
    db.refresh(user)
    _set_session_cookie(response, raw_token, settings)
    return _session_response(user, raw_token)


@router.post("/auth/login", response_model=SessionResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> SessionResponse:
    username = normalize_username(payload.username)
    client_ip = request_client_ip(request)
    window_start = utcnow() - timedelta(minutes=settings.login_window_minutes)
    recent_failures = (
        db.scalar(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.username == username,
                LoginAttempt.client_ip == client_ip,
                LoginAttempt.succeeded.is_(False),
                LoginAttempt.attempted_at >= window_start,
            )
        )
        or 0
    )
    if recent_failures >= settings.login_max_attempts:
        record_audit(
            db,
            event_type="auth.login_throttled",
            entity_type="user",
            entity_id=username,
            client_ip=client_ip,
            outcome="denied",
            request_id=getattr(request.state, "request_id", None),
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Login temporarily throttled."
        )

    user = db.scalar(select(User).where(User.username == username, User.is_active.is_(True)))
    succeeded = user is not None and verify_password(user.password_hash, payload.password)
    db.add(LoginAttempt(username=username, client_ip=client_ip, succeeded=succeeded))
    if not succeeded or user is None:
        record_audit(
            db,
            event_type="auth.login_failed",
            entity_type="user",
            entity_id=username,
            client_ip=client_ip,
            outcome="denied",
            request_id=getattr(request.state, "request_id", None),
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)
    user.last_login_at = utcnow()
    _, raw_token = _create_session(db, user=user, request=request, settings=settings)
    record_audit(
        db,
        event_type="auth.login_succeeded",
        actor_user_id=user.id,
        entity_type="user",
        entity_id=user.id,
        client_ip=client_ip,
        request_id=getattr(request.state, "request_id", None),
    )
    db.commit()
    _set_session_cookie(response, raw_token, settings)
    return _session_response(user, raw_token)


@router.get("/auth/session", response_model=SessionResponse)
def session_info(principal: Principal = Depends(get_current_principal)) -> SessionResponse:
    return _session_response(principal.user, principal.raw_session_token)


@router.post("/auth/logout", response_model=MessageResponse)
def logout(
    response: Response,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> MessageResponse:
    principal.session.revoked_at = utcnow()
    record_audit(
        db,
        event_type="auth.logout",
        actor_user_id=principal.user.id,
        entity_type="session",
        entity_id=principal.session.id,
        client_ip=request_client_ip(request),
        request_id=getattr(request.state, "request_id", None),
    )
    db.commit()
    response.delete_cookie(settings.session_cookie_name, path="/")
    return MessageResponse(message="Signed out.")
