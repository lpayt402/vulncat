from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vulnbatch.api.deps import Principal, request_client_ip, require_admin, require_admin_csrf
from vulnbatch.audit.service import record_audit
from vulnbatch.core.security import (
    hash_password,
    normalize_username,
    utcnow,
    validate_password,
    validate_username,
)
from vulnbatch.db.models import Role, User, UserSession
from vulnbatch.db.session import get_db
from vulnbatch.schemas.users import (
    ManagedUserResponse,
    PasswordReset,
    UserCreate,
    UserUpdate,
)

router = APIRouter(prefix="/api/v1/users", tags=["users"])


def _response(user: User) -> ManagedUserResponse:
    return ManagedUserResponse(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        role=user.role.name,
        is_active=user.is_active,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


def _active_admin_count(db: Session) -> int:
    return int(
        db.scalar(
            select(func.count(User.id))
            .join(Role, Role.id == User.role_id)
            .where(User.is_active.is_(True), Role.name == "administrator")
        )
        or 0
    )


def _role(db: Session, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description=f"{name.replace('_', ' ').title()} access")
        db.add(role)
        db.flush()
    return role


def _validate_new_password(password: str, username: str) -> None:
    result = validate_password(password, username)
    if not result.valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"password": list(result.errors)},
        )


@router.get("", response_model=list[ManagedUserResponse])
def list_users(
    _: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[ManagedUserResponse]:
    users = list(db.scalars(select(User).order_by(User.username.asc(), User.id.asc())))
    return [_response(user) for user in users]


@router.post("", response_model=ManagedUserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> ManagedUserResponse:
    username = normalize_username(payload.username)
    if not validate_username(username):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Username must be 3-64 lowercase letters, numbers, dots, underscores, or hyphens.",
        )
    _validate_new_password(payload.password, username)
    user = User(
        username=username,
        display_name=payload.display_name.strip(),
        password_hash=hash_password(payload.password),
        role_id=_role(db, payload.role).id,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists.",
        ) from exc
    record_audit(
        db,
        event_type="user.created",
        actor_user_id=principal.user.id,
        entity_type="user",
        entity_id=user.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={"username": username, "role": payload.role},
    )
    db.commit()
    db.refresh(user)
    return _response(user)


@router.patch("/{user_id}", response_model=ManagedUserResponse)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> ManagedUserResponse:
    user = db.get(User, user_id, with_for_update=True)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    if user.id == principal.user.id and (payload.is_active is False or payload.role == "read_only"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You cannot deactivate or remove administrator access from your current account.",
        )
    removes_admin = user.role.name == "administrator" and (
        payload.is_active is False or payload.role == "read_only"
    )
    if removes_admin and _active_admin_count(db) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="At least one active administrator must remain.",
        )
    previous = {
        "display_name": user.display_name,
        "role": user.role.name,
        "is_active": user.is_active,
    }
    if payload.display_name is not None:
        user.display_name = payload.display_name.strip()
    if payload.role is not None:
        user.role_id = _role(db, payload.role).id
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if previous["role"] != (payload.role or previous["role"]) or payload.is_active is False:
        db.execute(
            update(UserSession)
            .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
    record_audit(
        db,
        event_type="user.updated",
        actor_user_id=principal.user.id,
        entity_type="user",
        entity_id=user.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={
            "previous": previous,
            "new": {
                "display_name": user.display_name,
                "role": payload.role or previous["role"],
                "is_active": user.is_active,
            },
        },
    )
    db.commit()
    db.refresh(user)
    return _response(user)


@router.post("/{user_id}/reset-password")
def reset_user_password(
    user_id: uuid.UUID,
    payload: PasswordReset,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    user = db.get(User, user_id, with_for_update=True)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    _validate_new_password(payload.password, user.username)
    user.password_hash = hash_password(payload.password)
    db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    record_audit(
        db,
        event_type="user.password_reset",
        actor_user_id=principal.user.id,
        entity_type="user",
        entity_id=user.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
    )
    db.commit()
    return {"message": f"Password reset for {user.username}. Existing sessions were signed out."}
