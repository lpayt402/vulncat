from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnbatch.api.deps import Principal, get_current_principal, request_client_ip, require_admin_csrf
from vulnbatch.audit.service import record_audit
from vulnbatch.core.config import Settings, get_settings
from vulnbatch.db.models import ApplicationSetting
from vulnbatch.db.session import get_db
from vulnbatch.settings.service import effective_setting

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])

ALLOWED_KEYS = {
    "tracked_severities",
    "ip_association_staleness_days",
    "identity_auto_match_threshold",
    "maturity_gate_days",
    "medium_sla_days",
    "low_sla_days",
    "allow_finding_date_maturity_fallback",
    "large_export_finding_threshold",
    "export_retention_days",
    "upload_retention_days",
    "import_evidence_retention_days",
    "audit_retention_days",
}


def _coerce_setting_value(key: str, value: Any, settings: Settings) -> Any:
    current = getattr(settings, key)
    parsed = value
    if isinstance(value, str):
        stripped = value.strip()
        if current is None and stripped.lower() in {"", "null", "none"}:
            parsed = None
        elif isinstance(current, tuple):
            try:
                candidate = json.loads(stripped)
            except json.JSONDecodeError:
                candidate = [item.strip() for item in stripped.split(",") if item.strip()]
            parsed = candidate
        elif isinstance(current, bool):
            if stripped.lower() not in {"true", "false"}:
                raise ValueError("Boolean settings must be true or false.")
            parsed = stripped.lower() == "true"
        elif isinstance(current, int) or current is None:
            parsed = int(stripped)
        elif isinstance(current, float):
            parsed = float(stripped)
    candidate_settings = Settings.model_validate({**settings.model_dump(), key: parsed})
    validated = getattr(candidate_settings, key)
    return list(validated) if isinstance(validated, tuple) else validated


@router.get("")
def list_settings(
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    stored = {item.key: item.value for item in db.scalars(select(ApplicationSetting))}
    effective = {key: effective_setting(db, key, getattr(settings, key)) for key in sorted(ALLOWED_KEYS)}
    return {
        "effective": {
            **effective,
            "max_upload_bytes": settings.max_upload_bytes,
            "session_timeout_minutes": settings.session_timeout_minutes,
        },
        "stored_overrides": stored,
        "note": (
            "Stored calculation and retention overrides apply to new work immediately. "
            "Environment-only service settings require a restart."
        ),
    }


@router.put("/{key}")
def update_setting(
    key: str,
    value: Any,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    if key not in ALLOWED_KEYS:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unsupported setting.")
    try:
        validated_value = _coerce_setting_value(key, value, settings)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid value for {key}: {exc}",
        ) from exc
    setting = db.scalar(select(ApplicationSetting).where(ApplicationSetting.key == key))
    if setting is None:
        setting = ApplicationSetting(
            key=key,
            value=validated_value,
            updated_by_id=principal.user.id,
        )
        db.add(setting)
    else:
        setting.value = validated_value
        setting.updated_by_id = principal.user.id
    record_audit(
        db,
        event_type="settings.updated",
        actor_user_id=principal.user.id,
        entity_type="application_setting",
        entity_id=key,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={"key": key, "value": validated_value, "restart_required": False},
    )
    db.commit()
    return {"key": key, "value": validated_value, "restart_required": False}
