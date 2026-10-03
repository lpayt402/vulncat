from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import cast, func, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from vulnbatch.api.deps import Principal, get_current_principal, request_client_ip, require_admin_csrf
from vulnbatch.audit.service import record_audit
from vulnbatch.core.security import utcnow
from vulnbatch.db.models import (
    Asset,
    AssetFinding,
    FindingObservation,
    FindingStatusHistory,
    VulnerabilityDefinition,
)
from vulnbatch.db.session import get_db

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


def _finding_dict(
    finding: AssetFinding, asset: Asset, definition: VulnerabilityDefinition
) -> dict[str, object]:
    today = utcnow().date()
    age = (today - finding.maturity_date).days if finding.maturity_date else None
    days_overdue = max(0, (today - finding.sla_due_date).days) if finding.sla_due_date is not None else None
    return {
        "id": str(finding.id),
        "asset_id": str(asset.id),
        "canonical_hostname": asset.canonical_hostname,
        "current_ip_addresses": [
            identifier.normalized_value
            for identifier in asset.identifiers
            if identifier.active and identifier.identifier_type in ("ipv4", "ipv6")
        ],
        "owner": asset.system_owner,
        "team": asset.administrative_team,
        "environment": asset.environment,
        "operating_system": asset.operating_system,
        "plugin_id": finding.plugin_id,
        "plugin_name": definition.plugin_name,
        "plugin_family": definition.plugin_family,
        "cves": definition.cves,
        "severity": finding.severity,
        "status": finding.status,
        "port": finding.port,
        "protocol": finding.protocol,
        "service": finding.service,
        "first_found_at": finding.first_found_at,
        "last_found_at": finding.last_found_at,
        "maturity_date": finding.maturity_date,
        "maturity_date_source": finding.maturity_date_source,
        "vulnerability_age_days": age,
        "maturity_status": finding.maturity_status,
        "sla_due_date": finding.sla_due_date,
        "sla_status": finding.sla_status,
        "days_overdue": days_overdue,
        "exploit_available": bool(
            definition.exploit_available or definition.exploited_by_malware or definition.known_exploited
        ),
    }


@router.get("")
def list_findings(
    severity: list[str] = Query(default=[]),
    finding_status: list[str] = Query(default=[]),
    maturity_state: list[str] = Query(default=[]),
    sla_state: list[str] = Query(default=[]),
    plugin_id: list[str] = Query(default=[]),
    plugin_family: list[str] = Query(default=[]),
    cve: list[str] = Query(default=[]),
    owner: list[str] = Query(default=[]),
    team: list[str] = Query(default=[]),
    environment: list[str] = Query(default=[]),
    maintenance_group: list[str] = Query(default=[]),
    port: list[int] = Query(default=[]),
    protocol: list[str] = Query(default=[]),
    q: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    conditions: list[Any] = []
    if severity:
        conditions.append(AssetFinding.severity.in_([value.lower() for value in severity]))
    if finding_status:
        conditions.append(AssetFinding.status.in_([value.lower() for value in finding_status]))
    if maturity_state:
        conditions.append(AssetFinding.maturity_status.in_([value.lower() for value in maturity_state]))
    if sla_state:
        conditions.append(AssetFinding.sla_status.in_([value.lower() for value in sla_state]))
    if plugin_id:
        conditions.append(AssetFinding.plugin_id.in_([value.strip().lower() for value in plugin_id]))
    if plugin_family:
        conditions.append(
            func.lower(VulnerabilityDefinition.plugin_family).in_([v.lower() for v in plugin_family])
        )
    if cve:
        for value in cve:
            conditions.append(cast(VulnerabilityDefinition.cves, JSONB).contains([value.strip().upper()]))
    if owner:
        conditions.append(func.lower(Asset.system_owner).in_([value.lower() for value in owner]))
    if team:
        conditions.append(func.lower(Asset.administrative_team).in_([value.lower() for value in team]))
    if environment:
        conditions.append(func.lower(Asset.environment).in_([value.lower() for value in environment]))
    if maintenance_group:
        conditions.append(
            func.lower(Asset.maintenance_group).in_([value.lower() for value in maintenance_group])
        )
    if port:
        conditions.append(AssetFinding.port.in_(port))
    if protocol:
        conditions.append(func.lower(AssetFinding.protocol).in_([value.lower() for value in protocol]))
    if q:
        pattern = f"%{q.strip().lower()}%"
        conditions.append(
            or_(
                func.lower(Asset.canonical_hostname).like(pattern),
                func.lower(VulnerabilityDefinition.plugin_name).like(pattern),
                func.lower(AssetFinding.plugin_id).like(pattern),
            )
        )

    base = (
        select(AssetFinding, Asset, VulnerabilityDefinition)
        .join(Asset, Asset.id == AssetFinding.asset_id)
        .join(
            VulnerabilityDefinition,
            VulnerabilityDefinition.id == AssetFinding.vulnerability_definition_id,
        )
        .where(*conditions)
    )
    count_query = select(func.count()).select_from(base.order_by(None).subquery())
    total = int(db.scalar(count_query) or 0)
    rows = db.execute(
        base.order_by(
            AssetFinding.severity.desc(),
            func.lower(func.coalesce(Asset.canonical_hostname, "")),
            AssetFinding.plugin_id,
            AssetFinding.id,
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": [_finding_dict(finding, asset, definition) for finding, asset, definition in rows],
    }


@router.get("/plugins")
def plugin_view(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    total = int(db.scalar(select(func.count(VulnerabilityDefinition.id))) or 0)
    definitions = list(
        db.scalars(
            select(VulnerabilityDefinition)
            .order_by(VulnerabilityDefinition.plugin_id, VulnerabilityDefinition.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    items: list[dict[str, object]] = []
    for definition in definitions:
        finding_rows = db.execute(
            select(AssetFinding, Asset)
            .join(Asset, Asset.id == AssetFinding.asset_id)
            .where(AssetFinding.vulnerability_definition_id == definition.id)
            .order_by(func.lower(func.coalesce(Asset.canonical_hostname, "")), Asset.id)
        ).all()
        items.append(
            {
                "id": str(definition.id),
                "plugin_id": definition.plugin_id,
                "plugin_name": definition.plugin_name,
                "plugin_family": definition.plugin_family,
                "severity": finding_rows[0][0].severity if finding_rows else None,
                "cves": definition.cves,
                "solution": definition.solution,
                "affected_host_count": len(finding_rows),
                "affected_hosts": [
                    {
                        "asset_id": str(asset.id),
                        "canonical_hostname": asset.canonical_hostname,
                        "owner": asset.system_owner,
                        "team": asset.administrative_team,
                        "first_found_at": finding.first_found_at,
                        "last_found_at": finding.last_found_at,
                        "maturity_status": finding.maturity_status,
                        "sla_status": finding.sla_status,
                    }
                    for finding, asset in finding_rows
                ],
            }
        )
    return {"page": page, "page_size": page_size, "total": total, "items": items}


@router.get("/{finding_id}")
def finding_detail(
    finding_id: uuid.UUID,
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    row = db.execute(
        select(AssetFinding, Asset, VulnerabilityDefinition)
        .join(Asset, Asset.id == AssetFinding.asset_id)
        .join(
            VulnerabilityDefinition,
            VulnerabilityDefinition.id == AssetFinding.vulnerability_definition_id,
        )
        .where(AssetFinding.id == finding_id)
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    finding, asset, definition = row
    observations = list(
        db.scalars(
            select(FindingObservation)
            .where(FindingObservation.finding_id == finding.id)
            .order_by(FindingObservation.observed_at.desc())
        )
    )
    history = list(
        db.scalars(
            select(FindingStatusHistory)
            .where(FindingStatusHistory.finding_id == finding.id)
            .order_by(FindingStatusHistory.changed_at.desc())
        )
    )
    detail = _finding_dict(finding, asset, definition)
    detail["synopsis"] = definition.synopsis
    detail["description"] = definition.description
    detail["solution"] = finding.current_solution or definition.solution
    detail["current_evidence"] = finding.current_evidence
    detail["observations"] = [
        {
            "id": str(observation.id),
            "import_id": str(observation.import_id),
            "observed_at": observation.observed_at,
            "scan_name": observation.scan_name,
            "scan_time": observation.scan_time,
            "evidence": observation.evidence,
            "severity": observation.severity,
        }
        for observation in observations
    ]
    detail["status_history"] = [
        {
            "id": str(item.id),
            "changed_at": item.changed_at,
            "previous_status": item.previous_status,
            "new_status": item.new_status,
            "reason": item.reason,
            "source_import_id": str(item.source_import_id) if item.source_import_id else None,
        }
        for item in history
    ]
    return detail


@router.put("/{finding_id}/status")
def update_finding_status(
    finding_id: uuid.UUID,
    new_status: str,
    reason: str,
    request: Request,
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    allowed = {
        "open",
        "new_or_maturity_deferred",
        "planned",
        "in_progress",
        "not_observed",
        "remediated",
        "risk_accepted",
        "false_positive",
        "not_applicable",
    }
    normalized_status = new_status.strip().lower()
    if normalized_status not in allowed or not reason.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid status or reason."
        )
    finding = db.get(AssetFinding, finding_id, with_for_update=True)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    previous = finding.status
    finding.status = normalized_status
    history = FindingStatusHistory(
        finding_id=finding.id,
        changed_by_id=principal.user.id,
        previous_status=previous,
        new_status=normalized_status,
        reason=reason.strip(),
    )
    db.add(history)
    record_audit(
        db,
        event_type="finding.status_changed",
        actor_user_id=principal.user.id,
        entity_type="finding",
        entity_id=finding.id,
        request_id=getattr(request.state, "request_id", None),
        client_ip=request_client_ip(request),
        details={"previous_status": previous, "new_status": normalized_status, "reason": reason.strip()},
    )
    db.commit()
    return {"id": str(finding.id), "status": finding.status}
