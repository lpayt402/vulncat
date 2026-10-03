from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from vulnbatch.api.deps import Principal, get_current_principal
from vulnbatch.db.models import Asset, AssetFinding, IdentityReviewItem, ImportRun
from vulnbatch.db.session import get_db
from vulnbatch.queries.service import OPEN_BACKLOG_STATUSES

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("")
def dashboard(
    _: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    total_assets = int(
        db.scalar(select(func.count(Asset.id)).where(Asset.active.is_(True), Asset.merged_into_id.is_(None)))
        or 0
    )
    active_findings = AssetFinding.status.in_(OPEN_BACKLOG_STATUSES)
    severity_rows = db.execute(
        select(AssetFinding.severity, func.count(AssetFinding.id))
        .where(active_findings)
        .group_by(AssetFinding.severity)
    ).all()
    severity_counts = {severity: int(count) for severity, count in severity_rows}
    assets_medium = int(
        db.scalar(
            select(func.count(distinct(AssetFinding.asset_id))).where(
                active_findings, AssetFinding.severity == "medium"
            )
        )
        or 0
    )
    assets_low = int(
        db.scalar(
            select(func.count(distinct(AssetFinding.asset_id))).where(
                active_findings, AssetFinding.severity == "low"
            )
        )
        or 0
    )
    maturity_rows = db.execute(
        select(AssetFinding.maturity_status, func.count(AssetFinding.id))
        .where(active_findings)
        .group_by(AssetFinding.maturity_status)
    ).all()
    maturity_counts = {(state or "unknown"): int(count) for state, count in maturity_rows}
    sla_rows = db.execute(
        select(AssetFinding.sla_status, func.count(AssetFinding.id))
        .where(active_findings)
        .group_by(AssetFinding.sla_status)
    ).all()
    sla_counts = {(state or "unknown"): int(count) for state, count in sla_rows}
    by_team = [
        {"name": name or "Unassigned", "count": int(count)}
        for name, count in db.execute(
            select(Asset.administrative_team, func.count(AssetFinding.id))
            .join(AssetFinding, AssetFinding.asset_id == Asset.id)
            .where(active_findings)
            .group_by(Asset.administrative_team)
            .order_by(func.count(AssetFinding.id).desc())
            .limit(12)
        )
    ]
    by_maintenance_group = [
        {"name": name or "Unassigned", "count": int(count)}
        for name, count in db.execute(
            select(Asset.maintenance_group, func.count(AssetFinding.id))
            .join(AssetFinding, AssetFinding.asset_id == Asset.id)
            .where(active_findings)
            .group_by(Asset.maintenance_group)
            .order_by(func.count(AssetFinding.id).desc())
            .limit(12)
        )
    ]
    unresolved = int(
        db.scalar(
            select(func.count(IdentityReviewItem.id)).where(
                IdentityReviewItem.status.in_(("open", "deferred"))
            )
        )
        or 0
    )
    recent_import_items = list(
        db.scalars(select(ImportRun).order_by(ImportRun.requested_at.desc()).limit(10))
    )
    recent_imports = [
        {
            "id": str(item.id),
            "status": item.status,
            "source_type": item.source_type,
            "requested_at": item.requested_at,
            "completed_at": item.completed_at,
            "included_records": item.included_records,
            "skipped_records": item.skipped_records,
            "ambiguous_assets": item.ambiguous_assets,
            "warning_count": len(item.parse_warnings) + len(item.mapping_warnings),
        }
        for item in recent_import_items
    ]
    warning_total = sum(len(item.parse_warnings) + len(item.mapping_warnings) for item in recent_import_items)
    return {
        "total_tracked_assets": total_assets,
        "assets_with_open_medium": assets_medium,
        "assets_with_open_low": assets_low,
        "open_findings_by_severity": severity_counts,
        "maturity": maturity_counts,
        "sla": sla_counts,
        "overdue_findings": sla_counts.get("overdue", 0),
        "findings_by_administrative_team": by_team,
        "findings_by_maintenance_group": by_maintenance_group,
        "recent_imports": recent_imports,
        "unresolved_identity_review_items": unresolved,
        "data_quality_warnings": warning_total,
    }
