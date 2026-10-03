from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vulnbatch import __version__
from vulnbatch.core.config import get_settings
from vulnbatch.core.security import utcnow
from vulnbatch.db.models import (
    Asset,
    AssetFinding,
    ExportAssetSnapshot,
    ExportFindingSnapshot,
    ExportJob,
    FindingObservation,
    ImportRun,
    SavedView,
    SourceFile,
    VulnerabilityDefinition,
)
from vulnbatch.jobs.service import enqueue_job
from vulnbatch.queries.service import (
    finding_scope_conditions,
    host_row_select,
    human_query_summary,
    resolve_asset_ids,
)
from vulnbatch.schemas.query import ExportCreateRequest, ExportResponse, HostQueryV1, HostSummary
from vulnbatch.settings.service import effective_setting


def export_response(export: ExportJob) -> ExportResponse:
    return ExportResponse(
        id=export.id,
        scope_mode=export.scope_mode,
        output_format=export.output_format,
        status=export.status,
        progress=export.progress,
        matched_host_count=export.matched_host_count,
        matched_finding_count=export.matched_finding_count,
        data_as_of=export.data_as_of,
        requested_at=export.requested_at,
        started_at=export.started_at,
        completed_at=export.completed_at,
        failed_at=export.failed_at,
        expires_at=export.expires_at,
        failure_reason=export.failure_reason,
        output_sha256=export.output_sha256,
        output_byte_size=export.output_byte_size,
        download_ready=export.status == "completed" and bool(export.output_path),
    )


def _host_summary_from_row(row: Any) -> HostSummary:
    asset: Asset = row[0]
    current_ips = sorted(
        {
            identifier.normalized_value
            for identifier in asset.identifiers
            if identifier.active
            and not identifier.shared_or_non_identifying
            and identifier.identifier_type in ("ipv4", "ipv6")
        }
    )
    aliases = sorted(
        {
            identifier.normalized_value
            for identifier in asset.identifiers
            if identifier.identifier_type in ("fqdn", "short_hostname", "user_alias", "netbios")
            and identifier.normalized_value != asset.canonical_hostname
        }
    )
    return HostSummary(
        id=asset.id,
        canonical_hostname=asset.canonical_hostname,
        current_ip_addresses=current_ips,
        known_aliases=aliases,
        operating_system=asset.operating_system,
        system_owner=asset.system_owner,
        administrative_team=asset.administrative_team,
        technical_owner=asset.technical_owner,
        environment=asset.environment,
        data_center=asset.data_center,
        business_service=asset.business_service,
        server_role=asset.server_role,
        maintenance_group=asset.maintenance_group,
        patch_group=asset.patch_group,
        tags=sorted(tag.name for tag in asset.tags),
        open_medium_count=int(row[1] or 0),
        open_low_count=int(row[2] or 0),
        mature_backlog_count=int(row[3] or 0),
        new_deferred_count=int(row[4] or 0),
        overdue_count=int(row[5] or 0),
        oldest_open_finding=row[6],
        last_scan_observed_at=asset.last_scan_observed_at,
        identity_confidence=asset.identity_confidence,
        unresolved_identity=bool(row[7]),
    )


def _chunks(values: list[uuid.UUID], size: int = 1000) -> list[list[uuid.UUID]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def _resolve_scope(
    db: Session,
    request: ExportCreateRequest,
    requesting_user_id: uuid.UUID,
) -> tuple[
    list[uuid.UUID],
    dict[str, Any] | None,
    dict[str, Any] | None,
    str,
    SavedView | None,
]:
    scope = request.asset_scope
    if scope.mode == "selected_assets":
        requested_ids = list(dict.fromkeys(scope.asset_ids))
        existing_ids = list(
            db.scalars(
                select(Asset.id)
                .where(
                    Asset.id.in_(requested_ids),
                    Asset.active.is_(True),
                    Asset.merged_into_id.is_(None),
                )
                .order_by(func.lower(func.coalesce(Asset.canonical_hostname, "")), Asset.id)
            )
        )
        if len(existing_ids) != len(requested_ids):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="One or more selected canonical assets do not exist or are inactive.",
            )
        return existing_ids, None, None, f"{len(existing_ids)} explicitly selected canonical assets", None

    if scope.mode == "host_query":
        normalized, asset_ids = resolve_asset_ids(db, scope.query)
        return (
            asset_ids,
            scope.query.model_dump(mode="json", exclude_none=True),
            normalized.model_dump(mode="json", exclude_none=True),
            human_query_summary(normalized),
            None,
        )

    view = db.get(SavedView, scope.saved_view_id)
    if view is None or not (view.shared or view.owner_user_id == requesting_user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Saved view not found.")
    query = HostQueryV1.model_validate(view.query_json)
    normalized, asset_ids = resolve_asset_ids(db, query)
    return (
        asset_ids,
        view.query_json,
        normalized.model_dump(mode="json", exclude_none=True),
        human_query_summary(normalized),
        view,
    )


def _source_import_cutoff(db: Session) -> datetime | None:
    return db.scalar(select(func.max(ImportRun.completed_at)).where(ImportRun.status == "completed"))


def _date_age_days(value: date | None, data_as_of: datetime) -> int | None:
    if value is None:
        return None
    return (data_as_of.date() - value).days


def _days_overdue(value: date | None, data_as_of: datetime) -> int:
    if value is None or value >= data_as_of.date():
        return 0
    return (data_as_of.date() - value).days


def create_export_snapshot(
    db: Session,
    *,
    request: ExportCreateRequest,
    requesting_user_id: uuid.UUID,
) -> ExportJob:
    settings = get_settings()
    data_as_of = utcnow()
    asset_ids, original_query, normalized_query, query_summary, view = _resolve_scope(
        db, request, requesting_user_id
    )
    if not asset_ids:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="The asset scope resolves to zero canonical assets. No export was created.",
        )

    finding_count_statement = (
        select(func.count(AssetFinding.id))
        .select_from(AssetFinding)
        .join(Asset, Asset.id == AssetFinding.asset_id)
        .join(
            VulnerabilityDefinition,
            VulnerabilityDefinition.id == AssetFinding.vulnerability_definition_id,
        )
        .where(
            AssetFinding.asset_id.in_(asset_ids),
            *finding_scope_conditions(request.finding_scope),
        )
    )
    finding_count = int(db.scalar(finding_count_statement) or 0)
    large_export_threshold = int(
        effective_setting(
            db,
            "large_export_finding_threshold",
            settings.large_export_finding_threshold,
        )
    )
    if finding_count >= large_export_threshold and not request.confirm_large_export:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "large_export_confirmation_required",
                "matched_host_count": len(asset_ids),
                "matched_finding_count": finding_count,
                "threshold": large_export_threshold,
            },
        )

    job = enqueue_job(
        db,
        job_type="export",
        payload={},
        max_attempts=3,
    )
    export = ExportJob(
        requested_by_id=requesting_user_id,
        job_id=job.id,
        scope_mode=request.asset_scope.mode,
        saved_view_id=view.id if view else None,
        saved_view_revision=view.revision if view else None,
        saved_view_name=view.name if view else None,
        original_query_json=original_query,
        normalized_query_json=normalized_query,
        query_schema_version=1,
        finding_scope_json=request.finding_scope.model_dump(mode="json", exclude_none=True),
        output_format=request.format,
        matched_host_count=len(asset_ids),
        matched_finding_count=finding_count,
        data_as_of=data_as_of,
        source_import_cutoff=_source_import_cutoff(db),
        status="queued",
        app_version=__version__,
    )
    db.add(export)
    db.flush()
    job.payload = {"export_id": str(export.id)}
    job.unique_key = f"export:{export.id}"

    host_snapshot_by_asset: dict[uuid.UUID, dict[str, Any]] = {}
    snapshot_order = 0
    for chunk in _chunks(asset_ids):
        host_rows = db.execute(
            host_row_select(HostQueryV1())
            .where(Asset.id.in_(chunk))
            .order_by(func.lower(func.coalesce(Asset.canonical_hostname, "")), Asset.id)
        ).all()
        for row in host_rows:
            host_summary = _host_summary_from_row(row)
            snapshot = host_summary.model_dump(mode="json")
            host_snapshot_by_asset[host_summary.id] = snapshot
            db.add(
                ExportAssetSnapshot(
                    export_id=export.id,
                    asset_id=host_summary.id,
                    snapshot_order=snapshot_order,
                    snapshot_json=snapshot,
                )
            )
            snapshot_order += 1
        db.flush()

    latest_scan_name = (
        select(FindingObservation.scan_name)
        .where(FindingObservation.finding_id == AssetFinding.id)
        .order_by(FindingObservation.observed_at.desc(), FindingObservation.id.desc())
        .limit(1)
        .correlate(AssetFinding)
        .scalar_subquery()
    )
    finding_order = 0
    for chunk in _chunks(asset_ids):
        finding_rows = db.execute(
            select(
                AssetFinding,
                Asset,
                VulnerabilityDefinition,
                SourceFile.original_filename,
                latest_scan_name.label("source_scan"),
            )
            .join(Asset, Asset.id == AssetFinding.asset_id)
            .join(
                VulnerabilityDefinition,
                VulnerabilityDefinition.id == AssetFinding.vulnerability_definition_id,
            )
            .outerjoin(ImportRun, ImportRun.id == AssetFinding.last_source_import_id)
            .outerjoin(SourceFile, SourceFile.id == ImportRun.source_file_id)
            .where(
                AssetFinding.asset_id.in_(chunk),
                *finding_scope_conditions(request.finding_scope),
            )
            .order_by(
                func.lower(func.coalesce(Asset.canonical_hostname, "")),
                AssetFinding.severity.desc(),
                AssetFinding.plugin_id,
                AssetFinding.port,
                AssetFinding.protocol,
                AssetFinding.id,
            )
            .execution_options(stream_results=True, yield_per=500)
        )
        for finding, asset, definition, source_filename, source_scan in finding_rows:
            host_snapshot = host_snapshot_by_asset[asset.id]
            finding_snapshot = {
                "finding_id": str(finding.id),
                "asset_id": str(asset.id),
                "canonical_hostname": asset.canonical_hostname,
                "current_ip_address": ", ".join(host_snapshot["current_ip_addresses"]),
                "known_aliases": ", ".join(host_snapshot["known_aliases"]),
                "owner": asset.system_owner,
                "team": asset.administrative_team,
                "environment": asset.environment,
                "operating_system": asset.operating_system,
                "plugin_id": finding.plugin_id,
                "plugin_name": definition.plugin_name,
                "plugin_family": definition.plugin_family,
                "severity": finding.severity,
                "cves": ", ".join(definition.cves),
                "port": finding.port,
                "protocol": finding.protocol,
                "service": finding.service,
                "synopsis": definition.synopsis,
                "solution": finding.current_solution or definition.solution,
                "plugin_output": finding.current_evidence,
                "first_found": finding.first_found_at.isoformat() if finding.first_found_at else None,
                "last_found": finding.last_found_at.isoformat() if finding.last_found_at else None,
                "vulnerability_maturity_date": (
                    finding.maturity_date.isoformat() if finding.maturity_date else None
                ),
                "maturity_date_source": finding.maturity_date_source,
                "vulnerability_age_days": _date_age_days(finding.maturity_date, data_as_of),
                "maturity_status": finding.maturity_status,
                "sla_due_date": finding.sla_due_date.isoformat() if finding.sla_due_date else None,
                "sla_status": finding.sla_status,
                "days_overdue": _days_overdue(finding.sla_due_date, data_as_of),
                "finding_status": finding.status,
                "source_scan": source_scan,
                "source_import": source_filename
                or (str(finding.last_source_import_id) if finding.last_source_import_id else None),
            }
            db.add(
                ExportFindingSnapshot(
                    export_id=export.id,
                    finding_id=finding.id,
                    asset_id=asset.id,
                    snapshot_order=finding_order,
                    snapshot_json=finding_snapshot,
                )
            )
            finding_order += 1
            if finding_order % 500 == 0:
                db.flush()

    export.matched_finding_count = finding_order
    if normalized_query is not None:
        normalized_query["human_summary"] = query_summary
        export.normalized_query_json = normalized_query
    export_retention_days = int(
        effective_setting(
            db,
            "export_retention_days",
            settings.export_retention_days,
        )
    )
    export.expires_at = data_as_of + timedelta(days=export_retention_days)
    db.flush()
    return export
