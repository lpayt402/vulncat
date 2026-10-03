from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, exists, select
from sqlalchemy.orm import Session

from vulnbatch.audit.service import record_audit
from vulnbatch.core.config import get_settings
from vulnbatch.core.security import utcnow
from vulnbatch.db.models import (
    AuditEvent,
    ExportJob,
    IdentityReviewItem,
    ImportRecord,
    ImportRun,
    SourceFile,
)
from vulnbatch.settings.service import effective_setting


def _safe_unlink(path_value: str | None, root: Path) -> bool:
    if not path_value:
        return False
    path = Path(path_value).resolve()
    resolved_root = root.resolve()
    if not path.is_relative_to(resolved_root) or not path.is_file():
        return False
    path.unlink()
    return True


def run_retention_cleanup(db: Session) -> dict[str, int]:
    settings = get_settings()
    now = utcnow()
    result = {
        "expired_reports_removed": 0,
        "expired_uploads_removed": 0,
        "import_records_redacted": 0,
        "audit_events_removed": 0,
    }

    expired_exports = list(
        db.scalars(
            select(ExportJob).where(
                ExportJob.expires_at.is_not(None),
                ExportJob.expires_at <= now,
                ExportJob.output_path.is_not(None),
            )
        )
    )
    for export in expired_exports:
        if _safe_unlink(export.output_path, settings.report_dir):
            result["expired_reports_removed"] += 1
        export.output_path = None

    upload_days = effective_setting(
        db,
        "upload_retention_days",
        settings.upload_retention_days,
    )
    if upload_days is not None:
        upload_cutoff = now - timedelta(days=int(upload_days))
        for source in db.scalars(select(SourceFile).where(SourceFile.uploaded_at < upload_cutoff)):
            if _safe_unlink(source.storage_path, settings.upload_dir):
                result["expired_uploads_removed"] += 1

    evidence_days = effective_setting(
        db,
        "import_evidence_retention_days",
        settings.import_evidence_retention_days,
    )
    if evidence_days is not None:
        evidence_cutoff = now - timedelta(days=int(evidence_days))
        open_review_exists = exists(
            select(IdentityReviewItem.id).where(
                IdentityReviewItem.import_record_id == ImportRecord.id,
                IdentityReviewItem.status.in_(("open", "deferred")),
            )
        )
        records = list(
            db.scalars(
                select(ImportRecord)
                .join(ImportRun, ImportRun.id == ImportRecord.import_id)
                .where(
                    ImportRun.completed_at.is_not(None),
                    ImportRun.completed_at < evidence_cutoff,
                    ~open_review_exists,
                )
                .limit(10_000)
            )
        )
        for record in records:
            if record.raw_record or record.normalized_record:
                record.raw_record = {}
                record.normalized_record = {}
                result["import_records_redacted"] += 1

    audit_days = effective_setting(db, "audit_retention_days", settings.audit_retention_days)
    if audit_days is not None:
        audit_cutoff = now - timedelta(days=int(audit_days))
        expired_audit_ids = list(
            db.scalars(select(AuditEvent.id).where(AuditEvent.occurred_at < audit_cutoff).limit(100_000))
        )
        if expired_audit_ids:
            db.execute(delete(AuditEvent).where(AuditEvent.id.in_(expired_audit_ids)))
            result["audit_events_removed"] = len(expired_audit_ids)

    if any(result.values()):
        record_audit(
            db,
            event_type="retention.cleanup_completed",
            entity_type="application",
            details=result,
        )
    return result
