from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import tempfile
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import xlsxwriter  # type: ignore[import-untyped]
from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnbatch.audit.service import record_audit
from vulnbatch.core.config import get_settings
from vulnbatch.core.security import utcnow
from vulnbatch.db.models import (
    ExportAssetSnapshot,
    ExportFindingSnapshot,
    ExportJob,
    Job,
)
from vulnbatch.jobs.service import heartbeat

HOST_COLUMNS = [
    ("canonical_hostname", "Canonical hostname"),
    ("current_ip_addresses", "Current IP addresses"),
    ("system_owner", "Owner"),
    ("administrative_team", "Team"),
    ("environment", "Environment"),
    ("operating_system", "Operating system"),
    ("open_medium_count", "Medium count"),
    ("open_low_count", "Low count"),
    ("mature_backlog_count", "Mature count"),
    ("new_deferred_count", "New or deferred count"),
    ("overdue_count", "Overdue count"),
    ("oldest_open_finding", "Oldest First Found"),
    ("last_scan_observed_at", "Last observed"),
    ("maintenance_group", "Maintenance group"),
    ("tags", "Tags"),
]

FINDING_COLUMNS = [
    ("canonical_hostname", "Canonical hostname"),
    ("current_ip_address", "Current IP address"),
    ("known_aliases", "Known aliases"),
    ("owner", "Owner"),
    ("team", "Team"),
    ("environment", "Environment"),
    ("operating_system", "Operating system"),
    ("plugin_id", "Plugin ID"),
    ("plugin_name", "Plugin name"),
    ("plugin_family", "Plugin family"),
    ("severity", "Severity"),
    ("cves", "CVEs"),
    ("port", "Port"),
    ("protocol", "Protocol"),
    ("service", "Service"),
    ("synopsis", "Synopsis"),
    ("solution", "Solution"),
    ("plugin_output", "Plugin output"),
    ("first_found", "First Found"),
    ("last_found", "Last Found"),
    ("vulnerability_maturity_date", "Vulnerability Maturity Date"),
    ("maturity_date_source", "Maturity-date source"),
    ("vulnerability_age_days", "Vulnerability Age (days)"),
    ("maturity_status", "Maturity status"),
    ("sla_due_date", "SLA due date"),
    ("sla_status", "SLA status"),
    ("days_overdue", "Days overdue"),
    ("finding_status", "Finding status"),
    ("source_scan", "Source scan"),
    ("source_import", "Source import"),
]


def formula_safe(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value)
    if not isinstance(value, str):
        return value
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r", "\n"):
        return f"'{value}"
    return value


def _metadata(export: ExportJob) -> dict[str, Any]:
    query_json = export.normalized_query_json or {}
    return {
        "Export ID": str(export.id),
        "Generated timestamp": utcnow().isoformat(),
        "Data-as-of timestamp": export.data_as_of.isoformat(),
        "Requesting user ID": str(export.requested_by_id),
        "Scope mode": export.scope_mode,
        "Saved view": export.saved_view_name or "",
        "Saved view revision": export.saved_view_revision or "",
        "Human-readable query summary": query_json.get("human_summary", "Explicit asset selection"),
        "Normalized query JSON": json.dumps(
            export.normalized_query_json, sort_keys=True, separators=(",", ":")
        ),
        "Finding-scope summary": json.dumps(export.finding_scope_json, sort_keys=True, separators=(",", ":")),
        "Matched host count": export.matched_host_count,
        "Matched finding count": export.matched_finding_count,
        "Application version": export.app_version,
        "Source-import cutoff": export.source_import_cutoff.isoformat()
        if export.source_import_cutoff
        else "",
    }


def _asset_rows(db: Session, export_id: Any) -> Iterable[dict[str, Any]]:
    for snapshot in db.scalars(
        select(ExportAssetSnapshot)
        .where(ExportAssetSnapshot.export_id == export_id)
        .order_by(ExportAssetSnapshot.snapshot_order)
    ):
        yield snapshot.snapshot_json


def _finding_rows(db: Session, export_id: Any) -> Iterable[dict[str, Any]]:
    for snapshot in db.scalars(
        select(ExportFindingSnapshot)
        .where(ExportFindingSnapshot.export_id == export_id)
        .order_by(ExportFindingSnapshot.snapshot_order)
    ):
        yield snapshot.snapshot_json


def _write_worksheet(
    worksheet: Any,
    columns: list[tuple[str, str]],
    rows: Iterable[dict[str, Any]],
    header_format: Any,
) -> None:
    worksheet.freeze_panes(1, 0)
    worksheet.autofilter(0, 0, 0, len(columns) - 1)
    for column_index, (_, label) in enumerate(columns):
        worksheet.write(0, column_index, label, header_format)
        worksheet.set_column(column_index, column_index, min(max(len(label) + 2, 14), 42))
    for row_index, row in enumerate(rows, start=1):
        for column_index, (key, _) in enumerate(columns):
            worksheet.write(row_index, column_index, formula_safe(row.get(key)))


def _generate_xlsx(db: Session, export: ExportJob, path: Path) -> None:
    workbook = xlsxwriter.Workbook(
        path,
        {
            "constant_memory": True,
            "strings_to_formulas": False,
            "strings_to_urls": False,
        },
    )
    header = workbook.add_format({"bold": True, "bg_color": "#17324D", "font_color": "#FFFFFF", "border": 1})
    try:
        _write_worksheet(
            workbook.add_worksheet("Host Summary"),
            HOST_COLUMNS,
            _asset_rows(db, export.id),
            header,
        )
        _write_worksheet(
            workbook.add_worksheet("Finding Detail"),
            FINDING_COLUMNS,
            _finding_rows(db, export.id),
            header,
        )
        metadata_sheet = workbook.add_worksheet("Export Metadata")
        metadata_sheet.set_column(0, 0, 32)
        metadata_sheet.set_column(1, 1, 100)
        for row_index, (key, value) in enumerate(_metadata(export).items()):
            metadata_sheet.write(row_index, 0, key, header)
            metadata_sheet.write(row_index, 1, formula_safe(value))
    finally:
        workbook.close()


def _write_csv_file(
    path: Path,
    columns: list[tuple[str, str]],
    rows: Iterable[dict[str, Any]],
) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([label for _, label in columns])
        for row in rows:
            writer.writerow([formula_safe(row.get(key)) for key, _ in columns])


def _generate_csv_bundle(db: Session, export: ExportJob, path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="vulnerability-workbench-csv-") as temp_dir:
        temp = Path(temp_dir)
        host_path = temp / "host_summary.csv"
        finding_path = temp / "finding_detail.csv"
        metadata_path = temp / "export_metadata.json"
        _write_csv_file(host_path, HOST_COLUMNS, _asset_rows(db, export.id))
        _write_csv_file(finding_path, FINDING_COLUMNS, _finding_rows(db, export.id))
        metadata_path.write_text(json.dumps(_metadata(export), indent=2, default=str), encoding="utf-8")
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            archive.write(host_path, host_path.name)
            archive.write(finding_path, finding_path.name)
            archive.write(metadata_path, metadata_path.name)


def _html_table(columns: list[tuple[str, str]], rows: Iterable[dict[str, Any]]) -> str:
    parts = ["<table><thead><tr>"]
    parts.extend(f"<th>{html.escape(label)}</th>" for _, label in columns)
    parts.append("</tr></thead><tbody>")
    for row in rows:
        parts.append("<tr>")
        for key, _ in columns:
            value = formula_safe(row.get(key))
            parts.append(f"<td>{html.escape(str(value))}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table>")
    return "".join(parts)


def _generate_html(db: Session, export: ExportJob, path: Path) -> None:
    metadata = _metadata(export)
    metadata_rows = "".join(
        f"<dt>{html.escape(str(key))}</dt><dd>{html.escape(str(value))}</dd>"
        for key, value in metadata.items()
    )
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulncat maintenance-window report {html.escape(str(export.id))}</title>
<style>
body{{font:13px/1.45 system-ui,sans-serif;color:#17202a;margin:24px}}
h1,h2{{color:#17324d}} table{{border-collapse:collapse;width:100%;margin:16px 0 32px}}
th,td{{border:1px solid #ccd4dc;padding:6px;vertical-align:top;text-align:left}}
th{{background:#17324d;color:white;position:sticky;top:0}} tr:nth-child(even){{background:#f5f7f9}}
dl{{display:grid;grid-template-columns:220px 1fr;gap:4px 12px}}dt{{font-weight:700}}
@media print{{body{{margin:8mm}}th{{position:static}}}}
</style>
</head>
<body>
<h1>Vulncat maintenance-window report</h1>
<h2>Export metadata</h2><dl>{metadata_rows}</dl>
<h2>Host Summary</h2>{_html_table(HOST_COLUMNS, _asset_rows(db, export.id))}
<h2>Finding Detail</h2>{_html_table(FINDING_COLUMNS, _finding_rows(db, export.id))}
</body></html>"""
    path.write_text(document, encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def process_export_job(db: Session, job: Job) -> None:
    settings = get_settings()
    export_id = job.payload.get("export_id")
    if not export_id:
        raise ValueError("Export job payload is missing export_id.")
    export = db.get(ExportJob, export_id, with_for_update=True)
    if export is None:
        raise ValueError("Export record not found.")
    if export.status == "completed" and export.output_path and Path(export.output_path).exists():
        return

    export.status = "running"
    export.started_at = export.started_at or utcnow()
    export.progress = 5
    heartbeat(db, job, 5)
    db.flush()

    settings.report_dir.mkdir(parents=True, exist_ok=True)
    extension = {"xlsx": "xlsx", "csv": "zip", "html": "html"}[export.output_format]
    final_path = settings.report_dir / f"vulncat-export-{export.id}.{extension}"
    temporary_path = settings.report_dir / f".{export.id}.{extension}.tmp"
    if temporary_path.exists():
        temporary_path.unlink()

    try:
        if export.output_format == "xlsx":
            _generate_xlsx(db, export, temporary_path)
        elif export.output_format == "csv":
            _generate_csv_bundle(db, export, temporary_path)
        elif export.output_format == "html":
            _generate_html(db, export, temporary_path)
        else:
            raise ValueError(f"Unsupported export format: {export.output_format}")
        heartbeat(db, job, 90)
        os.replace(temporary_path, final_path)
        export.output_path = str(final_path)
        export.output_sha256 = _sha256(final_path)
        export.output_byte_size = final_path.stat().st_size
        export.status = "completed"
        export.progress = 100
        export.completed_at = utcnow()
        record_audit(
            db,
            event_type="export.completed",
            actor_user_id=export.requested_by_id,
            entity_type="export",
            entity_id=export.id,
            details={
                "scope_mode": export.scope_mode,
                "matched_host_count": export.matched_host_count,
                "matched_finding_count": export.matched_finding_count,
                "output_format": export.output_format,
                "output_sha256": export.output_sha256,
                "output_byte_size": export.output_byte_size,
            },
        )
    except Exception as exc:
        if temporary_path.exists():
            temporary_path.unlink()
        export.status = "failed"
        export.failed_at = utcnow()
        export.failure_reason = str(exc)[:8000]
        record_audit(
            db,
            event_type="export.failed",
            actor_user_id=export.requested_by_id,
            entity_type="export",
            entity_id=export.id,
            outcome="failed",
            details={"failure_reason": export.failure_reason},
        )
        raise
