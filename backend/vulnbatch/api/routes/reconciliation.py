from __future__ import annotations

import csv
import json
from io import StringIO
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import TypeAdapter
from sqlalchemy.orm import Session

from vulnbatch.api.deps import Principal, require_admin_csrf
from vulnbatch.core.security import utcnow
from vulnbatch.db.session import get_db
from vulnbatch.reconciliation.adapters import FIELDS, _at
from vulnbatch.reconciliation.models import Preview, SourceOptions
from vulnbatch.reconciliation.storage import ImportDocument, ReconciliationConflict, preview_bundle

router = APIRouter(prefix="/api/v1/reconciliation", tags=["offline reconciliation"])
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_TOTAL_BYTES = 30 * 1024 * 1024
MAX_FILES = 8
NOTICE = (
    "Transient preview only. Exports vary by source/version; configure columns explicitly. "
    "Canonical field presets describe synthetic examples, not verified vendor exports."
)


def _read(upload: UploadFile) -> bytes:
    upload.file.seek(0)
    data = upload.file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, "Each preview file must be 10 MiB or smaller")
    if not data:
        raise HTTPException(422, "File is empty")
    return data


def _decode(data: bytes) -> str:
    text = data.decode("utf-8-sig", errors="strict")
    if "\x00" in text:
        raise ValueError("Text contains NUL bytes; save the export as UTF-8")
    return text


def _flatten(row: dict[str, Any], prefix: str = "", depth: int = 0) -> list[str]:
    if depth > 8:
        return []
    fields = []
    for name, value in row.items():
        path = f"{prefix}.{name}" if prefix else str(name)
        if isinstance(value, dict):
            fields.extend(_flatten(value, path, depth + 1))
        else:
            fields.append(path)
    return fields


@router.post("/columns")
def columns(
    _: Principal = Depends(require_admin_csrf),
    upload: UploadFile = File(),
    format: Literal["csv", "json", "ndjson"] = Form(),
    records_path: str | None = Form(default=None, max_length=256),
) -> dict[str, Any]:
    try:
        if records_path is not None:
            if format != "json":
                raise ValueError("records_path applies only to JSON; omit it for other formats")
            if not records_path.strip():
                raise ValueError("records_path must be nonempty when provided; omit it for a JSON array")
        text = _decode(_read(upload))
        if format == "csv":
            headers = next(csv.reader(StringIO(text)), [])
            if len(headers) != len(set(headers)):
                raise ValueError("Duplicate CSV headers are ambiguous")
        else:
            if format == "ndjson":
                first = next((line for line in text.splitlines() if line.strip()), "")
                data = json.loads(first)
            else:
                data = json.loads(text)
                if records_path:
                    if not isinstance(data, dict):
                        raise ValueError("Records path requires an object envelope")
                    data = _at(data, records_path)
                    if not isinstance(data, list):
                        raise ValueError("Records path must select a JSON array")
                elif isinstance(data, dict):
                    records_path = next(
                        (
                            key
                            for key in ("resources", "results", "items", "data")
                            if isinstance(data.get(key), list)
                        ),
                        None,
                    )
                    if records_path:
                        data = data[records_path]
                if isinstance(data, list):
                    data = next((row for row in data if isinstance(row, dict)), {})
            if not isinstance(data, dict):
                raise ValueError("A sample JSON object is required")
            headers = _flatten(data)
        if len(headers) > 256:
            raise ValueError("Preview supports up to 256 columns")
        return {"columns": headers, "fields": FIELDS, "notice": NOTICE, "records_path": records_path}
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HTTPException(422, str(exc)[:500]) from exc


@router.post("/preview", response_model=Preview)
def preview(
    principal: Principal = Depends(require_admin_csrf),
    db: Session = Depends(get_db),
    uploads: list[UploadFile] = File(),
    options_json: str = Form(),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> Preview:
    if len(uploads) > MAX_FILES:
        raise HTTPException(413, "Preview supports at most eight files")
    try:
        options = TypeAdapter(list[SourceOptions]).validate_json(options_json)
        if len(options) != len(uploads):
            raise ValueError("Each file requires exactly one source configuration")
        data = [_read(upload) for upload in uploads]
        if sum(map(len, data)) > MAX_TOTAL_BYTES:
            raise HTTPException(413, "Combined preview files must be 30 MiB or smaller")
        documents = [
            ImportDocument(filename=upload.filename or "offline-export", content=content, options=config)
            for upload, content, config in zip(uploads, data, options, strict=True)
        ]
        return preview_bundle(
            db, documents, now=utcnow(), offset=offset, limit=limit, actor_id=principal.user.id
        )
    except ReconciliationConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except (ValueError, UnicodeError, RecursionError, csv.Error) as exc:
        raise HTTPException(422, str(exc)[:500]) from exc
