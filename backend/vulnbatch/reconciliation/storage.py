from __future__ import annotations

import base64
import hashlib
import hmac
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from io import BytesIO, StringIO
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from vulnbatch.audit.service import record_audit
from vulnbatch.core.config import get_settings
from vulnbatch.db.base import Base
from vulnbatch.db.models import Asset, AssetIdentifier
from vulnbatch.db.reconciliation import (
    AssignmentVersion,
    CoverageObservation,
    CurrentAssignment,
    ObservationLocator,
    ObservationNativeID,
    ReconciliationBatch,
    ReconciliationDecision,
    ReconciliationState,
    SourceInstance,
    SourceObservation,
    VulnerabilityOccurrence,
)
from vulnbatch.reconciliation.adapters import digest, parse_rows
from vulnbatch.reconciliation.conflicts import ConflictKeys
from vulnbatch.reconciliation.matching import EvidenceIndex
from vulnbatch.reconciliation.models import (
    AssetEvidence,
    Candidate,
    Observation,
    ParsedRow,
    Preview,
    SourceOptions,
)
from vulnbatch.reconciliation.nessus import parse_nessus_observations
from vulnbatch.reconciliation.preview import resolve_bundle, summarize


class ReconciliationConflict(ValueError):
    """A replay, stale state or unsafe identity transition must return HTTP 409."""


@dataclass(frozen=True)
class ImportDocument:
    filename: str
    content: bytes
    options: SourceOptions


class PreviewContext(BaseModel):
    revision: int = Field(ge=0)
    evaluated_at: datetime
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _preview_signature(encoded: str) -> str:
    return hmac.new(
        get_settings().secret_key.encode(),
        ("reconciliation-preview:" + encoded).encode(),
        hashlib.sha256,
    ).hexdigest()


def _preview_token(payload_hash: str, captured: int, now: datetime) -> str:
    context = PreviewContext(revision=captured, evaluated_at=now, payload_sha256=payload_hash)
    encoded = base64.urlsafe_b64encode(context.model_dump_json().encode()).decode().rstrip("=")
    return encoded + "." + _preview_signature(encoded)


def _verify_preview(token: str, payload_hash: str, now: datetime) -> PreviewContext:
    try:
        if not token.isascii() or len(token) > 2048:
            raise ValueError("Invalid preview token")
        encoded, signature = token.split(".")
        if not hmac.compare_digest(signature, _preview_signature(encoded)):
            raise ValueError("Invalid signature")
        context = PreviewContext.model_validate_json(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        if context.payload_sha256 != payload_hash or context.evaluated_at.tzinfo is None:
            raise ValueError("Files, mapping or actor changed")
        if not now - timedelta(minutes=30) <= context.evaluated_at <= now:
            raise ValueError("Preview expired")
        return context
    except (ValueError, UnicodeError) as exc:
        raise ReconciliationConflict(
            "Preview expired or its files, mapping or actor changed; preview again"
        ) from exc


def bundle_files(documents: list[ImportDocument]) -> list[dict[str, Any]]:
    if (
        not 1 <= len(documents) <= 8
        or any(not doc.content or len(doc.content) > 10 * 1024 * 1024 for doc in documents)
        or sum(len(doc.content) for doc in documents) > 30 * 1024 * 1024
    ):
        raise ValueError("Import supports 1-8 nonempty files, 10 MiB each and 30 MiB combined")
    if any("\x00" in doc.filename for doc in documents):
        raise ValueError("Import filenames cannot contain NUL characters")
    return [
        {
            "filename": doc.filename.replace("\\", "/").rsplit("/", 1)[-1][:512],
            "sha256": hashlib.sha256(doc.content).hexdigest(),
            "options": doc.options.model_dump(mode="json"),
        }
        for doc in documents
    ]


def revision(db: Session) -> int:
    return db.scalar(select(ReconciliationState.revision).where(ReconciliationState.id == 1)) or 0


def lock_mutations(db: Session) -> int:
    # A real database UPDATE serializes writers on PostgreSQL and SQLite. The caller owns
    # commit/rollback; locks and every evidence/audit write share that one transaction.
    dialect = db.get_bind().dialect.name
    if dialect not in {"postgresql", "sqlite"}:
        raise ValueError("Persistent reconciliation requires PostgreSQL (SQLite is for synthetic tests)")
    constructor = pg_insert if dialect == "postgresql" else sqlite_insert
    db.execute(constructor(ReconciliationState).values(id=1, revision=0).on_conflict_do_nothing())
    value = db.scalar(
        update(ReconciliationState)
        .where(ReconciliationState.id == 1)
        .values(revision=ReconciliationState.revision)
        .returning(ReconciliationState.revision)
        .execution_options(synchronize_session=False)
    )
    if value is None:
        raise ReconciliationConflict("Reconciliation mutation lock is unavailable")
    return value


def advance_revision(db: Session, previous: int) -> int:
    db.execute(
        update(ReconciliationState)
        .where(ReconciliationState.id == 1)
        .values(revision=previous + 1)
        .execution_options(synchronize_session=False)
    )
    return previous + 1


def bulk_insert(db: Session, model: type[Base], rows: list[dict[str, Any]]) -> None:
    for offset in range(0, len(rows), 500):
        db.execute(insert(model), rows[offset : offset + 500])


def matching_index(db: Session) -> tuple[EvidenceIndex, ConflictKeys]:
    index, conflicts = EvidenceIndex([]), ConflictKeys()
    # Legacy identifiers have no reliable vendor instance namespace. They suggest review
    # through weak aliases only; durable source evidence establishes new native matches.
    legacy = (
        select(
            AssetIdentifier.asset_id,
            AssetIdentifier.identifier_type,
            AssetIdentifier.normalized_value,
            AssetIdentifier.last_observed_at,
        )
        .join(Asset, Asset.id == AssetIdentifier.asset_id)
        .where(
            Asset.active.is_(True),
            Asset.merged_into_id.is_(None),
            AssetIdentifier.active.is_(True),
            AssetIdentifier.valid_to.is_(None),
            AssetIdentifier.shared_or_non_identifying.is_(False),
        )
        .execution_options(yield_per=1000)
    )
    for asset_id, kind, value, time in db.execute(legacy):
        field = {"fqdn": "fqdn", "short_hostname": "short_hostname", "mac_address": "mac_address"}.get(kind)
        evidence = (
            {field: value} if field else {"ip_addresses": [value]} if kind in {"ipv4", "ipv6"} else None
        )
        if evidence:
            index.add(
                Candidate(
                    asset_id=str(asset_id), evidence=AssetEvidence.model_validate(evidence), observed_at=time
                )
            )
    history = (
        select(SourceObservation.normalized, CurrentAssignment.asset_id, Asset.active, Asset.merged_into_id)
        .join(CurrentAssignment, CurrentAssignment.observation_id == SourceObservation.id)
        .outerjoin(Asset, Asset.id == CurrentAssignment.asset_id)
        .where(CurrentAssignment.review_status != "rejected")
        .execution_options(yield_per=1000)
    )
    for normalized, asset_id, active, merged_into in db.execute(history):
        observation = Observation.model_validate(normalized)
        conflicts.include(observation)  # Open/deferred conflict evidence also blocks later imports.
        if asset_id and active and merged_into is None:
            time = (
                observation.observed_at if observation.provenance.time_meaning == "source_observed" else None
            )
            index.add(Candidate(asset_id=str(asset_id), evidence=observation.asset, observed_at=time))
    return index, conflicts


def _parsed(document: ImportDocument, now: datetime) -> Iterator[ParsedRow]:
    config = document.options.model_copy(update={"instance": document.options.instance.strip()})
    file_hash = hashlib.sha256(document.content).hexdigest()
    if config.format == "nessus_xml":
        yield from parse_nessus_observations(
            BytesIO(document.content), config, file_hash=file_hash, imported_at=now
        )
    else:
        text = document.content.decode("utf-8-sig", errors="strict")
        if "\x00" in text:
            raise ValueError("Text contains NUL bytes; save the export as UTF-8")
        yield from parse_rows(StringIO(text), config, file_hash=file_hash, imported_at=now)


def _replay(db: Session, request_key: str, payload_hash: str) -> dict[str, Any] | None:
    batch = db.scalar(select(ReconciliationBatch).where(ReconciliationBatch.request_key == request_key))
    if batch is None:
        return None
    if batch.payload_sha256 != payload_hash:
        raise ReconciliationConflict("Import request key was already used with another payload or actor")
    return {**batch.result, "replayed": True}


def stage_bundle(documents: list[ImportDocument], now: datetime) -> list[tuple[int, ParsedRow]]:
    staged: list[tuple[int, ParsedRow]] = []
    expanded_bytes = 0
    for file_number, document in enumerate(documents, 1):
        for parsed in _parsed(document, now):
            if len(staged) >= 100_000:
                raise ValueError("Import exceeds 100000 logical rows; split the export")
            if parsed.observation is not None:
                expanded_bytes += len(parsed.observation.model_dump_json().encode("utf-8"))
                if expanded_bytes > 64 * 1024 * 1024:
                    raise ValueError(
                        "Expanded evidence exceeds 64 MiB; split the export into smaller bundles"
                    )
            staged.append((file_number, parsed))
    return staged


def known_assignments(db: Session, fingerprints: list[str]) -> dict[str, dict[str, Any]]:
    known = {}
    for offset in range(0, len(fingerprints), 500):
        statement = (
            select(SourceObservation.fingerprint, CurrentAssignment)
            .join(CurrentAssignment, CurrentAssignment.observation_id == SourceObservation.id)
            .where(SourceObservation.fingerprint.in_(fingerprints[offset : offset + 500]))
            .execution_options(populate_existing=True)
        )
        for fingerprint, assignment in db.execute(statement):
            known[fingerprint] = {
                "observation_id": str(assignment.observation_id),
                "asset_id": str(assignment.asset_id) if assignment.asset_id else None,
                "version": assignment.version,
                "review_status": assignment.review_status,
                "rule": assignment.rule,
                "explanation": assignment.explanation,
                "confidence": assignment.confidence,
                "candidate_ids": assignment.candidate_ids,
            }
    return known


def preview_bundle(
    db: Session,
    documents: list[ImportDocument],
    *,
    now: datetime,
    offset: int = 0,
    limit: int = 50,
    actor_id: uuid.UUID,
) -> Preview:
    payload_hash = digest({"actor": str(actor_id), "files": bundle_files(documents)})
    captured = revision(db)
    staged = stage_bundle(documents, now)
    index, conflicts = matching_index(db)
    fingerprints = list({parsed.observation.fingerprint for _, parsed in staged if parsed.observation})
    known = known_assignments(db, fingerprints)
    result = summarize(
        (parsed for _, parsed in staged),
        index,
        now=now,
        offset=offset,
        limit=limit,
        conflicts=conflicts,
        known=known,
    )
    if revision(db) != captured:
        raise ReconciliationConflict("Evidence changed during preview; preview these files again")
    return result.model_copy(
        update={"revision": captured, "preview_token": _preview_token(payload_hash, captured, now)}
    )


def persist_bundle(
    db: Session,
    documents: list[ImportDocument],
    *,
    actor_id: uuid.UUID,
    request_key: str,
    now: datetime,
    expected_revision: int | None = None,
    preview_token: str | None = None,
) -> dict[str, Any]:
    if not request_key.strip() or len(request_key) > 128:
        raise ValueError("Import request_key must contain 1-128 characters")
    if "\x00" in request_key or any("\x00" in doc.filename for doc in documents):
        raise ValueError("Import request key and filenames cannot contain NUL characters")
    files = bundle_files(documents)
    payload_hash = digest({"actor": str(actor_id), "files": files})
    replay = _replay(db, request_key, payload_hash)
    if replay is not None:
        return replay
    matching_now = now
    if preview_token is not None:
        context = _verify_preview(preview_token, payload_hash, now)
        if expected_revision is not None and expected_revision != context.revision:
            raise ReconciliationConflict("Preview revision does not match its signed context; preview again")
        expected_revision, matching_now = context.revision, context.evaluated_at
    staged = stage_bundle(documents, now)
    previous = lock_mutations(db)
    replay = _replay(db, request_key, payload_hash)
    if replay is not None:
        return replay
    if expected_revision is not None and previous != expected_revision:
        raise ReconciliationConflict(
            "Evidence changed after preview; preview these files again before saving"
        )
    index, conflicts = matching_index(db)
    unique = {
        parsed.observation.fingerprint: parsed.observation for _, parsed in staged if parsed.observation
    }
    retained = known_assignments(db, list(unique))
    known = {fingerprint: uuid.UUID(item["observation_id"]) for fingerprint, item in retained.items()}
    instances = {(item.source, item.label): item.id for item in db.scalars(select(SourceInstance))}
    planned = resolve_bundle(
        unique,
        index,
        conflicts,
        now=matching_now,
        known=retained,
        create_id=lambda _: str(uuid.uuid4()),
    )
    buffers: list[list[dict[str, Any]]] = [[] for _ in range(9)]
    (
        instance_rows,
        asset_rows,
        observation_rows,
        native_rows,
        vulnerability_rows,
        coverage_rows,
        assignments,
        versions,
        locators,
    ) = buffers
    batch_id, decision_id = uuid.uuid4(), uuid.uuid4()
    assigned = reviewed = 0
    for plan in planned:
        observation = plan.observation
        fingerprint = observation.fingerprint
        if plan.current_assignment is not None:
            continue  # Replays never override analyst assignments, rejection or defer status.
        identity = (observation.provenance.source, observation.provenance.instance)
        if identity not in instances:
            instances[identity] = uuid.uuid4()
            instance_rows.append({"id": instances[identity], "source": identity[0], "label": identity[1]})
        instance_id, observation_id = instances[identity], uuid.uuid4()
        known[fingerprint] = observation_id
        decision = plan.decision
        asset_id = uuid.UUID(plan.asset_id) if plan.asset_id else None
        if decision.action == "create":
            asset_rows.append(
                {
                    "id": asset_id,
                    "canonical_hostname": observation.asset.fqdn or observation.asset.short_hostname,
                    "operating_system": observation.asset.operating_system,
                }
            )
        if asset_id:
            assigned += 1
        else:
            reviewed += 1
        snapshot = {
            "asset_id": asset_id,
            "version": 1,
            "review_status": "assigned" if asset_id else "open",
            "rule": decision.rule,
            "explanation": decision.explanation,
            "confidence": decision.confidence,
            "candidate_ids": list(decision.candidate_ids),
        }
        assignments.append({"observation_id": observation_id, **snapshot})
        versions.append(
            {
                "id": uuid.uuid4(),
                "observation_id": observation_id,
                "decision_id": decision_id,
                "occurred_at": now,
                **snapshot,
            }
        )
        observation_rows.append(
            {
                "id": observation_id,
                "fingerprint": fingerprint,
                "source_instance_id": instance_id,
                "kind": observation.kind,
                "observed_at": observation.observed_at,
                "first_observed_at": observation.first_observed_at,
                "imported_at": now,
                "parser_version": observation.provenance.parser_version,
                "normalized": observation.model_dump(mode="json"),
            }
        )
        native_rows.extend(
            {
                "id": uuid.uuid4(),
                "observation_id": observation_id,
                "source_instance_id": instance_id,
                "kind": native.kind,
                "value": native.value,
            }
            for native in observation.asset.native_ids
        )
        if observation.vulnerability:
            vuln = observation.vulnerability
            identity_key: object = [
                native.key for native in observation.asset.native_ids
            ] or observation.asset.model_dump(mode="json", exclude={"operating_system"})
            occurrence: list[object] = (
                [str(instance_id), "native", vuln.occurrence_id]
                if vuln.occurrence_id
                else [
                    str(instance_id),
                    "derived",
                    identity_key,
                    vuln.vulnerability_id,
                    vuln.package,
                    vuln.package_version,
                    vuln.port,
                    vuln.protocol,
                ]
            )
            vulnerability_rows.append(
                {
                    "observation_id": observation_id,
                    "occurrence_key": digest(occurrence),
                    "native_occurrence_id": vuln.occurrence_id,
                    "vulnerability_id": vuln.vulnerability_id,
                    "native_status": vuln.native_status,
                    "evidence": vuln.model_dump(mode="json"),
                }
            )
        if observation.coverage:
            coverage_rows.append(
                {
                    "observation_id": observation_id,
                    **observation.coverage.model_dump(exclude={"native_status"}),
                    "evidence": observation.coverage.model_dump(mode="json"),
                }
            )
    errors = [
        parsed.model_dump(mode="json", exclude_none=True)
        for _, parsed in staged
        if parsed.observation is None
    ]
    valid = len(staged) - len(errors)
    result: dict[str, Any] = {
        "id": str(batch_id),
        "revision": previous + 1,
        "total_rows": len(staged),
        "valid_rows": valid,
        "error_rows": len(errors),
        "duplicate_rows": valid - len(observation_rows),
        "new_observations": len(observation_rows),
        "assigned_rows": assigned,
        "review_rows": reviewed,
        "errors": errors[:50],
        "errors_truncated": len(errors) > 50,
        "candidate_checks": index.candidate_checks,
        "replayed": False,
        "persisted": True,
    }
    for file_number, parsed in staged:
        if parsed.observation:
            provenance = parsed.observation.provenance
            locators.append(
                {
                    "id": uuid.uuid4(),
                    "observation_id": known[parsed.observation.fingerprint],
                    "batch_id": batch_id,
                    "file_number": file_number,
                    "record_number": parsed.record_number,
                    "filename": files[file_number - 1]["filename"],
                    "file_sha256": provenance.file_sha256,
                    "mapping_sha256": provenance.mapping_sha256,
                    "imported_at": now,
                }
            )
    bulk_insert(db, SourceInstance, instance_rows)
    bulk_insert(
        db,
        ReconciliationBatch,
        [
            {
                "id": batch_id,
                "request_key": request_key,
                "payload_sha256": payload_hash,
                "actor_user_id": actor_id,
                "imported_at": now,
                "files": files,
                "result": result,
            }
        ],
    )
    bulk_insert(
        db,
        ReconciliationDecision,
        [
            {
                "id": decision_id,
                "request_key": "import:" + request_key,
                "payload_sha256": payload_hash,
                "action": "import",
                "actor_user_id": actor_id,
                "occurred_at": now,
                "reason": "Offline source evidence imported with conservative matching",
                "changes": [],
                "result": {
                    "id": str(decision_id),
                    "revision": previous + 1,
                    "action": "import",
                    "changed_rows": len(observation_rows),
                    "replayed": False,
                },
            }
        ],
    )
    inserts: list[tuple[type[Base], list[dict[str, Any]]]] = [
        (Asset, asset_rows),
        (SourceObservation, observation_rows),
        (ObservationNativeID, native_rows),
        (VulnerabilityOccurrence, vulnerability_rows),
        (CoverageObservation, coverage_rows),
        (CurrentAssignment, assignments),
        (AssignmentVersion, versions),
        (ObservationLocator, locators),
    ]
    for model, data in inserts:
        bulk_insert(db, model, data)
    advance_revision(db, previous)
    record_audit(
        db,
        event_type="reconciliation.imported",
        actor_user_id=actor_id,
        entity_type="reconciliation_batch",
        entity_id=batch_id,
        details={key: value for key, value in result.items() if key != "errors"},
    )
    db.flush()
    return result
