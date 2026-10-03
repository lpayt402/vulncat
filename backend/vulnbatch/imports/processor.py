from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, selectinload

from vulnbatch.audit.service import record_audit
from vulnbatch.core.config import get_settings
from vulnbatch.core.security import utcnow
from vulnbatch.db.models import (
    Asset,
    AssetFinding,
    AssetIdentifier,
    AssetIdentifierObservation,
    FindingObservation,
    FindingStatusHistory,
    IdentityReviewItem,
    ImportRecord,
    ImportRun,
    Job,
    SourceFile,
    Tag,
    VulnerabilityDefinition,
)
from vulnbatch.findings.calculations import assess_maturity, assess_sla, select_maturity_date
from vulnbatch.findings.identity import normalize_finding_key
from vulnbatch.findings.lifecycle import FindingState, FindingStatus, apply_observation, reconcile_absence
from vulnbatch.identity.resolver import (
    AssetCandidate,
    IdentifierAssociation,
    IdentityResolver,
)
from vulnbatch.imports.generic_csv import parse_generic_csv
from vulnbatch.imports.models import NormalizedImportRecord
from vulnbatch.imports.nessus import parse_nessus_xml
from vulnbatch.imports.tenable import parse_tenable_csv, parse_tenable_json
from vulnbatch.jobs.service import heartbeat
from vulnbatch.reconciliation.storage import advance_revision, lock_mutations
from vulnbatch.settings.service import effective_setting

IDENTIFIER_FIELDS = (
    ("tenable_asset_uuid", "tenable_asset_uuid"),
    ("agent_uuid", "agent_uuid"),
    ("nessus_host_id", "nessus_host_id"),
    ("hardware_uuid", "hardware_uuid"),
    ("mac_address", "mac_address"),
    ("fqdn", "fqdn"),
    ("short_hostname", "short_hostname"),
    ("ipv4_address", "ipv4"),
    ("ipv6_address", "ipv6"),
)


@dataclass(frozen=True, slots=True)
class FindingPolicy:
    allow_finding_date_maturity_fallback: bool
    maturity_gate_days: int
    medium_sla_days: int
    low_sla_days: int


def _finding_policy(db: Session) -> FindingPolicy:
    settings = get_settings()
    return FindingPolicy(
        allow_finding_date_maturity_fallback=bool(
            effective_setting(
                db,
                "allow_finding_date_maturity_fallback",
                settings.allow_finding_date_maturity_fallback,
            )
        ),
        maturity_gate_days=int(effective_setting(db, "maturity_gate_days", settings.maturity_gate_days)),
        medium_sla_days=int(effective_setting(db, "medium_sla_days", settings.medium_sla_days)),
        low_sla_days=int(effective_setting(db, "low_sla_days", settings.low_sla_days)),
    )


@contextmanager
def _parsed_records(
    db: Session,
    source: SourceFile,
    import_run: ImportRun,
) -> Iterator[Iterator[NormalizedImportRecord]]:
    path = Path(source.storage_path)
    settings = get_settings()
    tracked_severities = tuple(effective_setting(db, "tracked_severities", settings.tracked_severities))
    if import_run.source_type == "nessus_xml":
        with path.open("rb") as stream:
            yield parse_nessus_xml(stream, tracked_severities=tracked_severities)
        return
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        if import_run.source_type == "tenable_csv":
            yield parse_tenable_csv(stream, tracked_severities=tracked_severities)
        elif import_run.source_type == "tenable_json":
            yield parse_tenable_json(stream, tracked_severities=tracked_severities)
        elif import_run.source_type == "generic_csv":
            if import_run.mapping is None:
                raise ValueError("Generic CSV import is missing its approved mapping.")
            yield parse_generic_csv(
                stream,
                mapping=import_run.mapping,
                tracked_severities=tracked_severities,
            )
        else:
            raise ValueError(f"Unsupported source type: {import_run.source_type}")


def _incoming_identifiers(record: NormalizedImportRecord) -> dict[str, object]:
    return {
        identifier_type: value
        for field_name, identifier_type in IDENTIFIER_FIELDS
        if (value := getattr(record.asset, field_name)) is not None
    }


def _identity_fingerprint(incoming: dict[str, object]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((identifier_type, str(value)) for identifier_type, value in incoming.items()))


def _finding_cache_key(
    asset_id: uuid.UUID,
    record: NormalizedImportRecord,
) -> tuple[uuid.UUID, str, str, int, str]:
    normalized = normalize_finding_key(
        asset_id=asset_id,
        scanner_source=record.asset.scanner_source,
        plugin_id=record.finding.plugin_id,
        port=record.finding.port,
        protocol=record.finding.protocol,
    )
    return (
        asset_id,
        normalized.scanner_source,
        normalized.plugin_id,
        normalized.port,
        normalized.protocol,
    )


def _candidate_assets(
    db: Session,
    incoming: dict[str, object],
) -> tuple[AssetCandidate, ...]:
    predicates = [
        and_(
            AssetIdentifier.identifier_type == identifier_type,
            AssetIdentifier.normalized_value == value,
        )
        for identifier_type, value in incoming.items()
    ]
    if not predicates:
        return ()
    assets = list(
        db.scalars(
            select(Asset)
            .join(AssetIdentifier, AssetIdentifier.asset_id == Asset.id)
            .where(Asset.active.is_(True), or_(*predicates))
            .distinct()
            .options(selectinload(Asset.identifiers))
        )
    )
    return tuple(
        AssetCandidate(
            asset_id=str(asset.id),
            operating_system=asset.operating_system,
            active=asset.active,
            identifiers=tuple(
                IdentifierAssociation(
                    identifier_type=identifier.identifier_type,
                    normalized_value=identifier.normalized_value,
                    original_value=identifier.original_value,
                    first_observed_at=identifier.first_observed_at,
                    last_observed_at=identifier.last_observed_at,
                    active=identifier.active,
                    manually_verified=identifier.manually_verified,
                    manual_override=identifier.manual_override,
                    shared_or_non_identifying=identifier.shared_or_non_identifying,
                )
                for identifier in asset.identifiers
            ),
        )
        for asset in assets
    )


def _create_asset(record: NormalizedImportRecord, confidence: float) -> Asset:
    canonical = (
        record.asset.fqdn
        or record.asset.short_hostname
        or record.asset.ipv4_address
        or record.asset.ipv6_address
    )
    return Asset(
        id=uuid.uuid4(),
        canonical_hostname=canonical,
        operating_system=record.asset.operating_system,
        identity_confidence=confidence,
        last_scan_observed_at=(record.asset.last_observed or record.finding.scan_time or datetime.now(UTC)),
    )


def _upsert_identifiers(
    db: Session,
    *,
    asset: Asset,
    record: NormalizedImportRecord,
    import_run: ImportRun,
    import_record: ImportRecord,
    matching_rule: str,
    confidence: float,
) -> None:
    observed_at = record.asset.last_observed or record.finding.scan_time or datetime.now(UTC)
    first_observed = record.asset.first_observed or observed_at
    existing = {
        (identifier.identifier_type, identifier.normalized_value): identifier
        for identifier in asset.identifiers
    }
    created_identifier = False
    for field_name, identifier_type in IDENTIFIER_FIELDS:
        value = getattr(record.asset, field_name)
        if value is None:
            continue
        identifier = existing.get((identifier_type, value))
        if identifier is None:
            identifier = AssetIdentifier(
                id=uuid.uuid4(),
                asset_id=asset.id,
                identifier_type=identifier_type,
                normalized_value=value,
                original_value=value,
                first_observed_at=first_observed,
                last_observed_at=observed_at,
                source_import_id=import_run.id,
                confidence=confidence,
                active=True,
            )
            asset.identifiers.append(identifier)
            db.add(identifier)
            existing[(identifier_type, value)] = identifier
            created_identifier = True
        else:
            identifier.first_observed_at = min(identifier.first_observed_at, first_observed)
            identifier.last_observed_at = max(identifier.last_observed_at, observed_at)
            identifier.source_import_id = import_run.id
            identifier.confidence = max(identifier.confidence, confidence)
            identifier.active = True
        db.add(
            AssetIdentifierObservation(
                identifier_id=identifier.id,
                import_id=import_run.id,
                import_record_id=import_record.id,
                observed_at=observed_at,
                matching_rule=matching_rule,
                confidence=confidence,
                evidence={
                    "source_file_id": str(import_run.source_file_id),
                    "record_number": record.record_number,
                    "raw_record": record.raw_record,
                },
            )
        )
    if created_identifier:
        # Keep newly associated identifiers visible to a later, non-identical
        # record in the same import without flushing once per identifier.
        db.flush()


def _apply_asset_metadata(db: Session, asset: Asset, record: NormalizedImportRecord) -> None:
    if not asset.canonical_name_pinned:
        if record.asset.fqdn:
            asset.canonical_hostname = record.asset.fqdn
        elif asset.canonical_hostname is None and record.asset.short_hostname:
            asset.canonical_hostname = record.asset.short_hostname
    if record.asset.operating_system:
        asset.operating_system = record.asset.operating_system
    observed_at = record.asset.last_observed or record.finding.scan_time
    if observed_at and (asset.last_scan_observed_at is None or observed_at > asset.last_scan_observed_at):
        asset.last_scan_observed_at = observed_at
    existing_tags = {tag.name.casefold(): tag for tag in asset.tags}
    for tag_name in record.asset.asset_tags:
        key = tag_name.casefold()
        tag = existing_tags.get(key) or db.scalar(select(Tag).where(Tag.name == tag_name))
        if tag is None:
            tag = Tag(name=tag_name)
            db.add(tag)
            db.flush()
        if tag not in asset.tags:
            asset.tags.append(tag)
        existing_tags[key] = tag


def _upsert_definition(
    db: Session,
    record: NormalizedImportRecord,
    cached: VulnerabilityDefinition | None = None,
) -> VulnerabilityDefinition:
    finding = record.finding
    if finding.plugin_id is None:
        raise ValueError("Included finding is missing Plugin ID.")
    definition = cached
    if definition is None:
        definition = db.scalar(
            select(VulnerabilityDefinition).where(
                VulnerabilityDefinition.scanner_source == record.asset.scanner_source,
                VulnerabilityDefinition.plugin_id == finding.plugin_id,
            )
        )
    if definition is None:
        definition = VulnerabilityDefinition(
            id=uuid.uuid4(),
            scanner_source=record.asset.scanner_source,
            plugin_id=finding.plugin_id,
            cves=[],
        )
        db.add(definition)
        # AssetFinding references the definition by UUID rather than ORM
        # relationship, so persist a newly created definition before batching
        # dependent findings.
        db.flush()
    for field_name in (
        "plugin_name",
        "plugin_family",
        "synopsis",
        "description",
        "solution",
        "plugin_publication_date",
        "plugin_modification_date",
        "cve_publication_date",
        "vendor_advisory_date",
        "exploit_available",
        "exploited_by_malware",
        "known_exploited",
    ):
        value = getattr(finding, field_name)
        if value is not None:
            setattr(definition, field_name, value)
    definition.cves = sorted(set(definition.cves).union(finding.cves))
    return definition


def _current_state(finding: AssetFinding) -> FindingState:
    return FindingState(
        status=FindingStatus(finding.status),
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
        first_found_at=finding.first_found_at,
        last_found_at=finding.last_found_at,
        times_observed=finding.times_observed,
        reopened_count=finding.reopened_count,
    )


def _maturity_and_sla(
    definition: VulnerabilityDefinition,
    record: NormalizedImportRecord,
    *,
    as_of: datetime,
    policy: FindingPolicy,
    first_found: datetime | None,
) -> tuple[Any, Any]:
    selection = select_maturity_date(
        cve_publication_date=definition.cve_publication_date,
        vendor_advisory_date=definition.vendor_advisory_date,
        plugin_publication_date=definition.plugin_publication_date,
        plugin_modification_date=definition.plugin_modification_date,
        first_found=first_found,
        allow_finding_date_fallback=policy.allow_finding_date_maturity_fallback,
    )
    maturity = assess_maturity(
        selection,
        as_of=as_of,
        gate_days=policy.maturity_gate_days,
        emergency_indicator=bool(
            definition.known_exploited or definition.exploited_by_malware or definition.exploit_available
        ),
    )
    sla = assess_sla(
        first_found=first_found,
        severity=record.finding.severity,
        as_of=as_of,
        medium_days=policy.medium_sla_days,
        low_days=policy.low_sla_days,
    )
    return maturity, sla


def _upsert_finding(
    db: Session,
    *,
    asset: Asset,
    definition: VulnerabilityDefinition,
    record: NormalizedImportRecord,
    import_run: ImportRun,
    import_record: ImportRecord,
    policy: FindingPolicy | None = None,
    assume_missing: bool = False,
) -> tuple[AssetFinding, bool]:
    normalized_key = normalize_finding_key(
        asset_id=asset.id,
        scanner_source=record.asset.scanner_source,
        plugin_id=record.finding.plugin_id,
        port=record.finding.port,
        protocol=record.finding.protocol,
    )
    finding = None
    if not assume_missing:
        finding = db.scalar(
            select(AssetFinding).where(
                AssetFinding.asset_id == asset.id,
                AssetFinding.scanner_source == normalized_key.scanner_source,
                AssetFinding.plugin_id == normalized_key.plugin_id,
                AssetFinding.port == normalized_key.port,
                AssetFinding.protocol == normalized_key.protocol,
            )
        )
    observed_at = record.finding.scan_time or record.finding.last_found or utcnow()
    first_found_candidates = [
        value
        for value in (
            finding.first_found_at if finding is not None else None,
            record.finding.first_found,
        )
        if value is not None
    ]
    effective_first_found = min(first_found_candidates) if first_found_candidates else None
    maturity, sla = _maturity_and_sla(
        definition,
        record,
        as_of=observed_at,
        policy=policy or _finding_policy(db),
        first_found=effective_first_found,
    )
    initial_status = (
        FindingStatus.NEW_OR_MATURITY_DEFERRED
        if maturity.maturity_status == "new_or_maturity_deferred"
        else FindingStatus.OPEN
    )
    created = finding is None
    lifecycle = apply_observation(
        _current_state(finding) if finding else None,
        observed_at=observed_at,
        first_found_at=record.finding.first_found,
        last_found_at=record.finding.last_found,
        initial_status=initial_status,
    )
    if finding is None:
        finding = AssetFinding(
            id=uuid.uuid4(),
            asset_id=asset.id,
            vulnerability_definition_id=definition.id,
            scanner_source=normalized_key.scanner_source,
            plugin_id=normalized_key.plugin_id,
            port=normalized_key.port,
            protocol=normalized_key.protocol,
            service=record.finding.service,
            severity=record.finding.severity or "unknown",
            status=lifecycle.state.status.value,
            first_seen_at=lifecycle.state.first_seen_at,
            last_seen_at=lifecycle.state.last_seen_at,
            first_found_at=lifecycle.state.first_found_at,
            last_found_at=lifecycle.state.last_found_at,
            times_observed=lifecycle.state.times_observed,
            reopened_count=lifecycle.state.reopened_count,
            current_evidence=record.finding.plugin_output,
            current_solution=record.finding.solution,
        )
        db.add(finding)
    else:
        finding.status = lifecycle.state.status.value
        finding.first_seen_at = lifecycle.state.first_seen_at
        finding.last_seen_at = lifecycle.state.last_seen_at
        finding.first_found_at = lifecycle.state.first_found_at
        finding.last_found_at = lifecycle.state.last_found_at
        finding.times_observed = lifecycle.state.times_observed
        finding.reopened_count = lifecycle.state.reopened_count
        finding.service = record.finding.service or finding.service
        finding.severity = record.finding.severity or finding.severity
        finding.current_evidence = record.finding.plugin_output or finding.current_evidence
        finding.current_solution = record.finding.solution or finding.current_solution
    finding.risk_factor = record.finding.risk_factor
    finding.cvss_v2 = record.finding.cvss_v2_score
    finding.cvss_v3 = record.finding.cvss_v3_score
    finding.vpr = record.finding.vpr_score
    finding.epss = record.finding.epss_score
    finding.maturity_date = maturity.maturity_date
    finding.maturity_date_source = maturity.maturity_date_source
    finding.maturity_gate_date = maturity.maturity_gate_date
    finding.maturity_status = (
        "deferred" if maturity.maturity_status == "new_or_maturity_deferred" else maturity.maturity_status
    )
    finding.sla_due_date = sla.sla_due_date
    finding.sla_status = {
        "within_sla": "not_due",
        "due_today": "approaching",
    }.get(sla.sla_status, sla.sla_status)
    finding.last_source_import_id = import_run.id

    db.add(
        FindingObservation(
            finding_id=finding.id,
            import_id=import_run.id,
            import_record_id=import_record.id,
            observed_at=observed_at,
            scan_name=record.finding.scan_name,
            scan_time=record.finding.scan_time,
            evidence=record.finding.plugin_output,
            severity=record.finding.severity or "unknown",
            solution=record.finding.solution,
            raw_metadata=record.finding.model_dump(mode="json"),
        )
    )
    if created or lifecycle.reopened:
        db.add(
            FindingStatusHistory(
                finding_id=finding.id,
                source_import_id=import_run.id,
                previous_status=lifecycle.previous_status.value if lifecycle.previous_status else None,
                new_status=finding.status,
                reason=lifecycle.reason,
                metadata_json={"reopened": lifecycle.reopened},
            )
        )
    return finding, created


def _copy_prior_force_record(
    db: Session,
    import_run: ImportRun,
    import_record: ImportRecord,
) -> bool:
    if not import_run.force_reprocess:
        return False
    prior = db.execute(
        select(ImportRecord.asset_id, ImportRecord.finding_id)
        .join(ImportRun, ImportRun.id == ImportRecord.import_id)
        .where(
            ImportRun.source_file_id == import_run.source_file_id,
            ImportRun.id != import_run.id,
            ImportRun.status == "completed",
            ImportRecord.content_hash == import_record.content_hash,
        )
        .order_by(ImportRun.completed_at.desc())
        .limit(1)
    ).one_or_none()
    if prior is None:
        return False
    import_record.asset_id, import_record.finding_id = prior
    import_record.processed_at = utcnow()
    return True


def process_import_job(db: Session, job: Job) -> None:
    import_id = job.payload.get("import_id")
    if not import_id:
        raise ValueError("Import job payload is missing import_id.")
    mutation_revision = lock_mutations(db)
    import_run = db.get(ImportRun, uuid.UUID(str(import_id)), with_for_update=True)
    if import_run is None:
        raise ValueError("Import record not found.")
    source = db.get(SourceFile, import_run.source_file_id)
    if source is None:
        raise ValueError("Immutable source file metadata is missing.")
    import_run.status = "running"
    import_run.started_at = import_run.started_at or utcnow()
    heartbeat(db, job, 1)
    db.flush()

    settings = get_settings()
    resolver = IdentityResolver(
        staleness_days=int(
            effective_setting(
                db,
                "ip_association_staleness_days",
                settings.ip_association_staleness_days,
            )
        ),
        auto_match_threshold=float(
            effective_setting(
                db,
                "identity_auto_match_threshold",
                settings.identity_auto_match_threshold,
            )
        ),
    )
    finding_policy = _finding_policy(db)
    observed_asset_ids: set[uuid.UUID] = set()
    observed_finding_ids: set[uuid.UUID] = set()
    observed_scanner_sources: set[str] = set()
    unique_assets: set[uuid.UUID] = set()
    new_asset_ids: set[uuid.UUID] = set()
    identity_cache: dict[tuple[tuple[str, str], ...], Asset] = {}
    definition_cache: dict[tuple[str, str], VulnerabilityDefinition] = {}
    seen_finding_keys: set[tuple[uuid.UUID, str, str, int, str]] = set()

    with _parsed_records(db, source, import_run) as records:
        for record in records:
            import_run.total_records += 1
            if record.finding.severity:
                import_run.severity_counts = {
                    **import_run.severity_counts,
                    record.finding.severity: import_run.severity_counts.get(record.finding.severity, 0) + 1,
                }
            if record.included_in_inventory:
                import_run.included_records += 1
            else:
                import_run.skipped_records += 1
            if record.warnings and len(import_run.parse_warnings) < 1000:
                import_run.parse_warnings = [
                    *import_run.parse_warnings,
                    *[
                        {
                            "record_number": record.record_number,
                            **warning.model_dump(mode="json"),
                        }
                        for warning in record.warnings
                    ],
                ][:1000]

            import_record = ImportRecord(
                id=uuid.uuid4(),
                import_id=import_run.id,
                record_number=record.record_number,
                content_hash=record.content_hash,
                raw_record=record.raw_record,
                normalized_record=record.model_dump(mode="json"),
                warnings=[warning.model_dump(mode="json") for warning in record.warnings],
            )
            db.add(import_record)
            # Import records are referenced by identifier and finding
            # observations through explicit UUID foreign keys. Persist each
            # parent record before creating those dependent rows; relying on a
            # later bulk flush can let PostgreSQL insert children first.
            db.flush()
            if _copy_prior_force_record(db, import_run, import_record):
                if import_record.asset_id:
                    unique_assets.add(import_record.asset_id)
                if import_run.total_records % 500 == 0:
                    heartbeat(db, job, min(90, 5 + import_run.total_records // 1000))
                    db.flush()
                continue

            incoming = _incoming_identifiers(record)
            fingerprint = _identity_fingerprint(incoming)
            asset = identity_cache.get(fingerprint) if fingerprint else None
            if asset is not None:
                matching_rule = "same_import_identity_fingerprint"
                confidence = asset.identity_confidence or 0.0
                import_run.matched_assets += 1
            else:
                candidates = _candidate_assets(db, incoming)
                observed_at = record.asset.last_observed or record.finding.scan_time or utcnow()
                decision = resolver.resolve(
                    incoming,
                    candidates,
                    observed_at=observed_at,
                    operating_system=record.asset.operating_system,
                )
                if decision.action == "review":
                    # The review item references this normalized record directly.
                    # Persist the record first because the relationship is stored
                    # as an explicit UUID rather than an ORM relationship.
                    db.flush()
                    db.add(
                        IdentityReviewItem(
                            source_import_id=import_run.id,
                            import_record_id=import_record.id,
                            incoming_identifiers=[
                                {
                                    "identifier_type": item.identifier_type,
                                    "normalized_value": item.normalized_value,
                                    "original_value": item.original_value,
                                }
                                for item in decision.incoming_identifiers
                            ],
                            candidate_asset_ids=list(decision.candidate_asset_ids),
                            conflicting_evidence=list(decision.conflicting_evidence),
                            matching_rule=decision.matching_rule,
                            explanation=decision.explanation,
                            confidence=decision.confidence,
                            first_observed_at=record.asset.first_observed,
                            last_observed_at=observed_at,
                        )
                    )
                    import_run.ambiguous_assets += 1
                    import_record.processed_at = utcnow()
                    if import_run.total_records % 500 == 0:
                        heartbeat(db, job, min(90, 5 + import_run.total_records // 1000))
                        db.flush()
                    continue

                matching_rule = decision.matching_rule
                confidence = decision.confidence
                if decision.action == "match" and decision.asset_id is not None:
                    asset = db.get(Asset, uuid.UUID(decision.asset_id))
                    if asset is None:
                        raise ValueError("Identity resolver selected a missing asset.")
                    import_run.matched_assets += 1
                else:
                    asset = _create_asset(record, confidence)
                    db.add(asset)
                    db.flush()
                    new_asset_ids.add(asset.id)
                    import_run.new_assets += 1
                if fingerprint:
                    identity_cache[fingerprint] = asset

            _apply_asset_metadata(db, asset, record)
            _upsert_identifiers(
                db,
                asset=asset,
                record=record,
                import_run=import_run,
                import_record=import_record,
                matching_rule=matching_rule,
                confidence=confidence,
            )
            asset.identity_confidence = max(asset.identity_confidence or 0.0, confidence)
            import_record.asset_id = asset.id
            unique_assets.add(asset.id)
            observed_asset_ids.add(asset.id)
            observed_scanner_sources.add(record.asset.scanner_source)

            if record.included_in_inventory:
                plugin_id = record.finding.plugin_id
                if plugin_id is None:
                    raise ValueError("Included finding is missing Plugin ID.")
                definition_key = (record.asset.scanner_source, plugin_id)
                definition = _upsert_definition(
                    db,
                    record,
                    cached=definition_cache.get(definition_key),
                )
                definition_cache[definition_key] = definition
                finding_key = _finding_cache_key(asset.id, record)
                finding, created = _upsert_finding(
                    db,
                    asset=asset,
                    definition=definition,
                    record=record,
                    import_run=import_run,
                    import_record=import_record,
                    policy=finding_policy,
                    assume_missing=(asset.id in new_asset_ids and finding_key not in seen_finding_keys),
                )
                seen_finding_keys.add(finding_key)
                import_record.finding_id = finding.id
                observed_finding_ids.add(finding.id)
                if created:
                    import_run.new_findings += 1
                else:
                    import_run.updated_findings += 1
            import_record.processed_at = utcnow()
            if import_run.total_records % 500 == 0:
                heartbeat(db, job, min(90, 5 + import_run.total_records // 1000))
                db.flush()

    db.flush()
    if import_run.complete_comparable_scope and observed_asset_ids:
        statement = select(AssetFinding).where(
            AssetFinding.asset_id.in_(observed_asset_ids),
            AssetFinding.scanner_source.in_(observed_scanner_sources),
        )
        if observed_finding_ids:
            statement = statement.where(AssetFinding.id.not_in(observed_finding_ids))
        for finding in db.scalars(statement):
            result = reconcile_absence(
                _current_state(finding),
                complete_comparable_scope=True,
                asset_was_in_scope=True,
                finding_was_observed=False,
            )
            if result.changed:
                finding.status = result.state.status.value
                db.add(
                    FindingStatusHistory(
                        finding_id=finding.id,
                        source_import_id=import_run.id,
                        previous_status=result.previous_status.value if result.previous_status else None,
                        new_status=finding.status,
                        reason=result.reason,
                        metadata_json={"authoritative_import_id": str(import_run.id)},
                    )
                )

    advance_revision(db, mutation_revision)
    import_run.unique_assets = len(unique_assets)
    import_run.status = "completed"
    import_run.completed_at = utcnow()
    heartbeat(db, job, 98)
    record_audit(
        db,
        event_type="import.completed",
        actor_user_id=import_run.importing_user_id,
        entity_type="import",
        entity_id=import_run.id,
        details={
            "source_file_id": str(import_run.source_file_id),
            "source_type": import_run.source_type,
            "total_records": import_run.total_records,
            "included_records": import_run.included_records,
            "skipped_records": import_run.skipped_records,
            "unique_assets": import_run.unique_assets,
            "new_assets": import_run.new_assets,
            "matched_assets": import_run.matched_assets,
            "ambiguous_assets": import_run.ambiguous_assets,
            "new_findings": import_run.new_findings,
            "updated_findings": import_run.updated_findings,
        },
    )
