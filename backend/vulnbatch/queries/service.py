from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Iterable, Sequence
from datetime import UTC, date, datetime, time
from typing import Any

from sqlalchemy import String, cast, exists, func, literal, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql import ColumnElement, Select

from vulnbatch.db.models import (
    Asset,
    AssetFinding,
    AssetIdentifier,
    IdentityReviewItem,
    Tag,
    VulnerabilityDefinition,
    asset_tags,
)
from vulnbatch.schemas.query import (
    DateRange,
    FindingScopeV1,
    FloatRange,
    HostQueryV1,
    HostSummary,
    NumericRange,
)

OPEN_BACKLOG_STATUSES = ("open", "new_or_maturity_deferred", "planned", "in_progress")
IP_TYPES = ("ipv4", "ipv6")
ALIAS_TYPES = ("fqdn", "short_hostname", "user_alias", "netbios")
IDENTIFIER_TYPE_MAP = {
    "tenable_asset_uuids": ("tenable_asset_uuid",),
    "agent_uuids": ("agent_uuid",),
    "nessus_host_ids": ("nessus_host_id",),
    "hardware_uuids": ("hardware_uuid", "bios_uuid"),
    "mac_addresses": ("mac_address",),
}


def _clean_strings(values: Iterable[str], *, lower: bool = True) -> list[str]:
    cleaned: set[str] = set()
    for value in values:
        candidate = value.strip()
        if not candidate:
            continue
        cleaned.add(candidate.lower() if lower else candidate)
    return sorted(cleaned)


def _normalize_hostname(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _normalize_mac(value: str) -> str:
    compact = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(compact) != 12 or not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        raise ValueError(f"Invalid MAC address: {value}")
    return ":".join(compact[index : index + 2].lower() for index in range(0, 12, 2))


def normalize_host_query(query: HostQueryV1) -> HostQueryV1:
    updates: dict[str, Any] = {
        "q": query.q.strip() if query.q else None,
        "canonical_hostnames": sorted(
            {_normalize_hostname(value) for value in query.canonical_hostnames if value.strip()}
        ),
        "aliases": sorted({_normalize_hostname(value) for value in query.aliases if value.strip()}),
        "ip_addresses": sorted(
            {str(ipaddress.ip_address(value.strip())) for value in query.ip_addresses if value.strip()}
        ),
        "mac_addresses": sorted({_normalize_mac(value) for value in query.mac_addresses if value.strip()}),
        "ports": sorted(set(query.ports)),
        "sort": query.sort,
    }
    for field_name in (
        "tenable_asset_uuids",
        "agent_uuids",
        "nessus_host_ids",
        "hardware_uuids",
        "operating_systems",
        "system_owners",
        "administrative_teams",
        "technical_owners",
        "environments",
        "data_centers",
        "business_services",
        "server_roles",
        "maintenance_groups",
        "patch_groups",
        "plugin_ids",
        "plugin_families",
        "cves",
        "protocols",
    ):
        updates[field_name] = _clean_strings(getattr(query, field_name))
    if query.tags is not None:
        updates["tags"] = query.tags.model_copy(update={"values": _clean_strings(query.tags.values)})
    return query.model_copy(update=updates)


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _datetime_bound(value: date | datetime, *, end: bool) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value
    return datetime.combine(value, time.max if end else time.min, tzinfo=UTC)


def _apply_numeric_range(expression: Any, value_range: NumericRange | None) -> list[ColumnElement[bool]]:
    if value_range is None:
        return []
    conditions: list[ColumnElement[bool]] = []
    if value_range.minimum is not None:
        conditions.append(expression >= value_range.minimum)
    if value_range.maximum is not None:
        conditions.append(expression <= value_range.maximum)
    return conditions


def _apply_float_range(expression: Any, value_range: FloatRange | None) -> list[ColumnElement[bool]]:
    if value_range is None:
        return []
    conditions: list[ColumnElement[bool]] = []
    if value_range.minimum is not None:
        conditions.append(expression >= value_range.minimum)
    if value_range.maximum is not None:
        conditions.append(expression <= value_range.maximum)
    return conditions


def _identifier_exists(
    identifier_types: Sequence[str],
    values: Sequence[str] | None = None,
    *,
    active_only: bool | None = None,
) -> ColumnElement[bool]:
    predicates: list[ColumnElement[bool]] = [
        AssetIdentifier.asset_id == Asset.id,
        AssetIdentifier.identifier_type.in_(identifier_types),
    ]
    if values:
        predicates.append(AssetIdentifier.normalized_value.in_(values))
    if active_only is not None:
        predicates.append(AssetIdentifier.active.is_(active_only))
    return exists(select(literal(1)).where(*predicates))


def _finding_count(*predicates: ColumnElement[bool]) -> ColumnElement[int]:
    return (
        select(func.count(AssetFinding.id))
        .where(
            AssetFinding.asset_id == Asset.id,
            AssetFinding.status.in_(OPEN_BACKLOG_STATUSES),
            *predicates,
        )
        .correlate(Asset)
        .scalar_subquery()
    )


def _oldest_open() -> ColumnElement[datetime | None]:
    return (
        select(func.min(AssetFinding.first_found_at))
        .where(
            AssetFinding.asset_id == Asset.id,
            AssetFinding.status.in_(OPEN_BACKLOG_STATUSES),
        )
        .correlate(Asset)
        .scalar_subquery()
    )


def _unresolved_identity_exists() -> ColumnElement[bool]:
    candidate_contains_asset = cast(IdentityReviewItem.candidate_asset_ids, JSONB).op("@>")(
        func.jsonb_build_array(cast(Asset.id, String))
    )
    return exists(
        select(literal(1)).where(
            IdentityReviewItem.status.in_(("open", "deferred")),
            candidate_contains_asset,
        )
    )


def _host_conditions(query: HostQueryV1) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = [Asset.active.is_(True), Asset.merged_into_id.is_(None)]

    if query.q:
        pattern = f"%{_escape_like(query.q.lower())}%"
        conditions.append(
            or_(
                func.lower(func.coalesce(Asset.canonical_hostname, "")).like(pattern, escape="\\"),
                exists(
                    select(literal(1)).where(
                        AssetIdentifier.asset_id == Asset.id,
                        func.lower(AssetIdentifier.normalized_value).like(pattern, escape="\\"),
                    )
                ),
            )
        )
    if query.canonical_hostnames:
        conditions.append(func.lower(Asset.canonical_hostname).in_(query.canonical_hostnames))
    if query.aliases:
        conditions.append(_identifier_exists(ALIAS_TYPES, query.aliases))
    if query.ip_addresses:
        if query.ip_scope == "current":
            conditions.append(_identifier_exists(IP_TYPES, query.ip_addresses, active_only=True))
        elif query.ip_scope == "history":
            conditions.append(_identifier_exists(IP_TYPES, query.ip_addresses, active_only=False))
        else:
            conditions.append(_identifier_exists(IP_TYPES, query.ip_addresses))

    for field_name, identifier_types in IDENTIFIER_TYPE_MAP.items():
        values = getattr(query, field_name)
        if values:
            conditions.append(_identifier_exists(identifier_types, values))

    string_fields = {
        "operating_systems": Asset.operating_system,
        "system_owners": Asset.system_owner,
        "administrative_teams": Asset.administrative_team,
        "technical_owners": Asset.technical_owner,
        "environments": Asset.environment,
        "data_centers": Asset.data_center,
        "business_services": Asset.business_service,
        "server_roles": Asset.server_role,
        "maintenance_groups": Asset.maintenance_group,
        "patch_groups": Asset.patch_group,
    }
    for field_name, column in string_fields.items():
        values = getattr(query, field_name)
        if values:
            conditions.append(func.lower(column).in_(values))

    if query.tags is not None:
        tag_names = query.tags.values
        tag_match_count = (
            select(func.count(func.distinct(Tag.name)))
            .select_from(asset_tags.join(Tag, asset_tags.c.tag_id == Tag.id))
            .where(
                asset_tags.c.asset_id == Asset.id,
                func.lower(Tag.name).in_(tag_names),
            )
            .correlate(Asset)
            .scalar_subquery()
        )
        if query.tags.match == "all":
            conditions.append(tag_match_count == len(tag_names))
        else:
            conditions.append(tag_match_count > 0)

    if query.last_scan_observation is not None:
        if query.last_scan_observation.start is not None:
            conditions.append(
                Asset.last_scan_observed_at >= _datetime_bound(query.last_scan_observation.start, end=False)
            )
        if query.last_scan_observation.end is not None:
            conditions.append(
                Asset.last_scan_observed_at <= _datetime_bound(query.last_scan_observation.end, end=True)
            )

    conditions.extend(_apply_float_range(Asset.identity_confidence, query.identity_confidence))
    unresolved = _unresolved_identity_exists()
    if query.identity_review_state == "exclude_unresolved":
        conditions.append(~unresolved)
    elif query.identity_review_state == "only_unresolved":
        conditions.append(unresolved)

    medium_count = _finding_count(AssetFinding.severity == "medium")
    low_count = _finding_count(AssetFinding.severity == "low")
    mature_count = _finding_count(AssetFinding.maturity_status == "mature")
    new_count = _finding_count(
        or_(
            AssetFinding.maturity_status.in_(("new", "deferred")),
            AssetFinding.status == "new_or_maturity_deferred",
        )
    )
    overdue_count = _finding_count(AssetFinding.sla_status == "overdue")
    conditions.extend(_apply_numeric_range(medium_count, query.open_medium_count))
    conditions.extend(_apply_numeric_range(low_count, query.open_low_count))
    conditions.extend(_apply_numeric_range(mature_count, query.mature_backlog_count))
    conditions.extend(_apply_numeric_range(new_count, query.new_deferred_count))
    conditions.extend(_apply_numeric_range(overdue_count, query.overdue_count))

    if query.oldest_open_finding is not None:
        oldest = _oldest_open()
        if query.oldest_open_finding.start is not None:
            conditions.append(oldest >= _datetime_bound(query.oldest_open_finding.start, end=False))
        if query.oldest_open_finding.end is not None:
            conditions.append(oldest <= _datetime_bound(query.oldest_open_finding.end, end=True))

    finding_predicates: list[ColumnElement[bool]] = [
        AssetFinding.asset_id == Asset.id,
        AssetFinding.status.in_(OPEN_BACKLOG_STATUSES),
    ]
    if query.open_severities:
        finding_predicates.append(AssetFinding.severity.in_(query.open_severities))
    if query.finding_statuses:
        finding_predicates.append(AssetFinding.status.in_(query.finding_statuses))
    if query.maturity_states:
        finding_predicates.append(AssetFinding.maturity_status.in_(query.maturity_states))
    if query.sla_states:
        finding_predicates.append(AssetFinding.sla_status.in_(query.sla_states))
    if query.plugin_ids:
        finding_predicates.append(AssetFinding.plugin_id.in_(query.plugin_ids))
    if query.ports:
        finding_predicates.append(AssetFinding.port.in_(query.ports))
    if query.protocols:
        finding_predicates.append(func.lower(AssetFinding.protocol).in_(query.protocols))

    definition_predicates: list[ColumnElement[bool]] = [
        VulnerabilityDefinition.id == AssetFinding.vulnerability_definition_id
    ]
    if query.plugin_families:
        definition_predicates.append(
            func.lower(VulnerabilityDefinition.plugin_family).in_(query.plugin_families)
        )
    if query.cves:
        definition_predicates.append(
            or_(*(cast(VulnerabilityDefinition.cves, JSONB).contains([cve]) for cve in query.cves))
        )
    if query.exploit_indicator is not None:
        exploit_present = or_(
            VulnerabilityDefinition.exploit_available.is_(True),
            VulnerabilityDefinition.exploited_by_malware.is_(True),
            VulnerabilityDefinition.known_exploited.is_(True),
        )
        definition_predicates.append(exploit_present if query.exploit_indicator else ~exploit_present)

    has_finding_filter = (
        any(
            (
                query.open_severities,
                query.finding_statuses,
                query.maturity_states,
                query.sla_states,
                query.plugin_ids,
                query.plugin_families,
                query.cves,
                query.ports,
                query.protocols,
            )
        )
        or query.exploit_indicator is not None
    )
    if has_finding_filter:
        conditions.append(
            exists(
                select(literal(1))
                .select_from(AssetFinding)
                .join(
                    VulnerabilityDefinition,
                    VulnerabilityDefinition.id == AssetFinding.vulnerability_definition_id,
                )
                .where(*finding_predicates, *definition_predicates)
            )
        )
    return conditions


def _sort_expressions(query: HostQueryV1) -> list[ColumnElement[Any]]:
    mapping: dict[str, Any] = {
        "canonical_hostname": func.lower(func.coalesce(Asset.canonical_hostname, "")),
        "operating_system": func.lower(func.coalesce(Asset.operating_system, "")),
        "system_owner": func.lower(func.coalesce(Asset.system_owner, "")),
        "administrative_team": func.lower(func.coalesce(Asset.administrative_team, "")),
        "environment": func.lower(func.coalesce(Asset.environment, "")),
        "maintenance_group": func.lower(func.coalesce(Asset.maintenance_group, "")),
        "last_scan_observed_at": Asset.last_scan_observed_at,
        "open_medium_count": _finding_count(AssetFinding.severity == "medium"),
        "open_low_count": _finding_count(AssetFinding.severity == "low"),
        "mature_backlog_count": _finding_count(AssetFinding.maturity_status == "mature"),
        "new_deferred_count": _finding_count(
            or_(
                AssetFinding.maturity_status.in_(("new", "deferred")),
                AssetFinding.status == "new_or_maturity_deferred",
            )
        ),
        "overdue_count": _finding_count(AssetFinding.sla_status == "overdue"),
        "oldest_open_finding": _oldest_open(),
        "identity_confidence": Asset.identity_confidence,
    }
    expressions: list[ColumnElement[Any]] = []
    for clause in query.sort:
        expression = mapping[clause.field]
        expressions.append(
            expression.desc().nullslast() if clause.direction == "desc" else expression.asc().nullsfirst()
        )
    expressions.append(Asset.id.asc())
    return expressions


def host_row_select(query: HostQueryV1) -> Select[Any]:
    conditions = _host_conditions(query)
    return (
        select(
            Asset,
            _finding_count(AssetFinding.severity == "medium").label("open_medium_count"),
            _finding_count(AssetFinding.severity == "low").label("open_low_count"),
            _finding_count(AssetFinding.maturity_status == "mature").label("mature_backlog_count"),
            _finding_count(
                or_(
                    AssetFinding.maturity_status.in_(("new", "deferred")),
                    AssetFinding.status == "new_or_maturity_deferred",
                )
            ).label("new_deferred_count"),
            _finding_count(AssetFinding.sla_status == "overdue").label("overdue_count"),
            _oldest_open().label("oldest_open_finding"),
            _unresolved_identity_exists().label("unresolved_identity"),
        )
        .where(*conditions)
        .options(selectinload(Asset.identifiers), selectinload(Asset.tags))
        .order_by(*_sort_expressions(query))
    )


def host_id_select(query: HostQueryV1) -> Select[Any]:
    return select(Asset.id).where(*_host_conditions(query)).order_by(*_sort_expressions(query))


def _host_summary_from_row(row: Any) -> HostSummary:
    asset: Asset = row[0]
    current_ips = sorted(
        {
            identifier.normalized_value
            for identifier in asset.identifiers
            if identifier.active
            and not identifier.shared_or_non_identifying
            and identifier.identifier_type in IP_TYPES
        }
    )
    aliases = sorted(
        {
            identifier.normalized_value
            for identifier in asset.identifiers
            if identifier.identifier_type in ALIAS_TYPES
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


def list_hosts(
    db: Session,
    query: HostQueryV1,
    *,
    page: int,
    page_size: int,
) -> tuple[HostQueryV1, int, list[HostSummary]]:
    normalized = normalize_host_query(query)
    id_query = host_id_select(normalized).order_by(None)
    total = int(db.scalar(select(func.count()).select_from(id_query.subquery())) or 0)
    rows = db.execute(host_row_select(normalized).offset((page - 1) * page_size).limit(page_size)).all()
    return normalized, total, [_host_summary_from_row(row) for row in rows]


def resolve_asset_ids(db: Session, query: HostQueryV1) -> tuple[HostQueryV1, list[uuid.UUID]]:
    normalized = normalize_host_query(query)
    return normalized, list(db.scalars(host_id_select(normalized)))


def finding_scope_conditions(scope: FindingScopeV1) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = []
    if scope.severities:
        conditions.append(AssetFinding.severity.in_(scope.severities))
    if scope.maturity_states:
        conditions.append(AssetFinding.maturity_status.in_(scope.maturity_states))
    if scope.sla_states:
        conditions.append(AssetFinding.sla_status.in_(scope.sla_states))
    if scope.statuses:
        conditions.append(AssetFinding.status.in_(scope.statuses))
    if scope.plugin_ids:
        conditions.append(AssetFinding.plugin_id.in_(_clean_strings(scope.plugin_ids)))
    if scope.ports:
        conditions.append(AssetFinding.port.in_(sorted(set(scope.ports))))
    if scope.protocols:
        conditions.append(func.lower(AssetFinding.protocol).in_(_clean_strings(scope.protocols)))
    if scope.owners:
        conditions.append(func.lower(Asset.system_owner).in_(_clean_strings(scope.owners)))
    if scope.teams:
        conditions.append(func.lower(Asset.administrative_team).in_(_clean_strings(scope.teams)))
    if scope.first_found is not None:
        conditions.extend(_finding_date_conditions(AssetFinding.first_found_at, scope.first_found))
    if scope.last_found is not None:
        conditions.extend(_finding_date_conditions(AssetFinding.last_found_at, scope.last_found))
    if scope.cves:
        conditions.append(
            or_(
                *(
                    cast(VulnerabilityDefinition.cves, JSONB).contains([cve])
                    for cve in _clean_strings(scope.cves)
                )
            )
        )
    if scope.exploit_indicator is not None:
        exploit_present = or_(
            VulnerabilityDefinition.exploit_available.is_(True),
            VulnerabilityDefinition.exploited_by_malware.is_(True),
            VulnerabilityDefinition.known_exploited.is_(True),
        )
        conditions.append(exploit_present if scope.exploit_indicator else ~exploit_present)
    return conditions


def _finding_date_conditions(column: Any, value_range: DateRange) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = []
    if value_range.start is not None:
        conditions.append(column >= _datetime_bound(value_range.start, end=False))
    if value_range.end is not None:
        conditions.append(column <= _datetime_bound(value_range.end, end=True))
    return conditions


def count_findings_for_query(db: Session, query: HostQueryV1, scope: FindingScopeV1) -> int:
    normalized = normalize_host_query(query)
    asset_ids = host_id_select(normalized).order_by(None).subquery()
    statement = (
        select(func.count(AssetFinding.id))
        .select_from(AssetFinding)
        .join(Asset, Asset.id == AssetFinding.asset_id)
        .join(
            VulnerabilityDefinition,
            VulnerabilityDefinition.id == AssetFinding.vulnerability_definition_id,
        )
        .where(
            AssetFinding.asset_id.in_(select(asset_ids.c.id)),
            *finding_scope_conditions(scope),
        )
    )
    return int(db.scalar(statement) or 0)


def count_unresolved_for_query(db: Session, query: HostQueryV1) -> int:
    normalized = normalize_host_query(query)
    statement = select(func.count()).select_from(
        select(Asset.id)
        .where(*_host_conditions(normalized), _unresolved_identity_exists())
        .order_by(None)
        .subquery()
    )
    return int(db.scalar(statement) or 0)


def human_query_summary(query: HostQueryV1) -> str:
    normalized = normalize_host_query(query)
    parts: list[str] = []
    payload = normalized.model_dump(mode="json", exclude_none=True)
    for key, value in payload.items():
        if key in {"schema_version", "sort", "ip_scope", "identity_review_state"}:
            continue
        if value not in ([], {}, None, ""):
            label = key.replace("_", " ")
            parts.append(f"{label}: {value}")
    if normalized.ip_addresses:
        parts.append(f"IP scope: {normalized.ip_scope}")
    if normalized.identity_review_state != "include_unresolved":
        parts.append(f"identity review: {normalized.identity_review_state}")
    return "; ".join(parts) if parts else "All active canonical assets"
