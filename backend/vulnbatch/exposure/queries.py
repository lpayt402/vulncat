from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import String, case, cast, func, or_, select, tuple_
from sqlalchemy.orm import Session, aliased

from vulnbatch.db.exposure import (
    ExposureAttribution,
    ExposureDecision,
    ExposureNode,
    ExposureNodeFact,
    ExposureRelationship,
)
from vulnbatch.db.models import Asset
from vulnbatch.db.reconciliation import (
    CoverageObservation,
    CurrentAssignment,
    SourceInstance,
    SourceObservation,
    VulnerabilityOccurrence,
)
from vulnbatch.exposure.service import _load, _utc, snapshot
from vulnbatch.reconciliation.storage import revision


def _node_items(db: Session, rows: list[ExposureNode], now: datetime) -> list[dict[str, Any]]:
    if not rows:
        return []
    ids = [row.id for row in rows]
    assets = _load(db, Asset, {row.asset_id for row in rows if row.asset_id})
    summaries: dict[uuid.UUID, Any] = {}
    counts: dict[uuid.UUID, dict[str, int]] = defaultdict(
        lambda: {"inventory": 0, "vulnerability": 0, "coverage": 0}
    )
    for start in range(0, len(ids), 400):
        part = ids[start : start + 400]
        summary_query = (
            select(
                ExposureNodeFact.node_id,
                func.count(),
                func.count(func.distinct(ExposureNodeFact.facts_sha256)),
                func.sum(case((ExposureNodeFact.observed_at < now - timedelta(days=90), 1), else_=0)),
                func.max(ExposureNodeFact.observed_at),
            )
            .where(ExposureNodeFact.node_id.in_(part))
            .group_by(ExposureNodeFact.node_id)
        )
        for node_id, count, distinct, stale, latest in db.execute(summary_query):
            summaries[node_id] = {
                "fact_count": count,
                "distinct_fact_count": distinct,
                "has_disagreement": distinct > 1,
                "stale_fact_count": stale,
                "latest_observed_at": _utc(latest).isoformat() if latest else None,
            }
        count_query = (
            select(ExposureAttribution.node_id, SourceObservation.kind, func.count())
            .join(SourceObservation, SourceObservation.id == ExposureAttribution.observation_id)
            .where(ExposureAttribution.node_id.in_(part), ExposureAttribution.status == "attributed")
            .group_by(ExposureAttribution.node_id, SourceObservation.kind)
        )
        for node_id, kind, count in db.execute(count_query):
            counts[node_id][kind] = count
        service_counts = (
            select(
                ExposureRelationship.to_node_id,
                SourceObservation.kind,
                func.count(func.distinct(SourceObservation.id)),
            )
            .join(ExposureAttribution, ExposureAttribution.node_id == ExposureRelationship.from_node_id)
            .join(SourceObservation, SourceObservation.id == ExposureAttribution.observation_id)
            .where(
                ExposureRelationship.to_node_id.in_(part),
                ExposureRelationship.kind == "endpoint_of",
                ExposureRelationship.active.is_(True),
                ExposureAttribution.status == "attributed",
            )
            .group_by(ExposureRelationship.to_node_id, SourceObservation.kind)
        )
        for node_id, kind, count in db.execute(service_counts):
            counts[node_id][kind] += count
    items = []
    for row in rows:
        asset = assets.get(row.asset_id) if row.asset_id else None
        data = snapshot(row)
        data.update(
            asset_name=asset.canonical_hostname if asset else None,
            fact_summary=summaries.get(
                row.id,
                {
                    "fact_count": 0,
                    "distinct_fact_count": 0,
                    "has_disagreement": False,
                    "stale_fact_count": 0,
                    "latest_observed_at": None,
                },
            ),
            exposure_counts=counts[row.id],
        )
        items.append(data)
    return items


def nodes(db: Session, *, q: str, kind: str | None, offset: int, limit: int, now: datetime) -> dict[str, Any]:
    captured = revision(db)
    query = select(ExposureNode).where(ExposureNode.active.is_(True))
    if kind:
        query = query.where(ExposureNode.kind == kind)
    if q.strip():
        pattern = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.where(
            or_(
                *[
                    field.ilike(pattern, escape="\\")
                    for field in (
                        ExposureNode.label,
                        ExposureNode.native_id,
                        ExposureNode.source,
                        ExposureNode.instance,
                        ExposureNode.ip_address,
                        ExposureNode.dns_name,
                        ExposureNode.network_scope,
                        cast(ExposureNode.id, String),
                    )
                ]
            )
        )
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = list(db.scalars(query.order_by(ExposureNode.label, ExposureNode.id).offset(offset).limit(limit)))
    return {
        "revision": captured,
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": _node_items(db, rows, now),
    }


def node_detail(
    db: Session, node_id: uuid.UUID, *, fact_offset: int, fact_limit: int, now: datetime
) -> dict[str, Any]:
    captured = revision(db)
    row = db.get(ExposureNode, node_id)
    if row is None:
        raise LookupError("Exposure node not found")
    facts_query = select(ExposureNodeFact).where(ExposureNodeFact.node_id == node_id)
    total = db.scalar(select(func.count()).select_from(facts_query.subquery())) or 0
    facts = list(
        db.scalars(
            facts_query.order_by(ExposureNodeFact.imported_at.desc(), ExposureNodeFact.id)
            .offset(fact_offset)
            .limit(fact_limit)
        )
    )
    return {
        "revision": captured,
        "node": _node_items(db, [row], now)[0],
        "facts": [
            {
                "id": str(fact.id),
                "node_id": str(fact.node_id),
                "decision_id": str(fact.decision_id),
                "observed_at": _utc(fact.observed_at).isoformat() if fact.observed_at else None,
                "imported_at": _utc(fact.imported_at).isoformat(),
                "facts_sha256": fact.facts_sha256,
                "payload": fact.payload,
                "provenance": fact.provenance,
            }
            for fact in facts
        ],
        "fact_total": total,
        "fact_offset": fact_offset,
        "fact_limit": fact_limit,
    }


def graph(
    db: Session,
    *,
    node_id: uuid.UUID | None,
    offset: int,
    limit: int,
    relationship_offset: int,
    relationship_limit: int,
    now: datetime,
) -> dict[str, Any]:
    captured = revision(db)
    query = select(ExposureNode)
    query = query.where(ExposureNode.id == node_id) if node_id else query.where(ExposureNode.active.is_(True))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = list(db.scalars(query.order_by(ExposureNode.label, ExposureNode.id).offset(offset).limit(limit)))
    ids = [row.id for row in rows]
    edge_query = select(ExposureRelationship).where(
        ExposureRelationship.active.is_(True),
        (ExposureRelationship.from_node_id.in_(ids) | ExposureRelationship.to_node_id.in_(ids)),
    )
    edge_total = db.scalar(select(func.count()).select_from(edge_query.subquery())) or 0
    edges = list(
        db.scalars(
            edge_query.order_by(ExposureRelationship.kind, ExposureRelationship.id)
            .offset(relationship_offset)
            .limit(relationship_limit)
        )
    )
    adjacent = _load(
        db, ExposureNode, {edge.from_node_id for edge in edges} | {edge.to_node_id for edge in edges}
    )
    return {
        "revision": captured,
        "total": total,
        "offset": offset,
        "limit": limit,
        "nodes": _node_items(db, rows, now),
        "relationships": [
            {
                **snapshot(edge),
                "from_node_label": adjacent[edge.from_node_id].label,
                "to_node_label": adjacent[edge.to_node_id].label,
                "from_node_kind": adjacent[edge.from_node_id].kind,
                "to_node_kind": adjacent[edge.to_node_id].kind,
            }
            for edge in edges
        ],
        "relationship_total": edge_total,
        "relationship_offset": relationship_offset,
        "relationship_limit": relationship_limit,
    }


def report(
    db: Session,
    *,
    node_id: uuid.UUID | None,
    observation_kind: str | None,
    offset: int,
    limit: int,
    now: datetime,
) -> dict[str, Any]:
    captured = revision(db)
    bound_asset = case(
        (ExposureNode.id.is_not(None), ExposureNode.asset_id), else_=CurrentAssignment.asset_id
    )
    query = (
        select(
            SourceObservation,
            SourceInstance,
            VulnerabilityOccurrence,
            CoverageObservation,
            ExposureAttribution,
            ExposureNode,
            Asset.canonical_hostname,
            bound_asset.label("bound_asset_id"),
        )
        .join(SourceInstance, SourceInstance.id == SourceObservation.source_instance_id)
        .outerjoin(VulnerabilityOccurrence, VulnerabilityOccurrence.observation_id == SourceObservation.id)
        .outerjoin(CoverageObservation, CoverageObservation.observation_id == SourceObservation.id)
        .outerjoin(ExposureAttribution, ExposureAttribution.observation_id == SourceObservation.id)
        .outerjoin(ExposureNode, ExposureNode.id == ExposureAttribution.node_id)
        .outerjoin(CurrentAssignment, CurrentAssignment.observation_id == SourceObservation.id)
        .outerjoin(Asset, Asset.id == bound_asset)
    )
    if node_id:
        explicit_endpoints = select(ExposureRelationship.from_node_id).where(
            ExposureRelationship.kind == "endpoint_of",
            ExposureRelationship.to_node_id == node_id,
            ExposureRelationship.active.is_(True),
        )
        query = query.where(
            or_(ExposureAttribution.node_id == node_id, ExposureAttribution.node_id.in_(explicit_endpoints))
        )
    count_query = query.with_only_columns(
        SourceObservation.kind, func.count(), maintain_column_froms=True
    ).group_by(SourceObservation.kind)
    counts = {"inventory": 0, "vulnerability": 0, "coverage": 0}
    counts.update({kind: count for kind, count in db.execute(count_query)})
    if observation_kind:
        query = query.where(SourceObservation.kind == observation_kind)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = list(
        db.execute(
            query.order_by(SourceObservation.imported_at.desc(), SourceObservation.id)
            .offset(offset)
            .limit(limit)
        )
    )
    endpoint_ids = {row[5].id for row in rows if row[5] and row[5].kind == "endpoint"}
    services: dict[uuid.UUID, list[ExposureNode]] = defaultdict(list)
    service_alias = aliased(ExposureNode)
    sequence = list(endpoint_ids)
    for start in range(0, len(sequence), 400):
        service_query = (
            select(ExposureRelationship.from_node_id, service_alias)
            .join(service_alias, service_alias.id == ExposureRelationship.to_node_id)
            .where(
                ExposureRelationship.from_node_id.in_(sequence[start : start + 400]),
                ExposureRelationship.active.is_(True),
                ExposureRelationship.kind == "endpoint_of",
                service_alias.active.is_(True),
            )
        )
        for endpoint_id, service in db.execute(service_query):
            if service.id not in {item.id for item in services[endpoint_id]}:
                services[endpoint_id].append(service)
    items = []
    for observation, source, vuln, coverage, attribution, node, asset_name, asset_id in rows:
        normalized = observation.normalized
        time_meaning = normalized.get("provenance", {}).get("time_meaning", "unknown")
        observed = _utc(observation.observed_at) if observation.observed_at else None
        time_warning = (
            "Source observation time is in the future; review source clock"
            if observed and (observed > _utc(now) or observed > _utc(observation.imported_at))
            else None
        )
        age = (
            max(0, int((_utc(now) - observed).total_seconds() // 86400))
            if observed and time_meaning == "source_observed" and time_warning is None
            else None
        )
        service = node if node and node.kind == "service" else None
        candidates = services[node.id] if node and node.kind == "endpoint" else []
        if len(candidates) == 1:
            service = candidates[0]
        reason = (
            attribution.reason if attribution else "No explicit service graph attribution; review required"
        )
        if len(candidates) > 1:
            reason += "; multiple explicit endpoint_of services require review"
        if time_warning:
            reason += "; " + time_warning
        item = {
            "observation_id": str(observation.id),
            "observation_kind": observation.kind,
            "vulnerability_id": vuln.vulnerability_id if vuln else None,
            "native_status": vuln.native_status if vuln else normalized.get("native_status"),
            "coverage_outcome": coverage.outcome if coverage else None,
            "source": source.source,
            "instance": source.label,
            "observed_at": observed.isoformat() if observed else None,
            "imported_at": _utc(observation.imported_at).isoformat(),
            "age_days": age,
            "time_meaning": time_meaning,
            "asset_id": str(asset_id) if asset_id else None,
            "asset_name": asset_name,
            "node_id": str(node.id) if node else None,
            "node_kind": node.kind if node else None,
            "node_label": node.label if node else None,
            "service_id": str(service.id) if service else None,
            "service_label": service.label if service else None,
            "network_scope": node.network_scope if node else normalized.get("asset", {}).get("network_scope"),
            "protocol": node.protocol if node else None,
            "port": node.port if node else None,
            "dns_name": node.dns_name if node else None,
            "sni": node.sni if node else None,
            "attribution_status": attribution.status
            if attribution and len(candidates) <= 1
            else "review_needed",
            "attribution_reason": reason,
            "attribution_id": str(attribution.observation_id) if attribution else None,
            "attribution_version": attribution.version if attribution else None,
            "time_warning": time_warning,
            "evidence": normalized,
        }
        items.append(item)
    return {
        "revision": captured,
        "total": total,
        "offset": offset,
        "limit": limit,
        "counts": counts,
        "items": items,
    }


def _undo_blocks(
    db: Session,
    rows: list[ExposureDecision],
    current: dict[str, dict[uuid.UUID, Any]],
    undone: set[uuid.UUID | None],
) -> dict[uuid.UUID, str | None]:
    from vulnbatch.exposure.service import reverse_changes
    from vulnbatch.reconciliation.storage import ReconciliationConflict

    reasons: dict[uuid.UUID, str | None] = {}
    plans: dict[uuid.UUID, list[dict[str, Any]]] = {}
    for row in rows:
        if row.action != "apply" or row.id in undone:
            reasons[row.id] = "Decision already undone or is an undo"
            continue
        try:
            plans[row.id] = reverse_changes(row, current)
            reasons[row.id] = None
        except ReconciliationConflict:
            reasons[row.id] = "Affected versions changed"
    inactive = {
        uuid.UUID(c["entity_id"])
        for changes in plans.values()
        for c in changes
        if c["entity_type"] == "node" and not c["after"]["active"]
    }
    edges_by_node: dict[uuid.UUID, dict[uuid.UUID, ExposureRelationship]] = defaultdict(dict)
    attrs_by_node: dict[uuid.UUID, dict[uuid.UUID, ExposureAttribution]] = defaultdict(dict)
    sequence = list(inactive)
    for start in range(0, len(sequence), 300):
        ids = sequence[start : start + 300]
        edges = db.scalars(
            select(ExposureRelationship).where(
                ExposureRelationship.active.is_(True),
                ExposureRelationship.from_node_id.in_(ids) | ExposureRelationship.to_node_id.in_(ids),
            )
        )
        for edge in edges:
            edges_by_node[edge.from_node_id][edge.id] = edge
            edges_by_node[edge.to_node_id][edge.id] = edge
        attrs = db.scalars(select(ExposureAttribution).where(ExposureAttribution.node_id.in_(ids)))
        for attribution in attrs:
            if attribution.node_id:
                attrs_by_node[attribution.node_id][attribution.observation_id] = attribution
    targets = set()
    for changes in plans.values():
        for change in changes:
            after = change["after"]
            if change["entity_type"] == "relationship" and after["active"]:
                targets.update({uuid.UUID(after["from_node_id"]), uuid.UUID(after["to_node_id"])})
            elif change["entity_type"] == "attribution" and after["node_id"]:
                targets.add(uuid.UUID(after["node_id"]))
    target_nodes = {**current["node"], **_load(db, ExposureNode, targets - set(current["node"]))}
    asset_ids = {
        uuid.UUID(c["after"]["asset_id"])
        for changes in plans.values()
        for c in changes
        if c["entity_type"] == "node" and c["after"]["asset_id"]
    }
    assets = _load(db, Asset, asset_ids)
    for decision_id, changes in plans.items():
        changed = {
            kind: {uuid.UUID(c["entity_id"]): c["after"] for c in changes if c["entity_type"] == kind}
            for kind in ("node", "relationship", "attribution")
        }
        deactivated = {key for key, value in changed["node"].items() if not value["active"]}
        for node_id in deactivated:
            for edge_id in edges_by_node[node_id]:
                if edge_id not in changed["relationship"] or changed["relationship"][edge_id]["active"]:
                    reasons[decision_id] = "Active relationships added later require review"
            for observation_id in attrs_by_node[node_id]:
                replacement = changed["attribution"].get(observation_id)
                if replacement is None or replacement["node_id"] == str(node_id):
                    reasons[decision_id] = "Attributions added later require review"
        for change in changes:
            after = change["after"]
            referenced = []
            if change["entity_type"] == "relationship" and after["active"]:
                referenced = [after["from_node_id"], after["to_node_id"]]
            elif change["entity_type"] == "attribution" and after["node_id"]:
                referenced = [after["node_id"]]
            for ref in referenced:
                key = uuid.UUID(ref)
                active = (
                    changed["node"][key]["active"]
                    if key in changed["node"]
                    else target_nodes.get(key) and target_nodes[key].active
                )
                if not active:
                    reasons[decision_id] = "Undo would restore a reference to an inactive node"
            if change["entity_type"] == "node" and after["asset_id"]:
                asset = assets.get(uuid.UUID(after["asset_id"]))
                if asset is None or not asset.active or asset.merged_into_id:
                    reasons[decision_id] = "Undo would restore a binding to a retired asset"
    return reasons


def history(db: Session, *, node_id: uuid.UUID | None, offset: int, limit: int) -> dict[str, Any]:
    from vulnbatch.db.exposure import ExposureVersion
    from vulnbatch.exposure.service import MODELS

    captured = revision(db)
    query = select(ExposureDecision)
    if node_id:
        related_entities = select(ExposureVersion.entity_type, ExposureVersion.entity_id).where(
            or_(
                (ExposureVersion.entity_type == "node") & (ExposureVersion.entity_id == node_id),
                ExposureVersion.snapshot["from_node_id"].as_string() == str(node_id),
                ExposureVersion.snapshot["to_node_id"].as_string() == str(node_id),
                ExposureVersion.snapshot["node_id"].as_string() == str(node_id),
            )
        )
        decision_ids = select(ExposureVersion.decision_id).where(
            tuple_(ExposureVersion.entity_type, ExposureVersion.entity_id).in_(related_entities)
        )
        query = query.where(ExposureDecision.id.in_(decision_ids))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = list(
        db.scalars(
            query.order_by(ExposureDecision.occurred_at.desc(), ExposureDecision.id)
            .offset(offset)
            .limit(limit)
        )
    )
    current = {
        kind: _load(
            db,
            model,
            {
                uuid.UUID(change["entity_id"])
                for row in rows
                for change in row.changes
                if change["entity_type"] == kind
            },
        )
        for kind, model in MODELS.items()
    }
    undone = set(
        db.scalars(
            select(ExposureDecision.undo_of_id).where(
                ExposureDecision.undo_of_id.in_([row.id for row in rows])
            )
        )
    )
    reasons = _undo_blocks(db, rows, current, undone)
    items = []
    for row in rows:
        reason = reasons[row.id]
        items.append(
            {
                "id": str(row.id),
                "decision_id": str(row.id),
                "request_key": row.request_key,
                "action": row.action,
                "actor_user_id": str(row.actor_user_id),
                "occurred_at": _utc(row.occurred_at).isoformat(),
                "reason": row.reason,
                "undo_of_id": str(row.undo_of_id) if row.undo_of_id else None,
                "changes": row.changes,
                "result": row.result,
                "undoable": reason is None,
                "undo_block_reason": reason,
            }
        )
    return {"revision": captured, "total": total, "offset": offset, "limit": limit, "items": items}
