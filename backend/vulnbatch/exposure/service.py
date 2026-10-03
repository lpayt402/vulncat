from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnbatch.audit.service import record_audit
from vulnbatch.core.config import get_settings
from vulnbatch.db.exposure import (
    ExposureAttribution,
    ExposureDecision,
    ExposureNode,
    ExposureNodeFact,
    ExposureRelationship,
    ExposureVersion,
)
from vulnbatch.db.models import Asset
from vulnbatch.db.reconciliation import SourceObservation
from vulnbatch.reconciliation.storage import (
    ReconciliationConflict,
    advance_revision,
    bulk_insert,
    lock_mutations,
    revision,
)
from vulnbatch.schemas.exposure import ApplyRequest, GraphEnvelope, UndoRequest

NAMESPACE = uuid.UUID("b6b0028c-ae80-4fbc-b164-dcfd851fc623")
MODELS = {"node": ExposureNode, "relationship": ExposureRelationship, "attribution": ExposureAttribution}
UUID_FIELDS = {"id", "asset_id", "from_node_id", "to_node_id", "observation_id", "node_id"}
EDGE_TYPES = {
    "endpoint_of": ({"endpoint"}, {"service"}),
    "backed_by": ({"service", "vip"}, {"host", "device", "load_balancer"}),
    "routes_to": ({"vip", "load_balancer"}, {"endpoint", "service"}),
    "hosted_on": ({"endpoint"}, {"host", "device"}),
    "management_of": ({"endpoint"}, {"device"}),
}


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _identity(*parts: str) -> uuid.UUID:
    return uuid.uuid5(NAMESPACE, json.dumps(parts, separators=(",", ":")))


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def snapshot(row: Any) -> dict[str, Any]:
    return {
        column.name: str(value) if isinstance(value, uuid.UUID) else value
        for column in row.__table__.columns
        if (value := getattr(row, column.name)) is not None
    } | {column.name: None for column in row.__table__.columns if getattr(row, column.name) is None}


def _typed(values: dict[str, Any]) -> dict[str, Any]:
    return {
        key: uuid.UUID(value) if key in UUID_FIELDS and value is not None else value
        for key, value in values.items()
    }


def _load(db: Session, model: Any, ids: set[uuid.UUID]) -> dict[uuid.UUID, Any]:
    result = {}
    key = model.observation_id if model is ExposureAttribution else model.id
    sequence = list(ids)
    for start in range(0, len(sequence), 400):
        result.update(
            {
                getattr(row, key.key): row
                for row in db.scalars(select(model).where(key.in_(sequence[start : start + 400])))
            }
        )
    return result


def _provenance(graph: GraphEnvelope, now: datetime, evaluated_at: datetime) -> dict[str, Any]:
    return {
        "source": graph.source,
        "instance": graph.instance,
        "observed_at": graph.observed_at.isoformat() if graph.observed_at else None,
        "imported_at": now.isoformat(),
        "evaluated_at": evaluated_at.isoformat(),
        "source_version": graph.source_version,
        "time_meaning": graph.time_meaning,
        "parser_version": "service-graph-v1",
        "intent": graph.intent,
        "manual_reviewed_at": now.isoformat() if graph.intent == "manual_correction" else None,
        "time_warning": "Source observation time is in the future; review source clock"
        if graph.observed_at and graph.observed_at > evaluated_at
        else None,
    }


def _check_version(row: Any | None, expected: int | None) -> None:
    if row is not None and expected is None:
        raise ReconciliationConflict("Existing exposure projections require an explicit expected_version")
    if expected is not None and (row is None or row.version != expected):
        raise ReconciliationConflict("Affected exposure version changed; preview again")


def _valid_time(provenance: dict[str, Any]) -> datetime | None:
    if provenance.get("time_meaning") != "source_observed" or not provenance.get("observed_at"):
        return None
    observed = _utc(datetime.fromisoformat(provenance["observed_at"]))
    cutoff = _utc(datetime.fromisoformat(provenance.get("evaluated_at") or provenance["imported_at"]))
    return observed if observed <= cutoff else None


def _older(provenance: dict[str, Any], existing: dict[str, Any]) -> bool:
    old_time, incoming_time = _valid_time(existing), _valid_time(provenance)
    reviewed_at = existing.get("manual_reviewed_at")
    if (
        provenance.get("intent") == "source_facts"
        and reviewed_at
        and (incoming_time is None or incoming_time < _utc(datetime.fromisoformat(reviewed_at)))
    ):
        return True
    return old_time is not None and (incoming_time is None or incoming_time < old_time)


def prepare(
    db: Session, graph: GraphEnvelope, now: datetime, *, evaluation_time: datetime | None = None
) -> dict[str, Any]:
    """Validate a bounded delta using reviewed time; record actual import time separately."""
    evaluated_at = evaluation_time or now
    refs = {node.ref: _identity("node", graph.source, graph.instance, node.native_id) for node in graph.nodes}

    def reference(value: str) -> uuid.UUID:
        if value in refs:
            return refs[value]
        try:
            return uuid.UUID(value)
        except ValueError as exc:
            raise ValueError("Graph reference must be a supplied ref or existing node UUID") from exc

    edges = [(edge, reference(edge.from_node), reference(edge.to_node)) for edge in graph.relationships]
    node_ids = set(refs.values()) | {a for _, a, _ in edges} | {b for _, _, b in edges}
    node_ids |= {reference(item.node_ref) for item in graph.attributions if item.node_ref}
    nodes = _load(db, ExposureNode, node_ids)
    projected = {key: snapshot(row) for key, row in nodes.items()}
    provenance = _provenance(graph, now, evaluated_at)
    changes: list[dict[str, Any]] = []
    facts: list[dict[str, Any]] = []
    warnings: list[str] = []
    if graph.observed_at is None or graph.time_meaning != "source_observed":
        warnings.append("Source observation time is unknown or has another meaning; source age is unknown")
    elif graph.observed_at > evaluated_at:
        warnings.append("Source observation time is in the future; review source clock and export metadata")
    elif graph.observed_at < evaluated_at - timedelta(days=90):
        warnings.append("Source observation is older than 90 days; freshness requires review")
    for item in graph.nodes:
        node_id = refs[item.ref]
        old = nodes.get(node_id)
        _check_version(old, item.expected_version)
        if old is not None and old.kind != item.kind:
            raise ValueError("A source native ID cannot change node kind; use a distinct native ID")
        values = item.model_dump(mode="json", exclude={"ref", "expected_version"})
        values.update(
            id=str(node_id),
            source=graph.source,
            instance=graph.instance,
            provenance=provenance,
            version=old.version + 1 if old else 1,
        )
        before = snapshot(old) if old is not None else None
        fact_values = {
            key: value
            for key, value in values.items()
            if key not in {"asset_id", "active", "version", "provenance"}
        }
        facts.append(
            {
                "id": uuid.uuid4(),
                "node_id": node_id,
                "observed_at": _valid_time(provenance),
                "imported_at": now,
                "facts_sha256": digest(fact_values),
                "payload": fact_values,
                "provenance": provenance,
            }
        )
        proposed = values
        if before and _older(provenance, before["provenance"]):
            values = {
                **before,
                "version": values["version"],
            }
            if graph.intent == "manual_correction":
                values.update(asset_id=proposed["asset_id"], active=proposed["active"])
                values["provenance"] = {**before["provenance"], "manual_reviewed_at": now.isoformat()}
            warnings.append(
                f"{item.ref}: older or unknown-time source facts preserved in history; "
                "newer dated projection retained"
            )
        projected[node_id] = values
        changes.append(
            {
                "entity_type": "node",
                "entity_id": str(node_id),
                "before": before,
                "after": values,
                "proposed": proposed,
            }
        )
    for node_id in node_ids:
        if node_id not in projected:
            raise ValueError("Graph refers to an unknown node")
    relation_ids = {
        _identity("edge", graph.source, graph.instance, edge.kind, str(a), str(b)) for edge, a, b in edges
    }
    if len(relation_ids) != len(edges):
        raise ValueError(
            "Duplicate normalized relationships are not supported; refs and UUIDs resolve to the same edge"
        )
    old_edges = _load(db, ExposureRelationship, relation_ids)
    for edge_item, a, b in edges:
        allowed_a, allowed_b = EDGE_TYPES[edge_item.kind]
        if a == b or projected[a]["kind"] not in allowed_a or projected[b]["kind"] not in allowed_b:
            raise ValueError(f"Invalid typed {edge_item.kind} relationship")
        key = _identity("edge", graph.source, graph.instance, edge_item.kind, str(a), str(b))
        old = old_edges.get(key)
        _check_version(old, edge_item.expected_version)
        values = {
            "id": str(key),
            "source": graph.source,
            "instance": graph.instance,
            "kind": edge_item.kind,
            "from_node_id": str(a),
            "to_node_id": str(b),
            "active": edge_item.active,
            "evidence": edge_item.evidence,
            "provenance": provenance,
            "version": old.version + 1 if old else 1,
        }
        proposed = values
        if old is not None and _older(provenance, old.provenance):
            values = {**snapshot(old), "version": values["version"]}
            if graph.intent == "manual_correction":
                values["active"] = edge_item.active
                values["provenance"] = {**old.provenance, "manual_reviewed_at": now.isoformat()}
            warnings.append(f"{edge_item.kind}: newer dated relationship evidence retained")
        changes.append(
            {
                "entity_type": "relationship",
                "entity_id": str(key),
                "before": snapshot(old) if old is not None else None,
                "after": values,
                "proposed": proposed,
            }
        )
    observation_ids = {item.observation_id for item in graph.attributions}
    observations = _load(db, SourceObservation, observation_ids)
    old_attributions = _load(db, ExposureAttribution, observation_ids)
    if set(observations) != observation_ids:
        raise ValueError("Attribution requires an existing immutable source observation")
    for attribution_item in graph.attributions:
        old = old_attributions.get(attribution_item.observation_id)
        _check_version(old, attribution_item.expected_version)
        attributed_node_id = reference(attribution_item.node_ref) if attribution_item.node_ref else None
        values = {
            "observation_id": str(attribution_item.observation_id),
            "node_id": str(attributed_node_id) if attributed_node_id else None,
            "status": attribution_item.status,
            "reason": attribution_item.reason,
            "evidence": attribution_item.evidence,
            "provenance": provenance,
            "version": old.version + 1 if old else 1,
        }
        proposed = values
        if old is not None and graph.intent == "source_facts" and _older(provenance, old.provenance):
            values = {**snapshot(old), "version": values["version"]}
            warnings.append(
                "Older or unknown-time source attribution retained in history; newer mapping retained"
            )
        changes.append(
            {
                "entity_type": "attribution",
                "entity_id": str(attribution_item.observation_id),
                "before": snapshot(old) if old is not None else None,
                "after": values,
                "proposed": proposed,
            }
        )
    _validate_dependencies(db, changes)
    try:
        _validate_targets(db, changes)
    except ReconciliationConflict as exc:
        raise ValueError(str(exc).replace("Undo would restore", "Exposure delta would create")) from exc
    return {
        "node_ids": {key: str(value) for key, value in refs.items()},
        "changes": changes,
        "facts": facts,
        "warnings": warnings,
        "counts": _counts(changes),
    }


def _counts(changes: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(change["entity_type"] for change in changes)
    return {
        "nodes": counts["node"],
        "relationships": counts["relationship"],
        "attributions": counts["attribution"],
    }


def _validate_dependencies(db: Session, changes: list[dict[str, Any]]) -> None:
    inactive = {
        uuid.UUID(change["entity_id"])
        for change in changes
        if change["entity_type"] == "node" and not change["after"]["active"]
    }
    if not inactive:
        return
    edge_changes = {
        uuid.UUID(c["entity_id"]): c["after"] for c in changes if c["entity_type"] == "relationship"
    }
    attr_changes = {
        uuid.UUID(c["entity_id"]): c["after"] for c in changes if c["entity_type"] == "attribution"
    }
    sequence = list(inactive)
    for start in range(0, len(sequence), 300):
        ids = sequence[start : start + 300]
        edge_query = select(ExposureRelationship).where(
            ExposureRelationship.active.is_(True),
            (ExposureRelationship.from_node_id.in_(ids) | ExposureRelationship.to_node_id.in_(ids)),
        )
        for edge in db.scalars(edge_query):
            if edge.id not in edge_changes or edge_changes[edge.id]["active"]:
                raise ReconciliationConflict("Deactivation requires explicit removal of active relationships")
        for item in db.scalars(select(ExposureAttribution).where(ExposureAttribution.node_id.in_(ids))):
            replacement = attr_changes.get(item.observation_id)
            if replacement is None or (
                replacement["node_id"] and uuid.UUID(replacement["node_id"]) in inactive
            ):
                raise ReconciliationConflict(
                    "Deactivation requires explicit removal of affected attributions"
                )


def _validate_targets(db: Session, changes: list[dict[str, Any]]) -> None:
    """Undo respects active targets and Asset bindings changed elsewhere."""
    node_changes = {uuid.UUID(c["entity_id"]): c["after"] for c in changes if c["entity_type"] == "node"}
    targets: set[uuid.UUID] = set()
    for change in changes:
        after = change["after"]
        if change["entity_type"] == "relationship" and after["active"]:
            targets.update({uuid.UUID(after["from_node_id"]), uuid.UUID(after["to_node_id"])})
        elif change["entity_type"] == "attribution" and after["node_id"]:
            targets.add(uuid.UUID(after["node_id"]))
    nodes = _load(db, ExposureNode, targets - set(node_changes))
    for target in targets:
        active = (
            node_changes[target]["active"]
            if target in node_changes
            else nodes.get(target) and nodes[target].active
        )
        if not active:
            raise ReconciliationConflict("Undo would restore a reference to an inactive node")
    asset_ids = {uuid.UUID(after["asset_id"]) for after in node_changes.values() if after["asset_id"]}
    assets = _load(db, Asset, asset_ids)
    if any(key not in assets or not assets[key].active or assets[key].merged_into_id for key in asset_ids):
        raise ReconciliationConflict("Undo would restore a binding to a retired asset")


def _signature(value: str) -> str:
    return hmac.new(
        get_settings().secret_key.encode(), ("exposure-preview:" + value).encode(), hashlib.sha256
    ).hexdigest()


def graph_hash(graph: GraphEnvelope, actor_id: uuid.UUID) -> str:
    return digest({"graph": graph.model_dump(mode="json"), "actor": str(actor_id)})


def preview(db: Session, graph: GraphEnvelope, actor_id: uuid.UUID, now: datetime) -> dict[str, Any]:
    captured = revision(db)
    planned = prepare(db, graph, now)
    payload_hash = graph_hash(graph, actor_id)
    context = {"revision": captured, "evaluated_at": now.isoformat(), "payload_sha256": payload_hash}
    encoded = base64.urlsafe_b64encode(json.dumps(context).encode()).decode().rstrip("=")
    return {key: value for key, value in planned.items() if key != "facts"} | {
        "revision": captured,
        "preview_token": encoded + "." + _signature(encoded),
        "payload_sha256": payload_hash,
    }


def _verify(token: str, payload_hash: str, now: datetime) -> dict[str, Any]:
    try:
        if not token.isascii() or len(token) > 2048:
            raise ValueError("Invalid token")
        encoded, signature = token.split(".")
        if not hmac.compare_digest(signature, _signature(encoded)):
            raise ValueError("Invalid signature")
        context = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        evaluated = datetime.fromisoformat(context["evaluated_at"])
        if evaluated.tzinfo is None or not now - timedelta(minutes=30) <= evaluated <= now:
            raise ValueError("Expired preview")
        if context["payload_sha256"] != payload_hash:
            raise ValueError("Changed graph or actor")
        return cast(dict[str, Any], context)
    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
        raise ReconciliationConflict(
            "Exposure preview expired or graph/actor changed; preview again"
        ) from exc


def _replay(db: Session, key: str, payload_hash: str) -> dict[str, Any] | None:
    previous = db.scalar(select(ExposureDecision).where(ExposureDecision.request_key == key))
    if previous is None:
        return None
    if previous.payload_sha256 != payload_hash:
        raise ReconciliationConflict("Exposure request key already used by a different actor or payload")
    return {**previous.result, "replayed": True}


def _write_changes(db: Session, changes: list[dict[str, Any]], decision_id: uuid.UUID, now: datetime) -> None:
    versions = []
    # Parent nodes precede references; undo also preserves all node identities and facts.
    for entity_type in ("node", "relationship", "attribution"):
        model = MODELS[entity_type]
        existing = _load(
            db, model, {uuid.UUID(c["entity_id"]) for c in changes if c["entity_type"] == entity_type}
        )
        for change in changes:
            if change["entity_type"] != entity_type:
                continue
            row = existing.get(uuid.UUID(change["entity_id"]))
            values = _typed(change["after"])
            if row is None:
                db.add(model(**values))
            else:
                for key, value in values.items():
                    setattr(row, key, value)
            versions.append(
                {
                    "id": uuid.uuid4(),
                    "entity_type": entity_type,
                    "entity_id": uuid.UUID(change["entity_id"]),
                    "version": values["version"],
                    "decision_id": decision_id,
                    "occurred_at": now,
                    "snapshot": change["after"],
                }
            )
        db.flush()
    bulk_insert(db, ExposureVersion, versions)


def _record(
    db: Session,
    payload: ApplyRequest | UndoRequest,
    actor_id: uuid.UUID,
    now: datetime,
    captured: int,
    planned: dict[str, Any],
    payload_hash: str,
    undo_of: uuid.UUID | None = None,
) -> dict[str, Any]:
    key = uuid.uuid4()
    result = {
        "decision_id": str(key),
        "revision": captured + 1,
        "changes": planned["changes"],
        "counts": _counts(planned["changes"]),
        "replayed": False,
    }
    db.add(
        ExposureDecision(
            id=key,
            request_key=payload.request_key,
            payload_sha256=payload_hash,
            action="undo" if undo_of else "apply",
            actor_user_id=actor_id,
            occurred_at=now,
            reason=payload.reason,
            undo_of_id=undo_of,
            changes=planned["changes"],
            result=result,
        )
    )
    db.flush()
    _write_changes(db, planned["changes"], key, now)
    bulk_insert(db, ExposureNodeFact, [{**fact, "decision_id": key} for fact in planned.get("facts", [])])
    advance_revision(db, captured)
    record_audit(
        db,
        event_type="exposure.undo" if undo_of else "exposure.apply",
        actor_user_id=actor_id,
        entity_type="exposure_decision",
        entity_id=key,
        details={"reason": payload.reason, "counts": result["counts"]},
    )
    return result


def apply_graph(db: Session, payload: ApplyRequest, actor_id: uuid.UUID, now: datetime) -> dict[str, Any]:
    captured = lock_mutations(db)
    payload_hash = digest({"actor": str(actor_id), "request": payload.model_dump(mode="json")})
    replayed = _replay(db, payload.request_key, payload_hash)
    if replayed is not None:
        return replayed
    if captured != payload.expected_revision:
        raise ReconciliationConflict("Exposure state revision changed; preview again")
    evaluated_at = now
    if payload.preview_token:
        context = _verify(payload.preview_token, graph_hash(payload.graph, actor_id), now)
        if context["revision"] != captured:
            raise ReconciliationConflict("Exposure preview revision changed; preview again")
        evaluated_at = datetime.fromisoformat(context["evaluated_at"])
    planned = prepare(db, payload.graph, now, evaluation_time=evaluated_at)
    return _record(db, payload, actor_id, now, captured, planned, payload_hash)


def reverse_changes(
    decision: ExposureDecision, current: dict[str, dict[uuid.UUID, Any]]
) -> list[dict[str, Any]]:
    changes = []
    for change in decision.changes:
        row = current[change["entity_type"]].get(uuid.UUID(change["entity_id"]))
        if row is None or row.version != change["after"]["version"]:
            raise ReconciliationConflict("Affected exposure versions changed; undo refused atomically")
        before = snapshot(row)
        if change["before"] is not None:
            after = {**change["before"], "version": row.version + 1}
        elif change["entity_type"] == "attribution":
            after = {
                **before,
                "node_id": None,
                "status": "review_needed",
                "reason": "Explicit attribution undone",
                "version": row.version + 1,
            }
        else:
            after = {**before, "active": False, "version": row.version + 1}
        changes.append(
            {
                "entity_type": change["entity_type"],
                "entity_id": change["entity_id"],
                "before": before,
                "after": after,
            }
        )
    return changes


def undo_plan(db: Session, decision: ExposureDecision) -> list[dict[str, Any]]:
    if decision.action != "apply" or db.scalar(
        select(ExposureDecision.id).where(ExposureDecision.undo_of_id == decision.id)
    ):
        raise ReconciliationConflict("This exposure decision cannot be undone again")
    current = {
        kind: _load(
            db, model, {uuid.UUID(c["entity_id"]) for c in decision.changes if c["entity_type"] == kind}
        )
        for kind, model in MODELS.items()
    }
    changes = reverse_changes(decision, current)
    _validate_dependencies(db, changes)
    _validate_targets(db, changes)
    return changes


def undo(db: Session, payload: UndoRequest, actor_id: uuid.UUID, now: datetime) -> dict[str, Any]:
    captured = lock_mutations(db)
    payload_hash = digest({"actor": str(actor_id), "request": payload.model_dump(mode="json")})
    replayed = _replay(db, payload.request_key, payload_hash)
    if replayed is not None:
        return replayed
    if payload.expected_revision != captured:
        raise ReconciliationConflict("Exposure state revision changed; refresh history")
    decision = db.get(ExposureDecision, payload.decision_id)
    if decision is None:
        raise ValueError("Unknown exposure decision")
    planned = {"changes": undo_plan(db, decision)}
    return _record(db, payload, actor_id, now, captured, planned, payload_hash, undo_of=decision.id)
