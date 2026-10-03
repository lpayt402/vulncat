from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from vulnbatch.core.security import csrf_token_for_session
from vulnbatch.db.base import Base
from vulnbatch.db.models import Asset, Role, User


@pytest.fixture
def context(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, Session, dict[str, Any]]]:
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("SECRET_KEY", "synthetic-exposure-secret-00000000000000000000")
    from vulnbatch.core.config import get_settings

    get_settings.cache_clear()
    from vulnbatch.api.deps import Principal, get_current_principal
    from vulnbatch.api.routes import exposure
    from vulnbatch.db.session import get_db

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def enable_fk(connection: Any, _: Any) -> None:
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        role = Role(name="administrator")
        db.add(role)
        db.flush()
        actor = User(
            username="synthetic", display_name="Synthetic", password_hash=token_urlsafe(16), role_id=role.id
        )
        asset = Asset(canonical_hostname="legacy.example.test")
        db.add_all([actor, asset])
        db.commit()
        settings = {"role": "administrator", "actor_id": actor.id, "asset_id": asset.id}
        token = token_urlsafe(32)
        app = FastAPI()
        app.include_router(exposure.router)
        app.dependency_overrides[get_current_principal] = lambda: cast(
            Principal,
            SimpleNamespace(
                user=SimpleNamespace(id=settings["actor_id"], role=SimpleNamespace(name=settings["role"])),
                raw_session_token=token,
            ),
        )
        app.dependency_overrides[get_db] = lambda: db
        with TestClient(app) as client:
            client.headers["X-CSRF-Token"] = csrf_token_for_session(token)
            yield client, db, settings
    engine.dispose()


def graph(**updates: Any) -> dict[str, Any]:
    return {
        "source": "synthetic_inventory",
        "instance": "lab-a",
        "observed_at": "2026-10-01T00:00:00Z",
        "source_version": "export-v1",
        "time_meaning": "source_observed",
        "nodes": [
            {
                "ref": "host",
                "native_id": "host-1",
                "kind": "host",
                "label": "Host",
                "ip_address": "192.0.2.1",
            },
            {"ref": "svc", "native_id": "svc-1", "kind": "service", "label": "Web"},
            {
                "ref": "ep",
                "native_id": "ep-1",
                "kind": "endpoint",
                "label": "HTTPS",
                "port": 443,
                "protocol": "tcp",
                "dns_name": "web.example.test",
                "sni": "web.example.test",
            },
            {"ref": "vip", "native_id": "vip-1", "kind": "vip", "label": "VIP", "ip_address": "192.0.2.1"},
        ],
        "relationships": [
            {"kind": "endpoint_of", "from_node": "ep", "to_node": "svc"},
            {"kind": "backed_by", "from_node": "svc", "to_node": "host"},
            {"kind": "routes_to", "from_node": "vip", "to_node": "ep"},
        ],
        "attributions": [],
        **updates,
    }


def apply(client: TestClient, payload: dict[str, Any] | None = None, key: str = "apply") -> dict[str, Any]:
    payload = payload or graph()
    # A caller explicitly reviews current versions before replacing existing projections.
    current = client.get("/api/v1/exposure/nodes").json()["items"]
    refs = {}
    for item in payload["nodes"]:
        match = next(
            (
                row
                for row in current
                if row["source"] == payload["source"]
                and row["instance"] == payload["instance"]
                and row["native_id"] == item["native_id"]
            ),
            None,
        )
        if match:
            item.setdefault("expected_version", match["version"])
            refs[item["ref"]] = match["id"]
    current_edges = client.get("/api/v1/exposure/graph").json()["relationships"]
    for edge in payload["relationships"]:
        match = next(
            (
                row
                for row in current_edges
                if row["source"] == payload["source"]
                and row["instance"] == payload["instance"]
                and row["kind"] == edge["kind"]
                and row["from_node_id"] == refs.get(edge["from_node"])
                and row["to_node_id"] == refs.get(edge["to_node"])
            ),
            None,
        )
        if match:
            edge.setdefault("expected_version", match["version"])
    for item in payload["attributions"]:
        row = next(
            (
                row
                for row in client.get("/api/v1/exposure/report").json()["items"]
                if row["observation_id"] == item["observation_id"]
            ),
            None,
        )
        if row and row["attribution_version"]:
            item.setdefault("expected_version", row["attribution_version"])
    preview = client.post("/api/v1/exposure/preview", json={"graph": payload})
    assert preview.status_code == 200, preview.text
    response = client.post(
        "/api/v1/exposure/apply",
        json={
            "graph": payload,
            "request_key": key,
            "reason": "Reviewed synthetic offline evidence",
            "expected_revision": preview.json()["revision"],
            "preview_token": preview.json()["preview_token"],
        },
    )
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def seed_observations(db: Session) -> list[uuid.UUID]:
    from vulnbatch.db.reconciliation import (
        CoverageObservation,
        SourceInstance,
        SourceObservation,
        VulnerabilityOccurrence,
    )

    source = SourceInstance(source="nessus", label="synthetic-scanner")
    db.add(source)
    db.flush()
    ids = []
    for i, kind in enumerate(["vulnerability", "inventory", "coverage"]):
        row = SourceObservation(
            fingerprint=str(i) * 64,
            source_instance_id=source.id,
            kind=kind,
            observed_at=datetime(2026, 10, 1, tzinfo=UTC),
            imported_at=datetime.now(UTC),
            parser_version="synthetic",
            normalized={
                "provenance": {"time_meaning": "source_observed"},
                "raw": {"original": True},
                "warnings": ["Ambiguous OS"],
                "asset": {"operating_system": "Windows or Linux"},
            },
        )
        db.add(row)
        db.flush()
        ids.append(row.id)
        if kind == "vulnerability":
            db.add(
                VulnerabilityOccurrence(
                    observation_id=row.id,
                    occurrence_key="a" * 64,
                    vulnerability_id="CVE-synthetic",
                    native_status="open",
                    evidence={"package_version": "1"},
                )
            )
        if kind == "coverage":
            db.add(CoverageObservation(observation_id=row.id, outcome="failed", complete=False, evidence={}))
    db.commit()
    return ids


def test_preview_is_read_only_and_nodes_have_explicit_identity(context: Any) -> None:
    client, db, _ = context
    from vulnbatch.db.exposure import ExposureNode

    before = client.get("/api/v1/exposure/nodes").json()
    preview = client.post("/api/v1/exposure/preview", json={"graph": graph()})
    assert preview.status_code == 200, preview.text
    assert db.scalar(select(func.count()).select_from(ExposureNode)) == 0
    assert client.get("/api/v1/exposure/nodes").json() == before
    result = apply(client)
    nodes = client.get("/api/v1/exposure/nodes").json()
    assert nodes["total"] == 4 and nodes["revision"] == result["revision"] == 1
    assert len({row["id"] for row in nodes["items"]}) == 4
    assert all(row["provenance"]["source_version"] == "export-v1" for row in nodes["items"])
    assert client.get("/api/v1/exposure/nodes", params={"q": "192.0.2.1"}).json()["total"] == 2


def test_duplicate_ips_across_networks_and_instances_remain_distinct(context: Any) -> None:
    client, _, _ = context
    payload = graph(
        nodes=[
            {
                "ref": str(i),
                "native_id": str(i),
                "kind": "host",
                "label": "Same",
                "ip_address": "192.0.2.1",
                "network_scope": str(i),
            }
            for i in range(2)
        ],
        relationships=[],
    )
    apply(client, payload)
    apply(client, {**payload, "instance": "lab-b"}, "another-instance")
    assert client.get("/api/v1/exposure/nodes").json()["total"] == 4


@pytest.mark.parametrize(
    "kind,from_ref,to_ref",
    [
        ("endpoint_of", "host", "svc"),
        ("backed_by", "ep", "host"),
        ("routes_to", "host", "ep"),
        ("hosted_on", "ep", "svc"),
        ("management_of", "ep", "host"),
    ],
)
def test_invalid_edges_are_atomic(context: Any, kind: str, from_ref: str, to_ref: str) -> None:
    client, _, _ = context
    response = client.post(
        "/api/v1/exposure/preview",
        json={"graph": graph(relationships=[{"kind": kind, "from_node": from_ref, "to_node": to_ref}])},
    )
    assert response.status_code == 422, response.text
    assert client.get("/api/v1/exposure/nodes").json()["total"] == 0


def test_report_attribution_keeps_vip_and_unknown_os_without_backend_inheritance(context: Any) -> None:
    client, db, _ = context
    ids = seed_observations(db)
    payload = graph(
        attributions=[
            {
                "observation_id": str(ids[0]),
                "node_ref": "vip",
                "status": "attributed",
                "reason": "Scanner explicitly measured the VIP",
            }
        ]
    )
    apply(client, payload)
    report = client.get("/api/v1/exposure/report").json()
    assert report["counts"] == {"inventory": 1, "vulnerability": 1, "coverage": 1}
    finding = next(row for row in report["items"] if row["observation_kind"] == "vulnerability")
    assert finding["node_kind"] == "vip" and finding["service_id"] is None
    assert finding["evidence"]["raw"] == {"original": True}
    assert finding["evidence"]["warnings"] == ["Ambiguous OS"]
    host = next(row for row in client.get("/api/v1/exposure/nodes").json()["items"] if row["kind"] == "host")
    assert client.get("/api/v1/exposure/report", params={"node_id": host["id"]}).json()["total"] == 0
    unknown = [row for row in report["items"] if row["attribution_status"] == "review_needed"]
    assert len(unknown) == 2 and all(row["node_id"] is None for row in unknown)


def test_endpoint_service_is_explicit_and_inventory_coverage_remain_separate(context: Any) -> None:
    client, db, _ = context
    ids = seed_observations(db)
    apply(
        client,
        graph(
            attributions=[
                {
                    "observation_id": str(ids[1]),
                    "node_ref": "ep",
                    "status": "attributed",
                    "reason": "Explicit inventory endpoint",
                }
            ]
        ),
    )
    row = client.get("/api/v1/exposure/report", params={"observation_kind": "inventory"}).json()["items"][0]
    assert row["service_label"] == "Web" and row["vulnerability_id"] is None
    assert row["protocol"] == "tcp" and row["port"] == 443
    assert row["dns_name"] == row["sni"] == "web.example.test"
    service_report = client.get("/api/v1/exposure/report", params={"node_id": row["service_id"]}).json()
    assert service_report["total"] == 1 and service_report["items"][0]["node_kind"] == "endpoint"


def test_required_confirmation_stale_revision_versions_and_preview_tampering(context: Any) -> None:
    client, _, _ = context
    preview = client.post("/api/v1/exposure/preview", json={"graph": graph()}).json()
    body = {"graph": graph(), "request_key": "write", "reason": "Review", "expected_revision": 0}
    assert client.post("/api/v1/exposure/apply", json=body).status_code == 422
    body["preview_token"] = preview["preview_token"]
    changed = graph()
    changed["nodes"][0]["label"] = "Changed"
    assert client.post("/api/v1/exposure/apply", json={**body, "graph": changed}).status_code == 409
    apply(client)
    assert client.post("/api/v1/exposure/apply", json=body).status_code == 409
    changed["nodes"][0]["expected_version"] = 99
    assert client.post("/api/v1/exposure/preview", json={"graph": changed}).status_code == 409


def test_idempotency_is_actor_and_payload_bound(context: Any) -> None:
    client, db, settings = context
    body = {
        "graph": graph(),
        "request_key": "same",
        "reason": "Review",
        "expected_revision": 0,
        "confirmed": True,
    }
    first = client.post("/api/v1/exposure/apply", json=body)
    replay = client.post("/api/v1/exposure/apply", json=body)
    assert first.status_code == replay.status_code == 200
    assert replay.json()["replayed"] and first.json()["decision_id"] == replay.json()["decision_id"]
    assert client.post("/api/v1/exposure/apply", json={**body, "reason": "Different"}).status_code == 409
    actor = User(
        username="other",
        display_name="Other",
        password_hash=token_urlsafe(16),
        role_id=db.scalar(select(Role.id)),
    )
    db.add(actor)
    db.commit()
    settings["actor_id"] = actor.id
    assert client.post("/api/v1/exposure/apply", json=body).status_code == 409


def test_undo_preserves_facts_history_and_requires_unchanged_versions(context: Any) -> None:
    client, _, _ = context
    saved = apply(client)
    undo = {
        "decision_id": saved["decision_id"],
        "request_key": "undo",
        "reason": "Reviewed undo",
        "expected_revision": 1,
        "confirmed": True,
    }
    response = client.post("/api/v1/exposure/undo", json=undo)
    assert response.status_code == 200, response.text
    assert client.get("/api/v1/exposure/nodes").json()["total"] == 0
    history = client.get("/api/v1/exposure/history").json()
    assert history["total"] == 2 and history["items"][0]["action"] == "undo"
    assert client.post("/api/v1/exposure/undo", json=undo).json()["replayed"]
    reactivated = graph()
    for item in reactivated["nodes"] + reactivated["relationships"]:
        item["expected_version"] = 2
    apply(client, reactivated, "reapply")
    stale = {**undo, "request_key": "unsafe-undo", "expected_revision": 3}
    assert client.post("/api/v1/exposure/undo", json=stale).status_code == 409


def test_stale_source_fact_does_not_replace_latest_and_disagreement_survives(context: Any) -> None:
    client, _, _ = context
    apply(client)
    older = graph(observed_at="2020-01-01T00:00:00Z", source_version="old")
    older["nodes"][0]["label"] = "Older host"
    older["nodes"][0]["facts"] = {"operating_system": "Ambiguous OS"}
    apply(client, older, "older")
    node = next(row for row in client.get("/api/v1/exposure/nodes").json()["items"] if row["kind"] == "host")
    assert node["label"] == "Host" and node["provenance"]["source_version"] == "export-v1"
    assert node["fact_summary"]["fact_count"] == 2 and node["fact_summary"]["has_disagreement"]
    assert node["fact_summary"]["stale_fact_count"] >= 1


def test_reads_are_bounded_and_writes_require_admin_csrf_auth(context: Any) -> None:
    client, _, settings = context
    apply(client)
    settings["role"] = "read_only"
    for endpoint in ["nodes", "graph", "report", "history"]:
        assert client.get(f"/api/v1/exposure/{endpoint}", params={"limit": 1}).status_code == 200
        assert client.get(f"/api/v1/exposure/{endpoint}", params={"limit": 501}).status_code == 422
    for endpoint in ["preview", "apply", "undo"]:
        assert client.post(f"/api/v1/exposure/{endpoint}").status_code == 403
    settings["role"] = "administrator"
    client.headers.pop("X-CSRF-Token")
    assert client.post("/api/v1/exposure/apply").status_code == 403
    from vulnbatch.api.deps import get_current_principal

    client.app.dependency_overrides.pop(get_current_principal)
    assert client.get("/api/v1/exposure/nodes").status_code == 401


def test_nul_and_oversize_envelopes_are_rejected(context: Any) -> None:
    client, _, _ = context
    assert client.get("/api/v1/exposure/nodes", params={"q": "x\x00"}).status_code == 422
    for payload in [graph(instance="x\x00"), graph(nodes=graph()["nodes"] * 2000)]:
        assert client.post("/api/v1/exposure/preview", json={"graph": payload}).status_code == 422


def test_manual_attribution_only_graph_is_version_guarded_and_undoable(context: Any) -> None:
    client, db, _ = context
    ids = seed_observations(db)
    apply(client)
    node = next(
        row for row in client.get("/api/v1/exposure/nodes").json()["items"] if row["kind"] == "endpoint"
    )
    manual: dict[str, Any] = {
        "source": "analyst",
        "instance": "manual-review",
        "nodes": [],
        "relationships": [],
        "attributions": [
            {
                "observation_id": str(ids[0]),
                "node_ref": node["id"],
                "status": "attributed",
                "reason": "Reviewed explicit endpoint evidence",
            }
        ],
    }
    saved = apply(client, manual, "manual-attribution")
    row = next(
        row
        for row in client.get("/api/v1/exposure/report").json()["items"]
        if row["observation_id"] == str(ids[0])
    )
    assert row["attribution_id"] == str(ids[0]) and row["attribution_version"] == 1
    history = client.get("/api/v1/exposure/history", params={"node_id": node["id"]}).json()
    assert history["total"] == 2 and history["items"][0]["decision_id"] == saved["decision_id"]
    assert not next(
        item for item in history["items"] if item["action"] == "apply" and item["request_key"] == "apply"
    )["undoable"]
    missing_version = {**manual, "attributions": [{**manual["attributions"][0], "reason": "Changed"}]}
    assert client.post("/api/v1/exposure/preview", json={"graph": missing_version}).status_code == 409
    response = client.post(
        "/api/v1/exposure/undo",
        json={
            "decision_id": saved["decision_id"],
            "request_key": "undo-manual",
            "reason": "Reviewed removal",
            "expected_revision": saved["revision"],
            "confirmed": True,
        },
    )
    assert response.status_code == 200, response.text
    row = next(
        row
        for row in client.get("/api/v1/exposure/report").json()["items"]
        if row["observation_id"] == str(ids[0])
    )
    assert row["attribution_status"] == "review_needed" and row["attribution_version"] == 2
    assert client.get("/api/v1/exposure/nodes").json()["total"] == 4


def test_unknown_and_future_source_times_keep_unknown_age_and_original_evidence(context: Any) -> None:
    client, db, _ = context
    ids = seed_observations(db)
    from vulnbatch.db.reconciliation import SourceInstance, SourceObservation

    source_id = db.scalar(select(SourceInstance.id))
    for number, meaning in enumerate(["source_observed", "unknown", "export_snapshot"]):
        db.add(
            SourceObservation(
                fingerprint=f"future-{number}".ljust(64, "x"),
                source_instance_id=source_id,
                kind="inventory",
                observed_at=datetime(2100, 1, 1, tzinfo=UTC),
                imported_at=datetime.now(UTC),
                parser_version="synthetic",
                normalized={"provenance": {"time_meaning": meaning}, "raw": {"clock": "future"}},
            )
        )
    db.commit()
    report = client.get("/api/v1/exposure/report").json()
    future = [row for row in report["items"] if row["evidence"].get("raw", {}).get("clock")]
    assert len(future) == 3 and all(row["age_days"] is None and row["time_warning"] for row in future)
    assert all(row["evidence"]["raw"] == {"clock": "future"} for row in future)
    known = next(row for row in report["items"] if row["observation_id"] == str(ids[0]))
    assert isinstance(known["age_days"], int)
    preview = client.post(
        "/api/v1/exposure/preview", json={"graph": graph(observed_at="2100-01-01T00:00:00Z")}
    ).json()
    assert any("future" in warning for warning in preview["warnings"])


def test_multiple_explicit_services_require_review_instead_of_arbitrary_choice(context: Any) -> None:
    client, db, _ = context
    ids = seed_observations(db)
    payload = graph(
        attributions=[
            {
                "observation_id": str(ids[0]),
                "node_ref": "ep",
                "status": "attributed",
                "reason": "Explicit endpoint",
            }
        ]
    )
    payload["nodes"].append(
        {"ref": "svc-two", "native_id": "svc-two", "kind": "service", "label": "Other service"}
    )
    payload["relationships"].append({"kind": "endpoint_of", "from_node": "ep", "to_node": "svc-two"})
    apply(client, payload)
    row = next(
        row
        for row in client.get("/api/v1/exposure/report").json()["items"]
        if row["observation_id"] == str(ids[0])
    )
    assert row["node_kind"] == "endpoint" and row["service_id"] is None
    assert row["attribution_status"] == "review_needed" and "multiple" in row["attribution_reason"]


def test_new_independent_references_block_original_undo_atomically(context: Any) -> None:
    client, db, _ = context
    ids = seed_observations(db)
    saved = apply(client)
    node = client.get("/api/v1/exposure/nodes").json()["items"][0]
    manual = {
        "source": "analyst",
        "instance": "review",
        "nodes": [],
        "relationships": [],
        "attributions": [
            {
                "observation_id": str(ids[0]),
                "node_ref": node["id"],
                "status": "attributed",
                "reason": "Later independent mapping",
            }
        ],
    }
    apply(client, manual, "later")
    before = client.get("/api/v1/exposure/nodes").json()
    response = client.post(
        "/api/v1/exposure/undo",
        json={
            "decision_id": saved["decision_id"],
            "request_key": "blocked",
            "reason": "Unsafe original undo",
            "expected_revision": 2,
            "confirmed": True,
        },
    )
    assert response.status_code == 409, response.text
    assert client.get("/api/v1/exposure/nodes").json() == before
    original = next(
        item
        for item in client.get("/api/v1/exposure/history").json()["items"]
        if item["decision_id"] == saved["decision_id"]
    )
    assert original["undoable"] is False and "later" in original["undo_block_reason"]


def test_device_management_and_zero_finding_coverage_do_not_claim_clean(context: Any) -> None:
    client, _, _ = context
    payload = graph(
        nodes=[
            {"ref": "device", "native_id": "device", "kind": "device", "label": "Appliance"},
            {
                "ref": "management",
                "native_id": "mgmt",
                "kind": "endpoint",
                "label": "Management",
                "port": 8443,
            },
        ],
        relationships=[{"kind": "management_of", "from_node": "management", "to_node": "device"}],
    )
    apply(client, payload)
    assert all(
        row["exposure_counts"] == {"inventory": 0, "vulnerability": 0, "coverage": 0}
        for row in client.get("/api/v1/exposure/nodes").json()["items"]
    )
    report = client.get("/api/v1/exposure/report").json()
    assert report["counts"] == {"inventory": 0, "vulnerability": 0, "coverage": 0} and report["total"] == 0


def test_source_native_id_kind_cannot_change_and_inactive_nodes_retain_facts(context: Any) -> None:
    client, _, _ = context
    apply(client)
    changed = graph()
    changed["nodes"][0].update(kind="device", expected_version=1)
    assert client.post("/api/v1/exposure/preview", json={"graph": changed}).status_code == 422
    history = client.get("/api/v1/exposure/history").json()["items"][0]
    node_id = next(c["entity_id"] for c in history["changes"] if c["entity_type"] == "node")
    client.post(
        "/api/v1/exposure/undo",
        json={
            "decision_id": history["decision_id"],
            "request_key": "undo-facts",
            "reason": "Reviewed undo",
            "expected_revision": 1,
            "confirmed": True,
        },
    )
    detail = client.get(f"/api/v1/exposure/nodes/{node_id}", params={"fact_limit": 1}).json()
    assert detail["node"]["active"] is False and detail["fact_total"] == 1 and len(detail["facts"]) == 1


def test_reference_alias_duplicate_edge_is_rejected_before_any_writes(context: Any) -> None:
    client, _, _ = context
    saved = apply(client)
    ids = {c["after"]["native_id"]: c["entity_id"] for c in saved["changes"] if c["entity_type"] == "node"}
    payload = graph()
    for node in payload["nodes"]:
        node["expected_version"] = 1
    payload["relationships"] = [
        {"kind": "endpoint_of", "from_node": "ep", "to_node": "svc", "expected_version": 1},
        {"kind": "endpoint_of", "from_node": ids["ep-1"], "to_node": ids["svc-1"], "expected_version": 1},
    ]
    for endpoint in ["preview", "apply"]:
        body = (
            {
                "graph": payload,
                "request_key": "alias-duplicate",
                "reason": "Synthetic duplicate",
                "expected_revision": 1,
                "confirmed": True,
            }
            if endpoint == "apply"
            else {"graph": payload}
        )
        response = client.post(f"/api/v1/exposure/{endpoint}", json=body)
        assert response.status_code == 422, response.text
    assert client.get("/api/v1/exposure/history").json()["total"] == 1
    assert all(node["version"] == 1 for node in client.get("/api/v1/exposure/nodes").json()["items"])


def test_stale_source_cannot_deactivate_rebind_or_remove_newer_relationship(context: Any) -> None:
    client, _, settings = context
    apply(client)
    older = graph(observed_at="2020-01-01T00:00:00Z")
    older["nodes"][0].update(active=False, asset_id=str(settings["asset_id"]))
    older["relationships"][1]["active"] = False
    saved = apply(client, older, "stale-connectivity")
    host = next(row for row in client.get("/api/v1/exposure/nodes").json()["items"] if row["kind"] == "host")
    assert host["active"] and host["asset_id"] is None
    assert client.get("/api/v1/exposure/graph").json()["relationship_total"] == 3
    changed_edge = next(
        c
        for c in saved["changes"]
        if c["entity_type"] == "relationship" and c["after"]["kind"] == "backed_by"
    )
    assert changed_edge["proposed"]["active"] is False and changed_edge["after"]["active"] is True


def test_explicit_manual_correction_can_rebind_without_changing_newer_facts(context: Any) -> None:
    client, _, settings = context
    apply(client)
    manual = graph(intent="manual_correction", time_meaning="unknown", observed_at=None, relationships=[])
    manual["nodes"] = [
        {**manual["nodes"][0], "asset_id": str(settings["asset_id"]), "label": "Unverified older label"}
    ]
    apply(client, manual, "reviewed-binding")
    host = next(row for row in client.get("/api/v1/exposure/nodes").json()["items"] if row["kind"] == "host")
    assert host["asset_id"] == str(settings["asset_id"]) and host["label"] == "Host"
    assert host["provenance"]["time_meaning"] == "source_observed"


def test_valid_fact_recovers_future_projection_and_future_fact_cannot_override_valid(context: Any) -> None:
    client, _, _ = context
    future = graph(observed_at="2126-10-01T00:00:00Z", relationships=[])
    future["nodes"] = [{**future["nodes"][0], "label": "Future clock"}]
    apply(client, future)
    first = client.get("/api/v1/exposure/nodes").json()["items"][0]
    assert first["provenance"]["time_warning"] and first["fact_summary"]["latest_observed_at"] is None
    valid = graph(relationships=[], nodes=[graph()["nodes"][0]])
    apply(client, valid, "valid-clock")
    corrected = client.get("/api/v1/exposure/nodes").json()["items"][0]
    assert corrected["label"] == "Host" and corrected["provenance"]["time_warning"] is None
    future["nodes"][0]["expected_version"] = 2
    apply(client, future, "later-future-clock")
    retained = client.get("/api/v1/exposure/nodes").json()["items"][0]
    assert retained["label"] == "Host" and retained["fact_summary"]["fact_count"] == 3
    detail = client.get(f"/api/v1/exposure/nodes/{retained['id']}").json()
    assert sum(fact["provenance"]["time_warning"] is not None for fact in detail["facts"]) == 2


def test_stale_discarded_targets_do_not_block_historical_evidence(context: Any) -> None:
    client, db, settings = context
    ids = seed_observations(db)
    initial = graph(
        nodes=[graph()["nodes"][0], graph()["nodes"][1]],
        relationships=[{"kind": "backed_by", "from_node": "svc", "to_node": "host"}],
        attributions=[
            {
                "observation_id": str(ids[0]),
                "node_ref": "host",
                "status": "attributed",
                "reason": "Original mapping",
            }
        ],
    )
    apply(client, initial)
    deactivated = {
        **initial,
        "intent": "manual_correction",
        "observed_at": "2026-10-02T00:00:00Z",
        "nodes": [{**initial["nodes"][0], "active": False}, initial["nodes"][1]],
        "relationships": [{**initial["relationships"][0], "active": False}],
        "attributions": [
            {"observation_id": str(ids[0]), "status": "review_needed", "reason": "Removed obsolete mapping"}
        ],
    }
    apply(client, deactivated, "deactivate")
    retired = db.get(Asset, settings["asset_id"])
    assert retired is not None
    retired.active = False
    db.commit()
    stale = {
        **initial,
        "observed_at": "2020-01-01T00:00:00Z",
        "nodes": [
            {**initial["nodes"][0], "expected_version": 2, "asset_id": str(retired.id)},
            {**initial["nodes"][1], "expected_version": 2},
        ],
        "relationships": [{**initial["relationships"][0], "expected_version": 2}],
        "attributions": [{**initial["attributions"][0], "expected_version": 2}],
    }
    response = client.post(
        "/api/v1/exposure/apply",
        json={
            "graph": stale,
            "request_key": "stale-old-targets",
            "reason": "Preserve original export as evidence",
            "expected_revision": 2,
            "confirmed": True,
        },
    )
    assert response.status_code == 200, response.text
    assert client.get("/api/v1/exposure/nodes").json()["total"] == 1
    assert client.get("/api/v1/exposure/graph").json()["relationship_total"] == 0
    finding = next(
        row
        for row in client.get("/api/v1/exposure/report").json()["items"]
        if row["observation_id"] == str(ids[0])
    )
    assert finding["attribution_status"] == "review_needed" and finding["node_id"] is None


def test_older_source_cannot_undo_unknown_time_manual_mapping_review(context: Any) -> None:
    client, db, _ = context
    ids = seed_observations(db)
    apply(
        client,
        graph(
            attributions=[
                {
                    "observation_id": str(ids[0]),
                    "node_ref": "vip",
                    "status": "attributed",
                    "reason": "Original dated source mapping",
                }
            ]
        ),
    )
    endpoint = next(
        row for row in client.get("/api/v1/exposure/nodes").json()["items"] if row["kind"] == "endpoint"
    )
    vip = next(row for row in client.get("/api/v1/exposure/nodes").json()["items"] if row["kind"] == "vip")
    manual = {
        "intent": "manual_correction",
        "source": "analyst",
        "instance": "review",
        "nodes": [],
        "relationships": [],
        "attributions": [
            {
                "observation_id": str(ids[0]),
                "node_ref": endpoint["id"],
                "status": "attributed",
                "reason": "Reviewed explicit endpoint mapping",
                "expected_version": 1,
            }
        ],
    }
    apply(client, manual, "manual-mapping")
    stale = {
        "source": "synthetic_inventory",
        "instance": "lab-a",
        "time_meaning": "source_observed",
        "observed_at": "2020-01-01T00:00:00Z",
        "nodes": [],
        "relationships": [],
        "attributions": [
            {
                "observation_id": str(ids[0]),
                "node_ref": vip["id"],
                "status": "attributed",
                "reason": "Old source mapping",
                "expected_version": 2,
            }
        ],
    }
    apply(client, stale, "older-than-review")
    row = next(
        row
        for row in client.get("/api/v1/exposure/report").json()["items"]
        if row["observation_id"] == str(ids[0])
    )
    assert row["node_id"] == endpoint["id"] and row["attribution_version"] == 3
    assert row["attribution_reason"] == "Reviewed explicit endpoint mapping"


def test_signed_preview_freezes_source_clock_classification_while_import_time_advances(
    context: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vulnbatch.api.routes import exposure
    from vulnbatch.db.exposure import ExposureDecision, ExposureNodeFact

    client, db, _ = context
    evaluated_at = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(exposure, "utcnow", lambda: evaluated_at)
    baseline = graph(
        nodes=[graph()["nodes"][0]],
        relationships=[],
        observed_at=(evaluated_at - timedelta(minutes=1)).isoformat(),
    )
    apply(client, baseline)
    incoming = graph(
        nodes=[{**graph()["nodes"][0], "label": "Crossed clock boundary", "expected_version": 1}],
        relationships=[],
        observed_at=(evaluated_at + timedelta(seconds=2)).isoformat(),
    )
    preview = client.post("/api/v1/exposure/preview", json={"graph": incoming})
    assert preview.status_code == 200, preview.text
    reviewed = preview.json()
    assert reviewed["changes"][0]["after"]["label"] == "Host"
    assert any("future" in warning for warning in reviewed["warnings"])
    imported_at = evaluated_at + timedelta(seconds=3)
    monkeypatch.setattr(exposure, "utcnow", lambda: imported_at)
    response = client.post(
        "/api/v1/exposure/apply",
        json={
            "graph": incoming,
            "request_key": "crossed-preview",
            "reason": "Apply exactly the reviewed source-clock classification",
            "expected_revision": reviewed["revision"],
            "preview_token": reviewed["preview_token"],
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["changes"][0]["after"]["label"] == "Host"
    proposed_provenance = result["changes"][0]["proposed"]["provenance"]
    assert proposed_provenance["evaluated_at"] == evaluated_at.isoformat()
    assert proposed_provenance["imported_at"] == imported_at.isoformat()
    assert (
        proposed_provenance["time_warning"]
        == reviewed["changes"][0]["proposed"]["provenance"]["time_warning"]
    )
    decision = db.get(ExposureDecision, uuid.UUID(result["decision_id"]))
    assert decision is not None
    assert decision.occurred_at.replace(tzinfo=UTC) == imported_at
    fact = db.scalar(select(ExposureNodeFact).where(ExposureNodeFact.decision_id == decision.id))
    assert (
        fact is not None and fact.observed_at is None and fact.imported_at.replace(tzinfo=UTC) == imported_at
    )
    incoming["nodes"][0]["expected_version"] = 2
    fresh = client.post("/api/v1/exposure/preview", json={"graph": incoming}).json()
    assert fresh["changes"][0]["after"]["label"] == "Crossed clock boundary"
    assert not any("future" in warning for warning in fresh["warnings"])
    later_imported_at = imported_at + timedelta(seconds=1)
    monkeypatch.setattr(exposure, "utcnow", lambda: later_imported_at)
    accepted = client.post(
        "/api/v1/exposure/apply",
        json={
            "graph": incoming,
            "request_key": "fresh-preview",
            "reason": "Reviewed source time is now credible",
            "expected_revision": fresh["revision"],
            "preview_token": fresh["preview_token"],
        },
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["changes"][0]["after"]["label"] == "Crossed clock boundary"
    node = client.get("/api/v1/exposure/nodes").json()["items"][0]
    assert node["provenance"]["evaluated_at"] == imported_at.isoformat()
    assert node["provenance"]["imported_at"] == later_imported_at.isoformat()
