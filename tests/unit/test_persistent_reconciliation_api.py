from __future__ import annotations

import importlib
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from vulnbatch.core.security import csrf_token_for_session
from vulnbatch.db.base import Base
from vulnbatch.db.models import Asset, AssetIdentifier, Role, User


@pytest.mark.parametrize("field", ["request_key", "reason"])
def test_decision_sql_text_rejects_nul(field: str) -> None:
    from pydantic import ValidationError

    from vulnbatch.schemas.reconciliation import DecisionRequest

    payload = {"request_key": "synthetic", "reason": "Reviewed", "action": "reject", "expected_revision": 0}
    payload[field] = "synthetic\x00text"
    with pytest.raises(ValidationError, match="NUL"):
        DecisionRequest.model_validate(payload)


def test_asset_search_rejects_nul(context: tuple[TestClient, Session, dict[str, str]]) -> None:
    client, _, _ = context
    assert client.get("/api/v1/reconciliation/assets", params={"q": "synthetic\x00"}).status_code == 422


def test_evidence_returns_assigned_asset_name_and_unnamed_choices_are_readable(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, _, _ = context
    save(client, rows=[{"native_id": "named", "hostname": "named.example.test"}, {"native_id": "unnamed"}])
    page = client.get("/api/v1/reconciliation/observations").json()
    named = next(item for item in page["items"] if item["observation"]["asset"]["fqdn"])
    assert named["asset_name"] == "named.example.test"
    detail = client.get(f"/api/v1/reconciliation/observations/{named['id']}").json()
    assert detail["asset_name"] == "named.example.test"
    choices = client.get("/api/v1/reconciliation/assets").json()["items"]
    assert all(isinstance(choice["display_name"], str) and choice["display_name"] for choice in choices)
    assert any(choice["canonical_hostname"] is None for choice in choices)


@pytest.fixture
def context(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, Session, dict[str, str]]]:
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("SECRET_KEY", "synthetic-unused-test-secret-0000000000000000")
    from vulnbatch.core.config import get_settings

    get_settings.cache_clear()
    from vulnbatch.api.deps import Principal, get_current_principal
    from vulnbatch.api.routes import identity, reconciliation
    from vulnbatch.db.session import get_db

    try:
        routes = importlib.import_module("vulnbatch.api.routes.reconciliation_storage")
    except ModuleNotFoundError:
        pytest.fail("Persistent reconciliation API is not implemented")
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        role = Role(name="administrator")
        db.add(role)
        db.flush()
        user = User(
            username="synthetic", display_name="Synthetic", password_hash=token_urlsafe(16), role_id=role.id
        )
        db.add(user)
        db.commit()
        settings = {"role": "administrator"}
        token = token_urlsafe(32)
        app = FastAPI()
        app.include_router(routes.router)
        app.include_router(reconciliation.router)
        app.include_router(identity.router)
        app.dependency_overrides[get_current_principal] = lambda: cast(
            Principal,
            SimpleNamespace(
                user=SimpleNamespace(id=user.id, role=SimpleNamespace(name=settings["role"])),
                raw_session_token=token,
            ),
        )
        app.dependency_overrides[get_db] = lambda: db
        with TestClient(app) as client:
            client.headers["X-CSRF-Token"] = csrf_token_for_session(token)
            yield client, db, settings
    engine.dispose()


def save(
    client: TestClient, key: str = "synthetic-import", rows: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/reconciliation/imports",
        data={
            "request_key": key,
            "options_json": json.dumps(
                [
                    {
                        "source": "inventory",
                        "instance": "synthetic",
                        "format": "json",
                        "time_meaning": "source_observed",
                    }
                ]
            ),
        },
        files=[
            (
                "uploads",
                (
                    "synthetic.json",
                    json.dumps(
                        rows or [{"native_id": "one", "observed_at": "2026-10-01T10:00:00Z"}]
                    ).encode(),
                ),
            )
        ],
    )
    assert response.status_code == 200, response.text
    return response.json()


def preview_rows(client: TestClient, rows: list[dict[str, Any]]) -> dict[str, Any]:
    response = client.post(
        "/api/v1/reconciliation/preview",
        data={
            "options_json": json.dumps(
                [
                    {
                        "source": "inventory",
                        "instance": "synthetic",
                        "format": "json",
                        "time_meaning": "source_observed",
                    }
                ]
            )
        },
        files=[("uploads", ("synthetic.json", json.dumps(rows).encode()))],
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_unnamed_assets_can_be_browsed_and_found_by_uuid_or_fallback_label(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, _, _ = context
    save(client, rows=[{"native_id": "unnamed-a"}, {"native_id": "unnamed-b"}])
    first = client.get("/api/v1/reconciliation/assets", params={"limit": 1}).json()
    second = client.get("/api/v1/reconciliation/assets", params={"limit": 1, "offset": 1}).json()
    assert first["total"] == 2 and len(first["items"]) == len(second["items"]) == 1
    assert first["items"][0]["id"] != second["items"][0]["id"]
    for asset in first["items"] + second["items"]:
        for query in (asset["id"], asset["id"][:8], asset["display_name"]):
            matches = client.get("/api/v1/reconciliation/assets", params={"q": query}).json()["items"]
            assert any(item["id"] == asset["id"] for item in matches), query


def test_preview_and_save_exclude_unscoped_legacy_hardware_identifiers(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, db, _ = context
    hardware = "00000000-0000-0000-0000-000000000001"
    now = datetime.now(UTC)
    legacy = Asset(canonical_hostname="legacy.example.test")
    db.add(legacy)
    db.flush()
    db.add(
        AssetIdentifier(
            asset_id=legacy.id,
            identifier_type="hardware_uuid",
            normalized_value=hardware,
            original_value=hardware,
            first_observed_at=now,
            last_observed_at=now,
        )
    )
    db.commit()
    rows = [{"hardware_uuid": hardware, "observed_at": now.isoformat()}]
    preview = preview_rows(client, rows)
    assert preview["items"][0]["decision"]["action"] == "create"
    saved = save(client, rows=rows)
    assert saved["new_observations"] == saved["assigned_rows"] == 1
    actual = client.get("/api/v1/reconciliation/observations").json()["items"][0]
    assert actual["rule"] == preview["items"][0]["decision"]["rule"] == "no_safe_match"
    assert actual["asset_id"] != str(legacy.id)


def test_preview_reuses_durable_history_and_retains_rejected_duplicates(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, _, _ = context
    now = datetime.now(UTC).isoformat()
    original = [
        {"native_id": "agent-a", "hardware_uuid": "00000000-0000-0000-0000-000000000001", "observed_at": now}
    ]
    save(client, rows=original)
    changed = [{**original[0], "note": "later export"}]
    proposed = preview_rows(client, changed)
    assert proposed["action_counts"] == {"match": 1}
    saved = save(client, "later", changed)
    assert saved["assigned_rows"] == 1 and saved["review_rows"] == 0
    page = client.get("/api/v1/reconciliation/observations").json()
    selected = next(item for item in page["items"] if item["observation"]["raw"].get("note"))
    rejected = client.post(
        "/api/v1/reconciliation/decisions",
        json={
            "request_key": "reject-one",
            "expected_revision": page["revision"],
            "action": "reject",
            "reason": "Synthetic rejected evidence",
            "observation_ids": [selected["id"]],
            "expected_versions": {selected["id"]: selected["version"]},
        },
    )
    assert rejected.status_code == 200, rejected.text
    retained = preview_rows(client, changed)
    assert retained["action_counts"] == {"retain": 1}
    assert retained["items"][0]["current_assignment"]["review_status"] == "rejected"
    assert retained["duplicate_rows"] == 1
    repeated = save(client, "repeat-rejected", changed)
    assert repeated["new_observations"] == repeated["assigned_rows"] == repeated["review_rows"] == 0


def test_save_rejects_stale_preview_revision_without_writes(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, _, _ = context
    proposed = preview_rows(client, [{"native_id": "pending"}])
    assert proposed["revision"] == 0
    save(client)
    response = client.post(
        "/api/v1/reconciliation/imports",
        data={
            "request_key": "stale-preview",
            "expected_revision": proposed["revision"],
            "options_json": json.dumps([{"source": "inventory", "instance": "synthetic", "format": "json"}]),
        },
        files=[("uploads", ("synthetic.json", b'[{"native_id":"pending"}]'))],
    )
    assert response.status_code == 409, response.text
    assert client.get("/api/v1/reconciliation/observations").json()["total"] == 1


def test_preview_keeps_historical_conflicts_and_excludes_rejected_repeat_evidence(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, _, _ = context
    original = {
        "native_id": "cloned",
        "hardware_uuid": "00000000-0000-0000-0000-000000000001",
        "observed_at": datetime.now(UTC).isoformat(),
    }
    clone = {**original, "hardware_uuid": "00000000-0000-0000-0000-000000000002"}
    save(client, rows=[original])
    assert save(client, "clone", [clone])["review_rows"] == 1
    fresh = {**original, "note": "fresh"}
    proposed = preview_rows(client, [fresh])
    assert proposed["action_counts"] == {"review": 1}
    assert proposed["items"][0]["decision"]["rule"] == "conflicting_ids_within_bundle"
    page = client.get("/api/v1/reconciliation/observations").json()
    rejected = next(item for item in page["items"] if item["review_status"] == "open")
    response = client.post(
        "/api/v1/reconciliation/decisions",
        json={
            "request_key": "reject-clone",
            "expected_revision": page["revision"],
            "action": "reject",
            "reason": "Synthetic cloned agent",
            "observation_ids": [rejected["id"]],
            "expected_versions": {rejected["id"]: rejected["version"]},
        },
    )
    assert response.status_code == 200, response.text
    proposed = preview_rows(client, [clone, fresh])
    assert proposed["action_counts"] == {"retain": 1, "match": 1}
    saved = save(client, "after-rejection", [clone, fresh])
    assert saved["duplicate_rows"] == saved["new_observations"] == saved["assigned_rows"] == 1
    assert saved["review_rows"] == 0


def test_signed_preview_freezes_matching_time_and_completed_replay_survives_expiry(
    context: tuple[TestClient, Session, dict[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vulnbatch.api.routes import reconciliation, reconciliation_storage

    client, _, _ = context
    now = datetime.now(UTC)
    monkeypatch.setattr(reconciliation, "utcnow", lambda: now)
    monkeypatch.setattr(reconciliation_storage, "utcnow", lambda: now)
    original = {
        "native_id": "boundary",
        "observed_at": (now - timedelta(days=90) + timedelta(seconds=1)).isoformat(),
    }
    save(client, rows=[original])
    rows = [{**original, "note": "new"}]
    proposed = preview_rows(client, rows)
    assert proposed["action_counts"] == {"match": 1}
    assert proposed["preview_token"]
    options = [
        {"source": "inventory", "instance": "synthetic", "format": "json", "time_meaning": "source_observed"}
    ]
    data = {
        "request_key": "frozen-time",
        "options_json": json.dumps(options),
        "expected_revision": proposed["revision"],
        "preview_token": proposed["preview_token"],
    }
    monkeypatch.setattr(reconciliation_storage, "utcnow", lambda: now + timedelta(seconds=2))
    response = client.post(
        "/api/v1/reconciliation/imports",
        data=data,
        files=[("uploads", ("synthetic.json", json.dumps(rows).encode()))],
    )
    assert response.status_code == 200, response.text
    assert response.json()["assigned_rows"] == 1 and response.json()["review_rows"] == 0
    monkeypatch.setattr(reconciliation_storage, "utcnow", lambda: now + timedelta(hours=1))
    replay = client.post(
        "/api/v1/reconciliation/imports",
        data=data,
        files=[("uploads", ("synthetic.json", json.dumps(rows).encode()))],
    )
    assert replay.status_code == 200 and replay.json()["replayed"] is True


@pytest.mark.parametrize("change", ["payload", "token", "expired", "unicode"])
def test_preview_context_rejects_changes_before_writing(
    context: tuple[TestClient, Session, dict[str, str]],
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    from vulnbatch.api.routes import reconciliation_storage

    client, _, _ = context
    rows = [{"native_id": "pending"}]
    proposed = preview_rows(client, rows)
    assert proposed["preview_token"]
    if change == "payload":
        rows[0]["native_id"] = "different"
    if change == "expired":
        now = datetime.now(UTC) + timedelta(hours=1)
        monkeypatch.setattr(reconciliation_storage, "utcnow", lambda: now)
    token = proposed["preview_token"] + "invalid" if change == "token" else proposed["preview_token"]
    if change == "unicode":
        token = token.rsplit(".", 1)[0] + ".é"
    response = client.post(
        "/api/v1/reconciliation/imports",
        data={
            "request_key": "invalid-context",
            "preview_token": token,
            "options_json": json.dumps(
                [
                    {
                        "source": "inventory",
                        "instance": "synthetic",
                        "format": "json",
                        "time_meaning": "source_observed",
                    }
                ]
            ),
        },
        files=[("uploads", ("synthetic.json", json.dumps(rows).encode()))],
    )
    assert response.status_code == 409, response.text
    assert client.get("/api/v1/reconciliation/observations").json()["total"] == 0


def test_empty_hostname_fallback_label_can_be_searched(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, db, _ = context
    asset = Asset(canonical_hostname="")
    db.add(asset)
    db.commit()
    choice = client.get("/api/v1/reconciliation/assets").json()["items"][0]
    found = client.get("/api/v1/reconciliation/assets", params={"q": choice["display_name"]}).json()["items"]
    assert any(item["id"] == str(asset.id) for item in found)


def test_legacy_csv_import_invalidates_preview(
    context: tuple[TestClient, Session, dict[str, str]],
    tmp_path: Any,
) -> None:
    import hashlib

    from vulnbatch.db.models import ImportRun, Job, SourceFile
    from vulnbatch.imports.processor import process_import_job

    client, db, _ = context
    pending = [{"native_id": "pending", "hostname": "late.example.test"}]
    proposed = preview_rows(client, pending)
    assert proposed["action_counts"] == {"create": 1}
    content = b"Plugin ID,Host,Risk,Port,Protocol\n100,late.example.test,Medium,0,tcp\n"
    path = tmp_path / "synthetic.csv"
    path.write_bytes(content)
    actor = db.scalar(select(User.id))
    source = SourceFile(
        sha256=hashlib.sha256(content).hexdigest(),
        original_filename="synthetic.csv",
        source_type="tenable_csv",
        byte_size=len(content),
        storage_path=str(path),
        uploaded_by_id=actor,
    )
    db.add(source)
    db.flush()
    run = ImportRun(source_file_id=source.id, importing_user_id=actor, source_type="tenable_csv")
    db.add(run)
    db.flush()
    job = Job(job_type="import", payload={"import_id": str(run.id)})
    db.add(job)
    db.commit()
    process_import_job(db, job)
    db.commit()
    assert run.status == "completed" and run.new_assets == 1
    assert preview_rows(client, pending)["action_counts"] == {"review": 1}
    response = client.post(
        "/api/v1/reconciliation/imports",
        data={
            "request_key": "before-legacy",
            "preview_token": proposed["preview_token"],
            "options_json": json.dumps(
                [
                    {
                        "source": "inventory",
                        "instance": "synthetic",
                        "format": "json",
                        "time_meaning": "source_observed",
                    }
                ]
            ),
        },
        files=[("uploads", ("synthetic.json", json.dumps(pending).encode()))],
    )
    assert response.status_code == 409, response.text
    assert client.get("/api/v1/reconciliation/observations").json()["total"] == 0


@pytest.mark.parametrize("action", ["move", "split", "mark-shared"])
def test_legacy_alias_edits_invalidate_preview(
    context: tuple[TestClient, Session, dict[str, str]],
    action: str,
) -> None:
    client, db, _ = context
    source, target = (
        Asset(canonical_hostname="source.example.test"),
        Asset(canonical_hostname="target.example.test"),
    )
    db.add_all([source, target])
    db.flush()
    now = datetime.now(UTC)
    identifier = AssetIdentifier(
        asset_id=source.id,
        identifier_type="ipv4",
        normalized_value="192.0.2.45",
        original_value="192.0.2.45",
        first_observed_at=now,
        last_observed_at=now,
    )
    db.add(identifier)
    db.commit()
    proposed = preview_rows(client, [{"native_id": "pending"}])
    payload = {"reason": "Synthetic alias edit"}
    if action == "move":
        payload["target_asset_id"] = str(target.id)
    if action == "split":
        payload["canonical_hostname"] = "split.example.test"
    changed = client.post(f"/api/v1/identity/identifiers/{identifier.id}/{action}", json=payload)
    assert changed.status_code == 200, changed.text
    assert client.get("/api/v1/reconciliation/observations").json()["revision"] == proposed["revision"] + 1


def test_nessus_expanded_raw_evidence_is_bounded_before_any_writes(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, _, _ = context
    content = (
        '<NessusClientData_v2><Report><ReportHost name="synthetic.example.test"><HostProperties>'
        '<tag name="custom">'
        + "x" * 65536
        + "</tag></HostProperties>"
        + '<ReportItem pluginID="100" severity="2"/>' * 1100
        + "</ReportHost></Report></NessusClientData_v2>"
    ).encode()
    options = json.dumps([{"source": "nessus", "instance": "synthetic", "format": "nessus_xml"}])
    for endpoint in ("preview", "imports"):
        response = client.post(
            f"/api/v1/reconciliation/{endpoint}",
            data={"request_key": "expanded", "options_json": options},
            files=[("uploads", ("synthetic.nessus", content))],
        )
        assert response.status_code == 422, response.text[:1000]
        assert "expanded evidence" in response.json()["detail"].lower()
        assert client.get("/api/v1/reconciliation/observations").json()["total"] == 0


def test_persistent_writes_require_admin_and_csrf(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, _, settings = context
    for endpoint in ("imports", "decisions"):
        settings["role"] = "read_only"
        assert client.post(f"/api/v1/reconciliation/{endpoint}").status_code == 403
        settings["role"] = "administrator"
        csrf = client.headers.pop("X-CSRF-Token")
        assert client.post(f"/api/v1/reconciliation/{endpoint}").status_code == 403
        client.headers["X-CSRF-Token"] = csrf


def test_readonly_can_read_bounded_evidence_and_audit(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, _, settings = context
    save(client)
    settings["role"] = "read_only"
    response = client.get("/api/v1/reconciliation/observations?limit=1")
    assert response.status_code == 200
    result = response.json()
    assert result["total"] == 1 and result["revision"] == 1
    assert client.get("/api/v1/reconciliation/observations?limit=501").status_code == 422
    detail = client.get(f"/api/v1/reconciliation/observations/{result['items'][0]['id']}")
    assert detail.status_code == 200 and detail.json()["locator_total"] == 1
    decisions = client.get("/api/v1/reconciliation/decisions").json()
    assert decisions["items"][0]["action"] == "import"
    assert client.get("/api/v1/reconciliation/assets?q=missing").json()["items"] == []


def test_persistent_reads_require_authentication(context: tuple[TestClient, Session, dict[str, str]]) -> None:
    client, _, _ = context
    from vulnbatch.api.deps import get_current_principal

    client.app.dependency_overrides.pop(get_current_principal)
    for endpoint in ("observations", "decisions", "assets"):
        assert client.get(f"/api/v1/reconciliation/{endpoint}").status_code == 401


def test_bad_rows_are_counted_and_supported_later_rows_persist(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, _, _ = context
    result = save(
        client,
        rows=[
            {"kind": "vulnerability", "native_id": "bad", "cves": {"id": "CVE-invalid"}},
            {"native_id": "good"},
        ],
    )
    assert result["error_rows"] == 1 and result["new_observations"] == 1
    assert "cves" in result["errors"][0]["error"]
    assert client.get("/api/v1/reconciliation/observations").json()["total"] == 1


def test_api_decisions_return_409_for_stale_revision_and_replay_safely(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, _, _ = context
    save(client)
    item = client.get("/api/v1/reconciliation/observations").json()["items"][0]
    payload = {
        "request_key": "reject",
        "expected_revision": 1,
        "reason": "Reviewed synthetic row",
        "action": "reject",
        "observation_ids": [item["id"]],
        "expected_versions": {item["id"]: 1},
    }
    first = client.post("/api/v1/reconciliation/decisions", json=payload)
    assert first.status_code == 200, first.text
    replay = client.post("/api/v1/reconciliation/decisions", json=payload)
    assert replay.status_code == 200 and replay.json()["replayed"]
    assert (
        client.post("/api/v1/reconciliation/decisions", json={**payload, "request_key": "stale"}).status_code
        == 409
    )
    assert client.get("/api/v1/reconciliation/observations").json()["items"][0]["version"] == 2


def test_read_revision_precedes_page_queries(
    context: tuple[TestClient, Session, dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, db, _ = context
    save(client)
    from vulnbatch.db.reconciliation import ReconciliationState
    from vulnbatch.reconciliation import queries

    trace: list[str] = []

    def executed(state: Any) -> None:
        if "source_observations" in str(state.statement):
            trace.append("page")

    event.listen(db, "do_orm_execute", executed)

    def concurrent_change(session: Session) -> int:
        trace.append("revision")
        captured = session.scalar(select(ReconciliationState.revision))
        state = session.get(ReconciliationState, 1)
        assert state is not None
        state.revision += 1
        session.flush()
        assert captured is not None
        return captured

    monkeypatch.setattr(queries, "revision", concurrent_change)
    response = client.get("/api/v1/reconciliation/observations").json()
    assert response["revision"] == 1
    assert trace[0] == "revision"
    assert db.scalar(select(ReconciliationState.revision)) == 2


def test_incompatible_import_configuration_has_no_side_effects(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, db, _ = context
    response = client.post(
        "/api/v1/reconciliation/imports",
        data={
            "request_key": "bad-options",
            "options_json": '[{"source":"inventory","instance":"synthetic",'
            '"format":"csv","records_path":"items"}]',
        },
        files=[("uploads", ("synthetic.csv", b"native_id\none\n"))],
    )
    assert response.status_code == 422
    assert client.get("/api/v1/reconciliation/observations").json()["total"] == 0
    assert db.scalars(select(Asset)).all() == []


def test_legacy_merge_cannot_retire_asset_with_persistent_evidence(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, db, _ = context
    save(client)
    item = client.get("/api/v1/reconciliation/observations").json()["items"][0]
    target = Asset(canonical_hostname="target.example.test")
    db.add(target)
    db.commit()
    response = client.post(
        "/api/v1/identity/merge",
        json={
            "source_asset_id": item["asset_id"],
            "target_asset_id": str(target.id),
            "reason": "Synthetic legacy merge",
        },
    )
    assert response.status_code == 409, response.text
    source = db.get(Asset, uuid.UUID(item["asset_id"]))
    assert source is not None and source.active and source.merged_into_id is None


def test_legacy_split_undo_cannot_retire_created_asset_with_persistent_evidence(
    context: tuple[TestClient, Session, dict[str, str]],
) -> None:
    client, db, _ = context
    original = Asset(canonical_hostname="original.example.test")
    db.add(original)
    db.flush()
    identifier = AssetIdentifier(
        asset_id=original.id,
        identifier_type="fqdn",
        normalized_value="alias.example.test",
        original_value="alias.example.test",
        first_observed_at=datetime(2026, 10, 1, tzinfo=UTC),
        last_observed_at=datetime(2026, 10, 1, tzinfo=UTC),
    )
    db.add(identifier)
    db.commit()
    split = client.post(
        f"/api/v1/identity/identifiers/{identifier.id}/split", json={"reason": "Synthetic legacy split"}
    )
    assert split.status_code == 200, split.text
    from vulnbatch.db.models import IdentityEvent

    event = db.scalar(select(IdentityEvent).where(IdentityEvent.event_type == "split_identifier"))
    assert event is not None
    save(client, rows=[{"hostname": "alias.example.test"}])
    page = client.get("/api/v1/reconciliation/observations").json()
    item = page["items"][0]
    assert item["asset_id"] is None
    assigned = client.post(
        "/api/v1/reconciliation/decisions",
        json={
            "request_key": "link-to-split",
            "expected_revision": page["revision"],
            "reason": "Reviewed synthetic alias",
            "action": "assign",
            "target_asset_id": str(event.primary_asset_id),
            "observation_ids": [item["id"]],
            "expected_versions": {item["id"]: 1},
        },
    )
    assert assigned.status_code == 200, assigned.text
    response = client.post(f"/api/v1/identity/events/{event.id}/undo", json={"reason": "Unsafe split undo"})
    assert response.status_code == 409, response.text
