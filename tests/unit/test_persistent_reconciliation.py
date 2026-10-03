from __future__ import annotations

import importlib
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from types import ModuleType
from typing import Any

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from vulnbatch.db.base import Base
from vulnbatch.db.models import Asset, Role, User
from vulnbatch.reconciliation.models import SourceOptions

NOW = datetime(2026, 10, 2, tzinfo=UTC)


def module(name: str) -> ModuleType:
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        pytest.fail(f"Persistent reconciliation is not implemented: {name}")


@pytest.fixture
def database() -> Iterator[tuple[Session, uuid.UUID]]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        role = Role(name="administrator")
        db.add(role)
        db.flush()
        user = User(
            username="synthetic-admin",
            display_name="Synthetic admin",
            password_hash=str(uuid.uuid4()),
            role_id=role.id,
        )
        db.add(user)
        db.commit()
        yield db, user.id
    engine.dispose()


def row(native: str = "agent-a", **extra: Any) -> dict[str, Any]:
    return {
        "native_id": native,
        "hostname": f"{native}.example.test",
        "observed_at": "2026-10-01T10:00:00Z",
        **extra,
    }


def ingest(
    db: Session, actor: uuid.UUID, rows: list[dict[str, Any]], key: str = "first", **options: Any
) -> dict[str, Any]:
    storage = module("vulnbatch.reconciliation.storage")
    document = storage.ImportDocument(
        filename="synthetic.json",
        content=json.dumps(rows).encode(),
        options=SourceOptions.model_validate(
            {
                "source": "crowdstrike",
                "instance": "synthetic-a",
                "format": "json",
                "time_meaning": "source_observed",
                **options,
            }
        ),
    )
    result = storage.persist_bundle(db, [document], actor_id=actor, request_key=key, now=NOW)
    db.commit()
    return result


def current(db: Session, **filters: Any) -> dict[str, Any]:
    return module("vulnbatch.reconciliation.queries").observations(db, **filters)


def test_import_key_replay_does_not_reparse_immutable_completed_batch(
    database: tuple[Session, uuid.UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    db, actor = database
    original = ingest(db, actor, [row()])

    def parser_changed(*_: Any) -> Any:
        raise ValueError("Synthetic parser upgrade")

    monkeypatch.setattr(module("vulnbatch.reconciliation.storage"), "_parsed", parser_changed)
    replay = ingest(db, actor, [row()])
    assert replay["replayed"] is True and replay["id"] == original["id"]


def decide(
    db: Session, actor: uuid.UUID, action: str, selected: list[dict[str, Any]], key: str, **extra: Any
) -> dict[str, Any]:
    schema = module("vulnbatch.schemas.reconciliation")
    payload = schema.DecisionRequest.model_validate(
        {
            "action": action,
            "request_key": key,
            "reason": "Reviewed synthetic evidence",
            "expected_revision": current(db)["revision"],
            "observation_ids": [item["id"] for item in selected],
            "expected_versions": {item["id"]: item["version"] for item in selected},
            **extra,
        }
    )
    result = module("vulnbatch.reconciliation.decisions").apply_decision(db, payload, actor_id=actor, now=NOW)
    db.commit()
    return result


def test_repeat_exports_keep_locators_but_not_duplicate_observations(
    database: tuple[Session, uuid.UUID],
) -> None:
    db, actor = database
    first = ingest(db, actor, [row(), row()])
    assert first["new_observations"] == 1 and first["duplicate_rows"] == 1
    replay = ingest(db, actor, [row(), row()])
    assert replay["id"] == first["id"] and replay["replayed"] is True
    assert replay["revision"] == first["revision"]
    repeated = ingest(db, actor, [row()], key="another-export")
    assert repeated["new_observations"] == 0 and repeated["duplicate_rows"] == 1
    item = current(db)["items"][0]
    detail = module("vulnbatch.reconciliation.queries").observation_detail(db, uuid.UUID(item["id"]))
    assert detail["locator_total"] == 3
    assert detail["history_total"] == 1
    assert item["observation"]["observed_at"] == "2026-10-01T10:00:00Z"
    assert len(db.scalars(select(Asset)).all()) == 1


def test_changed_payload_cannot_reuse_request_key(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    ingest(db, actor, [row()])
    with pytest.raises(ValueError, match="request key"):
        ingest(db, actor, [row("agent-b")])
    db.rollback()
    assert current(db)["total"] == 1


def test_fresh_native_history_matches_but_scopes_do_not_collide(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    ingest(db, actor, [row()])
    target = current(db)["items"][0]["asset_id"]
    result = ingest(db, actor, [row(observed_at="2026-10-01T11:00:00Z")], key="fresh")
    assert result["assigned_rows"] == 1
    assert {item["asset_id"] for item in current(db)["items"]} == {target}
    ingest(db, actor, [row(hostname="other.example.test")], key="other-scope", instance="synthetic-b")
    assert len({item["asset_id"] for item in current(db)["items"]}) == 2


@pytest.mark.parametrize(
    "changed",
    [
        {"observed_at": None},
        {"observed_at": "2025-01-01T00:00:00Z"},
        {"native_id": "agent-b", "ip": "192.0.2.10"},
        {"hardware_uuid": "different-hardware"},
    ],
)
def test_stale_reused_or_conflicting_evidence_goes_to_review(
    database: tuple[Session, uuid.UUID], changed: dict[str, Any]
) -> None:
    db, actor = database
    ingest(
        db, actor, [row(ip="192.0.2.10", hardware_uuid="original-hardware")], network_scope="synthetic-east"
    )
    result = ingest(
        db,
        actor,
        [row(ip="192.0.2.10", **{k: v for k, v in changed.items() if k != "ip"})],
        key="changed",
        network_scope="synthetic-east",
    )
    assert result["review_rows"] == 1
    assert current(db, review_status="open")["items"][0]["asset_id"] is None


def test_late_clone_blocks_every_row_before_any_asset_is_created(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    result = ingest(db, actor, [row(hardware_uuid="hardware-a"), row(hardware_uuid="hardware-b")])
    assert result["new_observations"] == 2 and result["review_rows"] == 2
    assert db.scalar(select(func.count()).select_from(Asset)) == 0


def test_failed_coverage_and_absence_never_retire_or_resolve(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    ingest(db, actor, [row(kind="vulnerability", vulnerability_id="CVE-SYNTHETIC", native_status="open")])
    target = current(db)["items"][0]["asset_id"]
    ingest(
        db,
        actor,
        [
            row(
                kind="coverage",
                coverage_outcome="dns_failed",
                complete=False,
                observed_at="2026-10-01T11:00:00Z",
            )
        ],
        key="failed",
    )
    ingest(db, actor, [row("unrelated")], key="absence")
    original = next(item for item in current(db)["items"] if item["observation"]["kind"] == "vulnerability")
    assert original["observation"]["native_status"] == "open"
    asset = db.get(Asset, uuid.UUID(target))
    assert asset is not None and asset.active and asset.last_scan_observed_at is None
    models = module("vulnbatch.db.reconciliation")
    assert db.scalar(select(func.count()).select_from(models.VulnerabilityOccurrence)) == 1
    assert db.scalar(select(func.count()).select_from(models.CoverageObservation)) == 1


def test_wrong_match_undo_preserves_new_import_and_raw_history(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    ingest(db, actor, [row("agent-a"), row("agent-b")])
    initial = {item["observation"]["asset"]["native_ids"][0]["value"]: item for item in current(db)["items"]}
    source, target = initial["agent-a"], initial["agent-b"]
    correction = decide(db, actor, "assign", [source], "wrong-match", target_asset_id=target["asset_id"])
    ingest(db, actor, [row("new-agent")], key="later-import")
    decide(db, actor, "undo", [], "undo-wrong", undo_decision_id=correction["id"])
    final = {item["id"]: item for item in current(db)["items"]}
    assert final[source["id"]]["asset_id"] == source["asset_id"]
    assert final[source["id"]]["version"] == 3
    assert current(db)["total"] == 3
    detail = module("vulnbatch.reconciliation.queries").observation_detail(db, uuid.UUID(source["id"]))
    assert [version["version"] for version in detail["history"]] == [1, 2, 3]
    assert detail["observation"]["raw"] == row("agent-a")


def test_merge_split_and_undo_move_only_assignments(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    ingest(db, actor, [row("agent-a"), row("agent-b")])
    initial = current(db)["items"]
    merge = decide(
        db,
        actor,
        "merge",
        [],
        "merge",
        source_asset_id=initial[0]["asset_id"],
        target_asset_id=initial[1]["asset_id"],
    )
    assert merge["changed_rows"] == 1
    assert len({item["asset_id"] for item in current(db)["items"]}) == 1
    moved = next(item for item in current(db)["items"] if item["id"] == initial[0]["id"])
    split = decide(db, actor, "split", [moved], "split", source_asset_id=moved["asset_id"])
    assert len({item["asset_id"] for item in current(db)["items"]}) == 2
    decide(db, actor, "undo", [], "undo-split", undo_decision_id=split["id"])
    with pytest.raises(ValueError, match=r"changed|version"):
        decide(db, actor, "undo", [], "unsafe-undo", undo_decision_id=merge["id"])
    db.rollback()
    assert all(asset.active and asset.merged_into_id is None for asset in db.scalars(select(Asset)))


def test_decision_replay_and_stale_revision_are_guarded(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    ingest(db, actor, [row()])
    item = current(db)["items"][0]
    schema = module("vulnbatch.schemas.reconciliation")
    payload = schema.DecisionRequest.model_validate(
        {
            "action": "reject",
            "request_key": "reject-once",
            "reason": "Synthetic rejected identity",
            "expected_revision": 1,
            "observation_ids": [item["id"]],
            "expected_versions": {item["id"]: 1},
        }
    )
    service = module("vulnbatch.reconciliation.decisions")
    first = service.apply_decision(db, payload, actor_id=actor, now=NOW)
    db.commit()
    replay = service.apply_decision(db, payload, actor_id=actor, now=NOW)
    db.commit()
    assert replay["id"] == first["id"] and replay["replayed"]
    with pytest.raises(ValueError, match="revision"):
        service.apply_decision(
            db, payload.model_copy(update={"request_key": "stale"}), actor_id=actor, now=NOW
        )
    db.rollback()
    assert current(db)["items"][0]["version"] == 2


def test_bad_versions_roll_back_every_selected_assignment(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    ingest(db, actor, [row("agent-a"), row("agent-b")])
    items = current(db)["items"]
    with pytest.raises(ValueError, match="version"):
        decide(
            db,
            actor,
            "reject",
            items,
            "mixed-stale",
            expected_versions={items[0]["id"]: 1, items[1]["id"]: 999},
        )
    db.rollback()
    assert all(item["version"] == 1 and item["asset_id"] for item in current(db)["items"])


def test_transaction_rollback_does_not_leave_partial_import(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    storage = module("vulnbatch.reconciliation.storage")
    config = SourceOptions(source="inventory", instance="synthetic", format="json")
    storage.persist_bundle(
        db,
        [
            storage.ImportDocument(
                filename="synthetic.json", content=json.dumps([row()]).encode(), options=config
            )
        ],
        actor_id=actor,
        request_key="rollback",
        now=NOW,
    )
    db.rollback()
    assert current(db)["total"] == 0
    assert db.scalar(select(func.count()).select_from(Asset)) == 0


def test_reimport_preserves_analyst_rejection_and_version(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    ingest(db, actor, [row()])
    decide(db, actor, "reject", current(db)["items"], "analyst-reject")
    before = current(db)["items"][0]
    ingest(db, actor, [row()], key="reimport-after-reject")
    after = current(db)["items"][0]
    assert after == before and after["review_status"] == "rejected"


def test_unresolved_clone_conflict_survives_later_batches(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    ingest(db, actor, [row(hardware_uuid="hardware-a")])
    ingest(db, actor, [row(hardware_uuid="hardware-b", observed_at="2026-10-01T11:00:00Z")], key="conflict")
    result = ingest(db, actor, [row(observed_at="2026-10-01T12:00:00Z")], key="native-only")
    assert result["review_rows"] == 1
    conflict = [
        item for item in current(db)["items"] if item["observation"]["asset"]["hardware_uuid"] == "hardware-b"
    ]
    decide(db, actor, "reject", conflict, "reject-clone")
    result = ingest(db, actor, [row(observed_at="2026-10-01T13:00:00Z")], key="resolved-conflict")
    assert result["assigned_rows"] == 1


def test_repeated_rejected_evidence_does_not_reopen_conflict(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    ingest(db, actor, [row(hardware_uuid="hardware-a")])
    rejected = row(hardware_uuid="hardware-b", observed_at="2026-10-01T11:00:00Z")
    ingest(db, actor, [rejected], key="conflict")
    decide(db, actor, "reject", current(db, review_status="open")["items"], "reject-clone")
    result = ingest(db, actor, [rejected, row(observed_at="2026-10-01T12:00:00Z")], key="repeated-rejected")
    assert result["duplicate_rows"] == 1 and result["assigned_rows"] == 1


@pytest.mark.parametrize(
    "fields",
    [
        {"native_id": "x" * 513},
        {"native_id_kind": "x" * 129},
        {"kind": "vulnerability", "vulnerability_id": "x" * 513},
        {"kind": "vulnerability", "vulnerability_id": "one", "occurrence_id": "x" * 513},
        {"native_status": "x" * 129},
        {"operating_system": "x" * 513},
        {"hostname": "x" * 256},
        {"native_id": "a\x00b"},
    ],
)
def test_database_bound_fields_reject_bad_row_and_keep_later_good_row(
    database: tuple[Session, uuid.UUID], fields: dict[str, Any]
) -> None:
    db, actor = database
    result = ingest(db, actor, [row(**fields), row("supported")])
    assert result["error_rows"] == 1 and result["new_observations"] == 1
    assert current(db)["total"] == 1


def test_undo_refuses_restoration_to_retired_asset(database: tuple[Session, uuid.UUID]) -> None:
    db, actor = database
    ingest(db, actor, [row("agent-a"), row("agent-b")])
    first, second = current(db)["items"]
    correction = decide(db, actor, "assign", [first], "correction", target_asset_id=second["asset_id"])
    old_asset = db.get(Asset, uuid.UUID(first["asset_id"]))
    assert old_asset is not None
    old_asset.active = False
    old_asset.merged_into_id = uuid.UUID(second["asset_id"])
    db.commit()
    with pytest.raises(ValueError, match=r"active|retired"):
        decide(db, actor, "undo", [], "unsafe-restoration", undo_decision_id=correction["id"])
    db.rollback()
    changed = next(item for item in current(db)["items"] if item["id"] == first["id"])
    assert changed["asset_id"] == second["asset_id"] and changed["version"] == 2


@pytest.mark.parametrize(
    "model_name",
    [
        "SourceObservation",
        "ObservationLocator",
        "ObservationNativeID",
        "VulnerabilityOccurrence",
        "CoverageObservation",
        "AssignmentVersion",
        "ReconciliationDecision",
        "ReconciliationBatch",
    ],
)
def test_persisted_evidence_and_audit_are_immutable(
    database: tuple[Session, uuid.UUID], model_name: str
) -> None:
    db, actor = database
    ingest(
        db,
        actor,
        [
            row(kind="vulnerability", vulnerability_id="synthetic-vuln"),
            row("agent-c", kind="coverage", coverage_outcome="unreachable"),
        ],
    )
    models = module("vulnbatch.db.reconciliation")
    record = db.scalar(select(getattr(models, model_name)))
    assert record is not None
    db.delete(record)
    with pytest.raises(ValueError, match="immutable"):
        db.flush()
    db.rollback()


@pytest.mark.parametrize("operation", ["preview", "page", "detail", "decision"])
def test_reused_session_refreshes_mutable_assignment_projection(
    database: tuple[Session, uuid.UUID],
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    from vulnbatch.db.reconciliation import CurrentAssignment
    from vulnbatch.reconciliation.storage import ImportDocument, ReconciliationConflict, preview_bundle
    from vulnbatch.schemas.reconciliation import DecisionRequest

    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("SECRET_KEY", "synthetic-unused-test-secret-0000000000000000")
    from vulnbatch.core.config import get_settings

    get_settings.cache_clear()
    db, actor = database
    rows = [row()]
    ingest(db, actor, rows)
    item = current(db)["items"][0]
    held = db.get(CurrentAssignment, uuid.UUID(item["id"]))
    assert held is not None and held.version == 1
    db.commit()
    with Session(db.get_bind(), expire_on_commit=False) as writer:
        decide(writer, actor, "reject", [item], "other-session")
    assert held.version == 1  # Keep a real stale ORM object in the reader's identity map.
    if operation == "preview":
        document = ImportDocument(
            "synthetic.json",
            json.dumps(rows).encode(),
            SourceOptions(
                source="crowdstrike",
                instance="synthetic-a",
                format="json",
                time_meaning="source_observed",
            ),
        )
        result = preview_bundle(db, [document], now=NOW, actor_id=actor)
        retained = result.items[0].current_assignment
        assert retained and retained["version"] == 2 and retained["review_status"] == "rejected"
    elif operation == "decision":
        payload = DecisionRequest(
            request_key="stale-version",
            expected_revision=2,
            action="reject",
            reason="Old projection",
            observation_ids=[uuid.UUID(item["id"])],
            expected_versions={item["id"]: 1},
        )
        with pytest.raises(ReconciliationConflict, match="assignment version changed"):
            module("vulnbatch.reconciliation.decisions").apply_decision(db, payload, actor_id=actor, now=NOW)
        db.rollback()
    else:
        result = (
            current(db)["items"][0]
            if operation == "page"
            else module("vulnbatch.reconciliation.queries").observation_detail(db, uuid.UUID(item["id"]))
        )
        assert result["version"] == 2 and result["review_status"] == "rejected"
