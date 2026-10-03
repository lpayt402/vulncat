from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from secrets import token_urlsafe
from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from vulnbatch.core.security import csrf_token_for_session
from vulnbatch.db.base import Base
from vulnbatch.db.models import Asset, AssetIdentifier


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("SECRET_KEY", "synthetic-unused-test-secret-0000000000000000")
    from vulnbatch.core.config import get_settings

    get_settings.cache_clear()
    from vulnbatch.api.deps import Principal, get_current_principal
    from vulnbatch.api.routes import reconciliation
    from vulnbatch.db.session import get_db

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        asset = Asset(canonical_hostname="existing.example.test")
        db.add(asset)
        db.flush()
        db.add(
            AssetIdentifier(
                asset_id=asset.id,
                identifier_type="fqdn",
                normalized_value="existing.example.test",
                original_value="existing.example.test",
                first_observed_at=datetime(2026, 10, 1, tzinfo=UTC),
                last_observed_at=datetime(2026, 10, 1, tzinfo=UTC),
            )
        )
        db.commit()
        app = FastAPI()
        app.include_router(reconciliation.router)
        user = SimpleNamespace(id=uuid.uuid4(), role=SimpleNamespace(name="administrator"))
        session_token = token_urlsafe(32)
        app.dependency_overrides[get_current_principal] = lambda: cast(
            Principal,
            SimpleNamespace(user=user, raw_session_token=session_token),
        )
        app.dependency_overrides[get_db] = lambda: db
        with TestClient(app) as result:
            result.headers["X-CSRF-Token"] = csrf_token_for_session(session_token)
            yield result
    engine.dispose()


def test_offline_endpoint_requires_csrf(client: TestClient) -> None:
    client.headers.pop("X-CSRF-Token")
    assert client.post("/api/v1/reconciliation/preview").status_code == 403


def test_columns_handles_json_envelopes_and_nested_fields(client: TestClient) -> None:
    response = client.post(
        "/api/v1/reconciliation/columns",
        data={"format": "json"},
        files={"upload": ("synthetic.json", b'{"resources":[{"host":{"aid":"x"}}]}')},
    )
    assert response.status_code == 200
    assert "host.aid" in response.json()["columns"]
    assert response.json()["records_path"] == "resources"


def test_preview_is_paginated_and_never_changes_inventory(client: TestClient) -> None:
    from vulnbatch.db.session import get_db

    opts = [{"source": "inventory", "instance": "synthetic", "format": "csv"}]
    data = b"hostname\nexisting.example.test\nnew.example.test\n"
    response = client.post(
        "/api/v1/reconciliation/preview?offset=1&limit=1",
        data={"options_json": json.dumps(opts)},
        files=[("uploads", ("test.csv", data))],
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["total"] == 2
    assert result["items"][0]["observation"]["asset"]["fqdn"] == "new.example.test"
    assert result["action_counts"] == {"review": 1, "create": 1}
    assert result["persisted"] is False
    db = client.app.dependency_overrides[get_db]()
    assert len(db.query(Asset).all()) == 1


def test_invalid_options_and_bad_encoding_are_422(client: TestClient) -> None:
    for opts, data in [
        ("not-json", b"x"),
        ('[{"source":"inventory","instance":"synthetic","format":"csv"}]', b"hostname\n\xff"),
    ]:
        response = client.post(
            "/api/v1/reconciliation/preview",
            data={"options_json": opts},
            files=[("uploads", ("test.csv", data))],
        )
        assert response.status_code == 422


def test_more_than_eight_files_are_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/reconciliation/preview",
        data={"options_json": "[]"},
        files=[("uploads", (f"test-{i}.csv", b"native_id\na\n")) for i in range(9)],
    )
    assert response.status_code == 413


def test_columns_uses_explicit_nested_json_records_path(client: TestClient) -> None:
    content = b'{"resources":{"items":[{"id":"a","host":{"name":"one"}}]}}'
    response = client.post(
        "/api/v1/reconciliation/columns",
        data={"format": "json", "records_path": "resources.items"},
        files={"upload": ("test.json", content)},
    )
    assert response.status_code == 200
    assert response.json()["columns"] == ["id", "host.name"]


def test_columns_requires_file_format_and_preview_rejects_unknown_mapping(client: TestClient) -> None:
    assert (
        client.post(
            "/api/v1/reconciliation/columns", files={"upload": ("test.csv", b"native_id\na\n")}
        ).status_code
        == 422
    )
    options = [{"source": "inventory", "instance": "test", "format": "csv", "mapping": {"typo": "native_id"}}]
    assert (
        client.post(
            "/api/v1/reconciliation/preview",
            data={"options_json": json.dumps(options)},
            files=[("uploads", ("test.csv", b"native_id\na\n"))],
        ).status_code
        == 422
    )


@pytest.mark.parametrize("format,data", [("csv", b"native_id\na\n"), ("ndjson", b'{"native_id":"a"}\n')])
def test_columns_rejects_records_path_for_non_json_formats(
    client: TestClient, format: str, data: bytes
) -> None:
    response = client.post(
        "/api/v1/reconciliation/columns",
        data={"format": format, "records_path": "unused"},
        files={"upload": ("synthetic.txt", data)},
    )
    assert response.status_code == 422
    assert "records_path" in response.json()["detail"] and "JSON" in response.json()["detail"]


def test_columns_rejects_whitespace_json_records_path(client: TestClient) -> None:
    response = client.post(
        "/api/v1/reconciliation/columns",
        data={"format": "json", "records_path": " "},
        files={"upload": ("synthetic.json", b'[{"native_id":"a"}]')},
    )
    assert response.status_code == 422
    assert "nonempty" in response.json()["detail"]


def test_missing_json_mapping_is_visible_as_an_error_without_an_inventory_proposal(
    client: TestClient,
) -> None:
    config = {
        "source": "crowdstrike",
        "instance": "synthetic",
        "format": "json",
        "mapping": {"native_id": "aid", "vulnerability_id": "finding.typo"},
    }
    content = [{"aid": "a", "finding": {"id": "v1"}}, {"aid": "b", "finding": {"typo": "v2"}}]
    response = client.post(
        "/api/v1/reconciliation/preview",
        data={"options_json": json.dumps([config])},
        files=[("uploads", ("synthetic.json", json.dumps(content).encode()))],
    )
    assert response.status_code == 200
    result = response.json()
    assert (result["total_rows"], result["valid_rows"], result["error_rows"], result["total"]) == (2, 1, 1, 1)
    assert "finding.typo" in result["errors"][0]["error"]
    assert result["items"][0]["observation"]["kind"] == "vulnerability"


@pytest.mark.parametrize(
    "source,record,message",
    [
        (
            "inventory",
            {"native_id": "a", "coverage_outcome": "failed", "complete": True},
            "cannot be complete",
        ),
        ("netbox", {"native_id": 7, "native_id_kind": "ipam.ipaddress"}, "Unsupported NetBox"),
        (
            "crowdstrike",
            {"native_id": "a", "vulnerability_id": "v1", "cves": [{"id": "CVE-2099-10001"}]},
            "cves",
        ),
    ],
)
def test_incompatible_rows_have_no_successful_proposals(
    client: TestClient, source: str, record: dict[str, object], message: str
) -> None:
    response = client.post(
        "/api/v1/reconciliation/preview",
        data={"options_json": json.dumps([{"source": source, "instance": "synthetic", "format": "json"}])},
        files=[("uploads", ("synthetic.json", json.dumps([record]).encode()))],
    )
    assert response.status_code == 200
    result = response.json()
    assert result["error_rows"] == 1 and result["valid_rows"] == 0 and result["items"] == []
    assert message in result["errors"][0]["error"]


@pytest.mark.parametrize("format", ["csv", "ndjson", "nessus_xml"])
def test_preview_rejects_incompatible_records_path_configuration(client: TestClient, format: str) -> None:
    response = client.post(
        "/api/v1/reconciliation/preview",
        data={
            "options_json": json.dumps(
                [{"source": "nessus", "instance": "synthetic", "format": format, "records_path": "unused"}]
            )
        },
        files=[("uploads", ("synthetic.txt", b"native_id\na\n"))],
    )
    assert response.status_code == 422
    assert "records_path" in response.json()["detail"] and "JSON" in response.json()["detail"]
