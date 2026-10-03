"""Synthetic SQLite scale checks count statements rather than machine-dependent time limits."""

from __future__ import annotations

import json
import time
import uuid
from collections import Counter
from datetime import UTC, datetime
from secrets import token_urlsafe
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from vulnbatch.core.security import csrf_token_for_session
from vulnbatch.db.base import Base
from vulnbatch.db.models import Role, User
from vulnbatch.db.reconciliation import SourceInstance, SourceObservation
from vulnbatch.reconciliation.storage import bulk_insert


def test_thousands_of_explicit_nodes_and_signals_use_bounded_batch_queries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("SECRET_KEY", "synthetic-service-scale-0000000000000000000000")
    from vulnbatch.core.config import get_settings

    get_settings.cache_clear()
    from vulnbatch.api.deps import Principal, get_current_principal
    from vulnbatch.api.routes import exposure
    from vulnbatch.db.session import get_db

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        role = Role(name="administrator")
        source = SourceInstance(source="inventory", label="synthetic-scale")
        db.add_all([role, source])
        db.flush()
        actor = User(username="scale", display_name="Scale", password_hash=token_urlsafe(16), role_id=role.id)
        db.add(actor)
        db.flush()
        ids = [uuid.uuid4() for _ in range(3000)]
        now = datetime.now(UTC)
        kinds = ["inventory", "vulnerability", "coverage"]
        bulk_insert(
            db,
            SourceObservation,
            [
                {
                    "id": key,
                    "fingerprint": f"{i:064x}",
                    "source_instance_id": source.id,
                    "kind": kinds[i % 3],
                    "observed_at": now,
                    "first_observed_at": None,
                    "imported_at": now,
                    "parser_version": "synthetic-scale",
                    "normalized": {"provenance": {"time_meaning": "source_observed"}, "raw": {"row": i}},
                }
                for i, key in enumerate(ids)
            ],
        )
        db.commit()
        app = FastAPI()
        app.include_router(exposure.router)
        token = token_urlsafe(32)
        app.dependency_overrides[get_current_principal] = lambda: cast(
            Principal,
            SimpleNamespace(
                user=SimpleNamespace(id=actor.id, role=SimpleNamespace(name="administrator")),
                raw_session_token=token,
            ),
        )
        app.dependency_overrides[get_db] = lambda: db
        statements: Counter[str] = Counter()

        @event.listens_for(engine, "before_cursor_execute")
        def count_sql(_: Any, __: Any, statement: str, ___: Any, ____: Any, _____: Any) -> None:
            statements[statement.strip().split()[0].upper()] += 1

        started = time.perf_counter()
        with TestClient(app) as client:
            client.headers["X-CSRF-Token"] = csrf_token_for_session(token)
            node_refs: dict[int, str] = {}
            write_selects = []
            revision = 0
            for batch in range(2):
                nodes, relationships = [], []
                for number in range(batch * 500, (batch + 1) * 500):
                    for prefix, kind in [("host", "host"), ("svc", "service"), ("ep", "endpoint")]:
                        nodes.append(
                            {
                                "ref": f"{prefix}-{number}",
                                "native_id": f"{prefix}-{number}",
                                "kind": kind,
                                "label": f"{prefix} {number}",
                                "network_scope": "synthetic",
                            }
                        )
                    relationships.extend(
                        [
                            {"kind": "endpoint_of", "from_node": f"ep-{number}", "to_node": f"svc-{number}"},
                            {"kind": "backed_by", "from_node": f"svc-{number}", "to_node": f"host-{number}"},
                        ]
                    )
                graph = {
                    "source": "synthetic",
                    "instance": "scale",
                    "observed_at": now.isoformat(),
                    "time_meaning": "source_observed",
                    "nodes": nodes,
                    "relationships": relationships,
                }
                statements.clear()
                response = client.post(
                    "/api/v1/exposure/apply",
                    json={
                        "graph": graph,
                        "request_key": f"nodes-{batch}",
                        "reason": "Synthetic scale benchmark",
                        "expected_revision": revision,
                        "confirmed": True,
                    },
                )
                assert response.status_code == 200, response.text[:1000]
                write_selects.append(statements["SELECT"])
                assert statements["SELECT"] <= 50, statements
                revision = response.json()["revision"]
                for change in response.json()["changes"]:
                    if change["entity_type"] == "node" and change["after"]["kind"] == "endpoint":
                        number = int(change["after"]["native_id"].split("-")[1])
                        node_refs[number] = change["entity_id"]
            for batch in range(2):
                graph = {
                    "source": "analyst",
                    "instance": "scale",
                    "attributions": [
                        {
                            "observation_id": str(ids[i]),
                            "node_ref": node_refs[i // 3],
                            "status": "attributed",
                            "reason": "Explicit synthetic endpoint mapping",
                        }
                        for i in range(batch * 1500, (batch + 1) * 1500)
                    ],
                }
                statements.clear()
                response = client.post(
                    "/api/v1/exposure/apply",
                    json={
                        "graph": graph,
                        "request_key": f"signals-{batch}",
                        "reason": "Synthetic scale benchmark",
                        "expected_revision": revision,
                        "confirmed": True,
                    },
                )
                assert response.status_code == 200, response.text[:1000]
                assert statements["SELECT"] <= 40, statements
                revision = response.json()["revision"]
                write_selects.append(statements["SELECT"])
            statements.clear()
            nodes_response = client.get(
                "/api/v1/exposure/nodes", params={"limit": 500, "kind": "service"}
            ).json()
            assert nodes_response["total"] == 1000 and len(nodes_response["items"]) == 500
            assert statements["SELECT"] <= 12, statements
            assert all(
                item["exposure_counts"] == {"inventory": 1, "vulnerability": 1, "coverage": 1}
                for item in nodes_response["items"]
            )
            statements.clear()
            first = client.get("/api/v1/exposure/report", params={"limit": 500}).json()
            first_queries = statements["SELECT"]
            assert first["total"] == 3000 and first["counts"] == {
                "inventory": 1000,
                "vulnerability": 1000,
                "coverage": 1000,
            }
            assert len(first["items"]) == 500 and first_queries <= 6
            statements.clear()
            second = client.get("/api/v1/exposure/report", params={"offset": 500, "limit": 500}).json()
            assert not {row["observation_id"] for row in first["items"]} & {
                row["observation_id"] for row in second["items"]
            }
            assert statements["SELECT"] <= 6
            statements.clear()
            history = client.get("/api/v1/exposure/history", params={"limit": 50}).json()
            history_queries = statements["SELECT"]
            assert history["total"] == 4 and history_queries <= 60
        print(
            json.dumps(
                {
                    "nodes": 3000,
                    "observations": 3000,
                    "relationships": 2000,
                    "write_selects_per_batch": write_selects,
                    "report_page_selects": first_queries,
                    "history_page_selects": history_queries,
                    "seconds": round(time.perf_counter() - started, 3),
                }
            )
        )
    engine.dispose()
