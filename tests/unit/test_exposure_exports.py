from __future__ import annotations

import json
from typing import Any

from test_service_exposure_api import context as context
from test_service_exposure_api import seed_observations

from vulnbatch.reporting import REPORT_COLUMNS, render_payload


def test_export_keeps_report_page_and_shared_rendering(context: Any) -> None:
    from vulnbatch.api.routes.exposure_exports import router

    client, db, _ = context
    client.app.include_router(router)
    seed_observations(db)
    report = client.get("/api/v1/exposure/report", params={"offset": 1, "limit": 1}).json()
    assert report["total"] == 3
    assert len(report["items"]) == 1
    for format in ("json", "csv", "markdown"):
        response = client.get(
            "/api/v1/exposure/report/export", params={"offset": 1, "limit": 1, "format": format}
        )
        assert response.status_code == 200
        assert response.text == render_payload(report, format, REPORT_COLUMNS)
        assert "attachment" in response.headers["Content-Disposition"]
        if format == "json":
            assert json.loads(response.text)["items"] == report["items"]
    assert client.get("/api/v1/exposure/report/export?limit=501").status_code == 422


def test_bound_nodes_block_legacy_retirement(context: Any) -> None:
    from test_service_exposure_api import apply, graph

    from vulnbatch.reconciliation.decisions import guard_legacy_retirement
    from vulnbatch.reconciliation.storage import ReconciliationConflict

    client, db, state = context
    payload = graph()
    payload["nodes"][0]["asset_id"] = str(state["asset_id"])
    apply(client, payload, "explicit-binding")
    try:
        guard_legacy_retirement(db, [state["asset_id"]])
    except ReconciliationConflict as exc:
        assert "bound" in str(exc)
        db.rollback()
    else:
        raise AssertionError("Legacy retirement must not invalidate an explicit service binding")
