"""Exercise the example through the real routes and shared client, with all review states."""

from __future__ import annotations

import importlib.util
from typing import Any

import httpx
from test_service_exposure_api import context as context


def test_fictional_loader_includes_assigned_and_review_needed_evidence(context: Any) -> None:
    from vulnbatch.api.routes import reconciliation, reconciliation_storage
    from vulnbatch.client.transport import ApiClient

    api, _, _ = context
    api.app.include_router(reconciliation.router)
    api.app.include_router(reconciliation_storage.router)

    def transport(request: httpx.Request) -> httpx.Response:
        response = api.request(
            request.method, str(request.url), headers=dict(request.headers), content=request.content
        )
        return httpx.Response(response.status_code, headers=response.headers, content=response.content)

    spec = importlib.util.spec_from_file_location(
        "fictional_service_loader", "examples/service-exposure/load.py"
    )
    assert spec and spec.loader
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    with ApiClient(transport=httpx.MockTransport(transport)) as client:
        client.csrf_token = api.headers["X-CSRF-Token"]
        result = loader.load_example(client)
        assert result["imported"]["new_observations"] == 13
        assert result["report"]["total"] == 13
        rows = {item["evidence"]["raw"]["fixture_ref"]: item for item in result["report"]["items"]}
        assert rows["vip-tls"]["node_id"] == result["node_ids"]["vip"]
        assert rows["vip-tls"]["service_id"] is None
        assert rows["checkout-vuln"]["service_id"] == result["node_ids"]["checkout"]
        assert rows["management-vuln"]["service_id"] is None
        assert rows["directory-logon"]["age_days"] is None
        assert rows["mgmt-unreachable"]["coverage_outcome"] == "unreachable"
        assert rows["stale-fingerprint"]["attribution_status"] == "review_needed"
        node = api.get("/api/v1/exposure/nodes/" + result["node_ids"]["east-a"]).json()
        assert node["node"]["facts"]["fingerprint"] == "Ubuntu 24.04"
        assert node["fact_total"] == 2
