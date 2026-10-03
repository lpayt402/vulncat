from __future__ import annotations

from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.testclient import TestClient

from vulnbatch.core.static import FrontendStaticFiles


@pytest.fixture
def browser_client(tmp_path: Path) -> TestClient:
    (tmp_path / "index.html").write_text("<html><body>Workbench UI</body></html>", encoding="utf-8")
    files = FrontendStaticFiles(directory=tmp_path, html=True)
    return TestClient(Starlette(routes=[Mount("/", app=files)]))


def test_known_client_routes_support_direct_navigation(browser_client: TestClient) -> None:
    for route in ("/login", "/setup", "/hosts/11111111-1111-4111-8111-111111111111", "/imports", "/services"):
        response = browser_client.get(route)
        assert response.status_code == 200, route
        assert "Workbench UI" in response.text


def test_unknown_api_and_asset_paths_keep_not_found(browser_client: TestClient) -> None:
    for route in ("/api/v1/missing", "/assets/missing.js", "/hosts/missing.css", "/missing"):
        assert browser_client.get(route).status_code == 404
