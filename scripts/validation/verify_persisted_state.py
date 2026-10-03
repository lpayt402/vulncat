from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
SUMMARY_PATH = ROOT / "tmp" / "e2e" / "summary.json"
if os.environ.get("VULNERABILITY_WORKBENCH_DISPOSABLE_TEST") != "1":
    raise SystemExit("Use this validator only with an explicitly designated disposable synthetic test stack.")
BASE_URL = os.environ["VULNERABILITY_WORKBENCH_TEST_BASE_URL"].rstrip("/")
ADMIN_USERNAME = os.environ.get("VULNERABILITY_WORKBENCH_TEST_ADMIN_USERNAME", "validation-admin")
ADMIN_PASSWORD = os.environ["VULNERABILITY_WORKBENCH_TEST_ADMIN_PASSWORD"]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def expect(response: httpx.Response, status_code: int = 200) -> httpx.Response:
    if response.status_code != status_code:
        raise RuntimeError(
            f"{response.request.method} {response.request.url} returned "
            f"{response.status_code}: {response.text[:2_000]}"
        )
    return response


def main() -> int:
    try:
        summary: dict[str, Any] = json.loads(SUMMARY_PATH.read_text(encoding="utf-8"))
        require(summary["status"] == "passed", "End-to-end summary is not a passing baseline.")
        with httpx.Client(base_url=BASE_URL, timeout=30, follow_redirects=True) as client:
            expect(client.get("/healthz"))
            expect(client.get("/readyz"))
            session = expect(
                client.post(
                    "/api/v1/auth/login",
                    json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
                )
            ).json()
            require(
                session["user"]["role"] == "administrator",
                "Persisted administrator account could not sign in.",
            )
            hosts = expect(
                client.post(
                    "/api/v1/assets/query",
                    json={"query": {"schema_version": 1}, "page": 1, "page_size": 200},
                )
            ).json()
            require(
                hosts["total"] == summary["host_count"],
                "Canonical host count changed across persistence validation.",
            )
            imports = expect(client.get("/api/v1/imports")).json()
            persisted_import_ids = {item["id"] for item in imports}
            expected_import_ids = {
                item["id"] for item in summary["imports"].values() if isinstance(item, dict) and "id" in item
            }
            require(
                expected_import_ids.issubset(persisted_import_ids),
                "One or more completed imports were missing after restart or restore.",
            )
            exports = expect(client.get("/api/v1/exports")).json()
            persisted_export_ids = {item["id"] for item in exports}
            for export_name in ("xlsx", "csv", "html"):
                expected = summary["exports"][export_name]
                require(
                    expected["id"] in persisted_export_ids,
                    f"Persisted {export_name} export history entry was missing.",
                )
                download = expect(client.get(f"/api/v1/exports/{expected['id']}/download"))
                actual_hash = hashlib.sha256(download.content).hexdigest()
                require(
                    actual_hash == expected["sha256"],
                    f"Persisted {export_name} artifact hash changed.",
                )
        print(
            json.dumps(
                {
                    "status": "passed",
                    "host_count": summary["host_count"],
                    "import_count_verified": len(expected_import_ids),
                    "export_artifacts_verified": 3,
                },
                indent=2,
            )
        )
        return 0
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
