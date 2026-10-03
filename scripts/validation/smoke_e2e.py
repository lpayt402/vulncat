from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import secrets
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
OUTPUT_DIR = ROOT / "tmp" / "e2e"
if os.environ.get("VULNERABILITY_WORKBENCH_DISPOSABLE_TEST") != "1":
    raise SystemExit("Use this validator only with an explicitly designated disposable synthetic test stack.")
BASE_URL = os.environ["VULNERABILITY_WORKBENCH_TEST_BASE_URL"].rstrip("/")
ADMIN_USERNAME = os.environ.get("VULNERABILITY_WORKBENCH_TEST_ADMIN_USERNAME", "validation-admin")
ADMIN_PASSWORD = os.environ.get(
    "VULNERABILITY_WORKBENCH_TEST_ADMIN_PASSWORD",
    secrets.token_urlsafe(32),
)
READ_ONLY_USERNAME = os.environ.get("VULNERABILITY_WORKBENCH_TEST_READ_ONLY_USERNAME", "validation-reader")
READ_ONLY_PASSWORD = os.environ.get(
    "VULNERABILITY_WORKBENCH_TEST_READ_ONLY_PASSWORD",
    secrets.token_urlsafe(32),
)


class ValidationFailure(RuntimeError):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationFailure(message)


def expect(response: httpx.Response, *status_codes: int) -> httpx.Response:
    if response.status_code not in status_codes:
        body = response.text[:2_000]
        raise ValidationFailure(
            f"{response.request.method} {response.request.url} returned "
            f"{response.status_code}, expected {status_codes}: {body}"
        )
    return response


def json_response(response: httpx.Response, *status_codes: int) -> Any:
    return expect(response, *status_codes).json()


def mutation_headers(csrf_token: str) -> dict[str, str]:
    return {"X-CSRF-Token": csrf_token}


def sign_in_admin(client: httpx.Client) -> tuple[dict[str, Any], str, bool]:
    setup_status = json_response(client.get("/api/v1/system/setup-status"), 200)
    setup_performed = bool(setup_status["setup_required"])
    if setup_performed:
        session = json_response(
            client.post(
                "/api/v1/auth/setup",
                json={
                    "username": ADMIN_USERNAME,
                    "display_name": "Validation Administrator",
                    "password": ADMIN_PASSWORD,
                },
            ),
            201,
        )
    else:
        session = json_response(
            client.post(
                "/api/v1/auth/login",
                json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            ),
            200,
        )
    check(session["user"]["role"] == "administrator", "Validation admin did not receive admin role.")
    return session, session["csrf_token"], setup_performed


def upload_import(
    client: httpx.Client,
    csrf_token: str,
    fixture_name: str,
    source_type: str,
    *,
    content: bytes | None = None,
) -> dict[str, Any]:
    path = FIXTURES / fixture_name
    upload_content = content if content is not None else path.read_bytes()
    media_type = {
        ".csv": "text/csv",
        ".json": "application/json",
        ".nessus": "application/xml",
        ".xml": "application/xml",
    }.get(path.suffix.lower(), "application/octet-stream")
    return json_response(
        client.post(
            "/api/v1/imports/upload",
            headers=mutation_headers(csrf_token),
            files={"upload": (fixture_name, upload_content, media_type)},
            data={
                "source_type": source_type,
                "force_reprocess": "false",
                "complete_comparable_scope": "false",
            },
        ),
        202,
    )


def wait_for_import(
    client: httpx.Client,
    import_id: str,
    *,
    timeout_seconds: float = 120,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        result = json_response(client.get(f"/api/v1/imports/{import_id}"), 200)
        if result["status"] == "completed":
            return result
        if result["status"] == "failed":
            raise ValidationFailure(
                f"Import {import_id} failed: {result.get('failure_reason') or result.get('job')}"
            )
        time.sleep(0.5)
    raise ValidationFailure(f"Import {import_id} did not complete within {timeout_seconds} seconds.")


def wait_for_export(
    client: httpx.Client,
    export_id: str,
    *,
    timeout_seconds: float = 120,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        result = json_response(client.get(f"/api/v1/exports/{export_id}"), 200)
        if result["status"] == "completed":
            return result
        if result["status"] in {"failed", "cancelled"}:
            raise ValidationFailure(
                f"Export {export_id} ended as {result['status']}: {result.get('failure_reason')}"
            )
        time.sleep(0.5)
    raise ValidationFailure(f"Export {export_id} did not complete within {timeout_seconds} seconds.")


def download_export(
    client: httpx.Client,
    export_id: str,
    filename: str,
) -> tuple[Path, str]:
    response = expect(client.get(f"/api/v1/exports/{export_id}/download"), 200)
    path = OUTPUT_DIR / filename
    path.write_bytes(response.content)
    sha256 = hashlib.sha256(response.content).hexdigest()
    advertised_sha256 = response.headers.get("X-Content-SHA256")
    check(
        not advertised_sha256 or advertised_sha256 == sha256,
        f"Downloaded export hash did not match its X-Content-SHA256 header for {filename}.",
    )
    return path, sha256


def create_conflict_csv() -> bytes:
    headers = [
        "Asset UUID",
        "Agent UUID",
        "FQDN",
        "IP Address",
        "MAC Address",
        "Operating System",
        "Asset Tags",
        "Plugin ID",
        "Plugin Name",
        "Plugin Family",
        "Severity",
        "Risk Factor",
        "CVSS V3.0 Base Score",
        "VPR Score",
        "CVE",
        "Port",
        "Protocol",
        "Service",
        "Synopsis",
        "Description",
        "Solution",
        "Plugin Output",
        "First Found",
        "Last Found",
        "Plugin Published",
        "Plugin Modified",
        "Exploit Available",
        "Exploited By Malware",
        "Scan Name",
        "Scan Time",
    ]
    row = [
        "11111111-1111-4111-8111-111111111111",
        "44444444-4444-4444-8444-444444444444",
        "identity-conflict.example.test",
        "192.0.2.200",
        "",
        "Synthetic Conflict OS",
        "identity-review",
        "50001",
        "Synthetic identity conflict",
        "Validation",
        "Medium",
        "Medium",
        "5.0",
        "4.0",
        "CVE-2026-50001",
        "443",
        "tcp",
        "https",
        "Synthetic conflict",
        "Safe validation-only identity conflict",
        "Resolve the synthetic validation finding",
        "Synthetic validation evidence",
        "2026-06-01T00:00:00Z",
        "2026-07-15T00:00:00Z",
        "2026-05-01",
        "2026-06-01",
        "no",
        "no",
        "identity-conflict-validation",
        "2026-07-15T01:00:00Z",
    ]
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerow(row)
    return output.getvalue().encode("utf-8")


def create_export(
    client: httpx.Client,
    csrf_token: str,
    *,
    asset_scope: dict[str, Any],
    output_format: str,
) -> dict[str, Any]:
    return json_response(
        client.post(
            "/api/v1/exports",
            headers=mutation_headers(csrf_token),
            json={
                "asset_scope": asset_scope,
                "finding_scope": {
                    "schema_version": 1,
                    "severities": ["medium", "low"],
                    "statuses": [
                        "open",
                        "new_or_maturity_deferred",
                        "planned",
                        "in_progress",
                    ],
                },
                "format": output_format,
                "confirm_large_export": True,
            },
        ),
        202,
    )


def verify_xlsx(path: Path, expected_host_count: int) -> None:
    with zipfile.ZipFile(path) as archive:
        workbook_xml = archive.read("xl/workbook.xml").decode("utf-8")
        check("Host Summary" in workbook_xml, "XLSX is missing the Host Summary sheet.")
        check("Finding Detail" in workbook_xml, "XLSX is missing the Finding Detail sheet.")
        check("Export Metadata" in workbook_xml, "XLSX is missing the Export Metadata sheet.")
        worksheet_xml = "\n".join(
            archive.read(name).decode("utf-8", errors="replace")
            for name in archive.namelist()
            if name.startswith("xl/worksheets/") and name.endswith(".xml")
        )
    check("Snapshot Owner" in worksheet_xml, "XLSX did not retain the snapshotted owner value.")
    check(
        "Changed After Snapshot" not in worksheet_xml,
        "XLSX re-read mutable asset data instead of using the persisted snapshot.",
    )
    check("'=2+2" in worksheet_xml, "XLSX did not neutralize a formula-like owner value.")
    check("<f>" not in worksheet_xml, "XLSX unexpectedly contains formula cells.")
    check(expected_host_count > 0, "XLSX validation expected at least one host.")


def verify_csv_bundle(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        check(
            set(archive.namelist()) == {"host_summary.csv", "finding_detail.csv", "export_metadata.json"},
            "CSV bundle did not contain the expected three provenance files.",
        )
        host_csv = archive.read("host_summary.csv").decode("utf-8-sig")
        finding_csv = archive.read("finding_detail.csv").decode("utf-8-sig")
        metadata = json.loads(archive.read("export_metadata.json"))
    check("'=2+2" in host_csv, "CSV export did not neutralize a formula-like owner value.")
    check("Canonical hostname" in host_csv, "CSV host summary header is missing.")
    check("Plugin ID" in finding_csv, "CSV finding-detail header is missing.")
    check("Data-as-of timestamp" in metadata, "CSV metadata is missing the data-as-of timestamp.")


def verify_html(path: Path) -> None:
    document = path.read_text(encoding="utf-8")
    check("<h2>Host Summary</h2>" in document, "HTML export is missing Host Summary.")
    check("<h2>Finding Detail</h2>" in document, "HTML export is missing Finding Detail.")
    check("<h2>Export metadata</h2>" in document, "HTML export is missing provenance metadata.")
    check(
        "'=2+2" in document or "&#x27;=2+2" in document,
        "HTML export did not preserve the neutralized formula-like value.",
    )


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "base_url": BASE_URL,
        "started_at_epoch": time.time(),
        "checks": [],
        "imports": {},
        "exports": {},
    }
    try:
        with httpx.Client(base_url=BASE_URL, timeout=30, follow_redirects=True) as admin:
            expect(admin.get("/healthz"), 200)
            expect(admin.get("/readyz"), 200)
            summary["checks"].extend(["healthz", "readyz"])

            session, admin_csrf, setup_performed = sign_in_admin(admin)
            summary["setup_performed"] = setup_performed
            summary["admin_user_id"] = session["user"]["id"]

            users = json_response(admin.get("/api/v1/users"), 200)
            reader = next(
                (user for user in users if user["username"] == READ_ONLY_USERNAME),
                None,
            )
            if reader is None:
                reader = json_response(
                    admin.post(
                        "/api/v1/users",
                        headers=mutation_headers(admin_csrf),
                        json={
                            "username": READ_ONLY_USERNAME,
                            "display_name": "Validation Reader",
                            "password": READ_ONLY_PASSWORD,
                            "role": "read_only",
                        },
                    ),
                    201,
                )
            check(reader["role"] == "read_only", "Validation reader did not receive read-only role.")
            summary["reader_user_id"] = reader["id"]
            summary["checks"].append("local_users_and_roles")

            imported_ids: list[str] = []
            fixture_imports = [
                ("tenable_vm.csv", "tenable_csv"),
                ("tenable_vm.json", "tenable_json"),
                ("sample.nessus", "nessus_xml"),
            ]
            for fixture_name, source_type in fixture_imports:
                submitted = upload_import(admin, admin_csrf, fixture_name, source_type)
                completed = wait_for_import(admin, submitted["id"])
                imported_ids.append(completed["id"])
                summary["imports"][source_type] = {
                    "id": completed["id"],
                    "total_records": completed["total_records"],
                    "included_records": completed["included_records"],
                    "skipped_records": completed["skipped_records"],
                    "new_assets": completed["new_assets"],
                    "matched_assets": completed["matched_assets"],
                    "ambiguous_assets": completed["ambiguous_assets"],
                }

            generic_mapping = {
                "fqdn": "Server Name",
                "ip_address": "Address",
                "plugin_id": "Check",
                "severity": "Rating",
                "first_found": "First Seen",
                "solution": "Fix",
            }
            generic_preview = json_response(
                admin.post(
                    "/api/v1/imports/generic/preview",
                    headers=mutation_headers(admin_csrf),
                    files={
                        "upload": (
                            "generic.csv",
                            (FIXTURES / "generic.csv").read_bytes(),
                            "text/csv",
                        )
                    },
                    data={"mapping_json": json.dumps(generic_mapping)},
                ),
                200,
            )
            check(len(generic_preview["records"]) == 2, "Generic CSV preview did not return two rows.")
            check(
                "Unused Column" in generic_preview["unmapped_columns"],
                "Generic CSV preview did not identify its unmapped column.",
            )
            generic_submitted = json_response(
                admin.post(
                    "/api/v1/imports/generic/commit",
                    headers=mutation_headers(admin_csrf),
                    json={
                        "source_file_id": generic_preview["source_file_id"],
                        "mapping": generic_mapping,
                        "profile_name": "Validation generic mapping",
                        "share_profile": True,
                        "complete_comparable_scope": False,
                        "force_reprocess": False,
                    },
                ),
                202,
            )
            generic_completed = wait_for_import(admin, generic_submitted["id"])
            imported_ids.append(generic_completed["id"])
            summary["imports"]["generic_csv"] = {
                "id": generic_completed["id"],
                "total_records": generic_completed["total_records"],
                "included_records": generic_completed["included_records"],
                "unmapped_columns": generic_preview["unmapped_columns"],
            }

            base_query = {"schema_version": 1}
            before_duplicate = json_response(
                admin.post(
                    "/api/v1/assets/query",
                    json={"query": base_query, "page": 1, "page_size": 200},
                ),
                200,
            )
            duplicate = upload_import(admin, admin_csrf, "tenable_vm.csv", "tenable_csv")
            check(
                duplicate["duplicate_of_import_id"] == summary["imports"]["tenable_csv"]["id"],
                "Duplicate upload did not reference the original completed import.",
            )
            after_duplicate = json_response(
                admin.post(
                    "/api/v1/assets/query",
                    json={"query": base_query, "page": 1, "page_size": 200},
                ),
                200,
            )
            check(
                before_duplicate["total"] == after_duplicate["total"],
                "Duplicate upload changed the canonical asset count.",
            )
            summary["checks"].append("duplicate_upload_no_reprocessing")

            assets_by_hostname = {item["canonical_hostname"]: item for item in after_duplicate["items"]}
            app_asset = assets_by_hostname.get("app-01.example.test")
            db_asset = assets_by_hostname.get("db-01.example.test")
            check(
                app_asset is not None and db_asset is not None,
                "Base scanner imports did not create expected assets.",
            )

            conflict_submitted = upload_import(
                admin,
                admin_csrf,
                "identity-conflict.csv",
                "tenable_csv",
                content=create_conflict_csv(),
            )
            conflict_completed = wait_for_import(admin, conflict_submitted["id"])
            check(
                conflict_completed["ambiguous_assets"] >= 1,
                "Synthetic strong-identifier conflict was not routed to identity review.",
            )
            reviews = json_response(admin.get("/api/v1/identity/review"), 200)
            review = next(
                (item for item in reviews if item["source_import_id"] == conflict_completed["id"]),
                None,
            )
            check(review is not None, "Identity-review item for the synthetic conflict was not found.")
            resolved_review = json_response(
                admin.post(
                    f"/api/v1/identity/review/{review['id']}/resolve",
                    headers=mutation_headers(admin_csrf),
                    json={
                        "action": "match_existing",
                        "asset_id": app_asset["id"],
                        "reason": "Synthetic validation conflict matched to the known app asset.",
                    },
                ),
                200,
            )
            check(resolved_review["status"] == "resolved", "Identity-review resolution did not persist.")
            summary["imports"]["identity_conflict"] = {
                "id": conflict_completed["id"],
                "review_id": review["id"],
                "resolved_asset_id": app_asset["id"],
            }
            summary["checks"].append("manual_identity_review_resolution")

            preview = json_response(
                admin.post(
                    "/api/v1/assets/query/preview",
                    json={"query": base_query},
                ),
                200,
            )
            current_hosts = json_response(
                admin.post(
                    "/api/v1/assets/query",
                    json={"query": base_query, "page": 1, "page_size": 200},
                ),
                200,
            )
            check(
                preview["matching_host_count"] == current_hosts["total"],
                "Host preview and paginated host list returned different totals.",
            )
            check(
                current_hosts["total"] >= 5, "Expected at least five canonical assets after fixture imports."
            )
            mac_query = json_response(
                admin.post(
                    "/api/v1/assets/query",
                    json={
                        "query": {
                            "schema_version": 1,
                            "mac_addresses": ["00:11:22:33:44:55"],
                        },
                        "page": 1,
                        "page_size": 20,
                    },
                ),
                200,
            )
            check(mac_query["total"] == 1, "Normalized MAC-address query did not match exactly one asset.")
            injection_query = json_response(
                admin.post(
                    "/api/v1/assets/query",
                    json={
                        "query": {"schema_version": 1, "q": "' OR 1=1 --"},
                        "page": 1,
                        "page_size": 20,
                    },
                ),
                200,
            )
            check(
                injection_query["total"] < current_hosts["total"],
                "Free-text query treated an injection-like string as executable query syntax.",
            )
            summary["host_count"] = current_hosts["total"]
            summary["finding_count_estimate"] = preview["estimated_matching_finding_count"]
            summary["checks"].extend(
                [
                    "shared_query_semantics",
                    "mac_normalization",
                    "query_parameterization",
                ]
            )

            expect(
                admin.patch(
                    f"/api/v1/assets/{app_asset['id']}",
                    json={"system_owner": "Missing CSRF should fail"},
                ),
                403,
            )
            with httpx.Client(base_url=BASE_URL, timeout=30) as anonymous:
                expect(
                    anonymous.post(
                        "/api/v1/assets/query",
                        json={"query": base_query, "page": 1, "page_size": 20},
                    ),
                    401,
                )
            summary["checks"].extend(["csrf_enforced", "authentication_enforced"])

            json_response(
                admin.patch(
                    f"/api/v1/assets/{app_asset['id']}",
                    headers=mutation_headers(admin_csrf),
                    json={"system_owner": "Snapshot Owner"},
                ),
                200,
            )
            json_response(
                admin.patch(
                    f"/api/v1/assets/{db_asset['id']}",
                    headers=mutation_headers(admin_csrf),
                    json={"system_owner": "=2+2"},
                ),
                200,
            )

            saved_view = json_response(
                admin.post(
                    "/api/v1/saved-views",
                    headers=mutation_headers(admin_csrf),
                    json={
                        "name": "All canonical hosts - validation",
                        "description": "Synthetic end-to-end validation scope",
                        "shared": True,
                        "query": base_query,
                    },
                ),
                201,
            )
            xlsx_export = create_export(
                admin,
                admin_csrf,
                asset_scope={"mode": "saved_view", "saved_view_id": saved_view["id"]},
                output_format="xlsx",
            )
            check(
                xlsx_export["matched_host_count"] == current_hosts["total"],
                "Saved-view export did not snapshot the same host set as preview/list.",
            )
            json_response(
                admin.put(
                    f"/api/v1/saved-views/{saved_view['id']}",
                    headers=mutation_headers(admin_csrf),
                    json={
                        "name": "All canonical hosts - validation",
                        "description": "Edited after export submission",
                        "shared": True,
                        "query": {
                            "schema_version": 1,
                            "canonical_hostnames": ["db-01.example.test"],
                        },
                    },
                ),
                200,
            )
            json_response(
                admin.patch(
                    f"/api/v1/assets/{app_asset['id']}",
                    headers=mutation_headers(admin_csrf),
                    json={"system_owner": "Changed After Snapshot"},
                ),
                200,
            )
            xlsx_completed = wait_for_export(admin, xlsx_export["id"])
            xlsx_path, xlsx_hash = download_export(
                admin,
                xlsx_export["id"],
                "maintenance-window-validation.xlsx",
            )
            verify_xlsx(xlsx_path, xlsx_export["matched_host_count"])

            csv_export = create_export(
                admin,
                admin_csrf,
                asset_scope={"mode": "host_query", "query": base_query},
                output_format="csv",
            )
            csv_completed = wait_for_export(admin, csv_export["id"])
            csv_path, csv_hash = download_export(
                admin,
                csv_export["id"],
                "maintenance-window-validation-csv.zip",
            )
            verify_csv_bundle(csv_path)

            html_export = create_export(
                admin,
                admin_csrf,
                asset_scope={
                    "mode": "selected_assets",
                    "asset_ids": [app_asset["id"], db_asset["id"]],
                },
                output_format="html",
            )
            html_completed = wait_for_export(admin, html_export["id"])
            html_path, html_hash = download_export(
                admin,
                html_export["id"],
                "maintenance-window-validation.html",
            )
            verify_html(html_path)

            summary["exports"] = {
                "xlsx": {
                    "id": xlsx_completed["id"],
                    "path": str(xlsx_path),
                    "sha256": xlsx_hash,
                    "matched_host_count": xlsx_completed["matched_host_count"],
                    "matched_finding_count": xlsx_completed["matched_finding_count"],
                },
                "csv": {
                    "id": csv_completed["id"],
                    "path": str(csv_path),
                    "sha256": csv_hash,
                    "matched_host_count": csv_completed["matched_host_count"],
                    "matched_finding_count": csv_completed["matched_finding_count"],
                },
                "html": {
                    "id": html_completed["id"],
                    "path": str(html_path),
                    "sha256": html_hash,
                    "matched_host_count": html_completed["matched_host_count"],
                    "matched_finding_count": html_completed["matched_finding_count"],
                },
            }
            summary["checks"].extend(
                [
                    "selected_query_saved_view_export_modes",
                    "durable_export_snapshot",
                    "saved_view_revision_snapshot",
                    "xlsx_provenance_and_formula_safety",
                    "csv_provenance_and_formula_safety",
                    "html_provenance_and_formula_safety",
                ]
            )

            with httpx.Client(base_url=BASE_URL, timeout=30, follow_redirects=True) as reader_client:
                reader_session = json_response(
                    reader_client.post(
                        "/api/v1/auth/login",
                        json={
                            "username": READ_ONLY_USERNAME,
                            "password": READ_ONLY_PASSWORD,
                        },
                    ),
                    200,
                )
                reader_csrf = reader_session["csrf_token"]
                check(
                    reader_session["user"]["role"] == "read_only",
                    "Reader session did not retain read-only role.",
                )
                reader_hosts = json_response(
                    reader_client.post(
                        "/api/v1/assets/query",
                        json={"query": base_query, "page": 1, "page_size": 20},
                    ),
                    200,
                )
                check(
                    reader_hosts["total"] == current_hosts["total"],
                    "Read-only user could not read the canonical host inventory.",
                )
                expect(reader_client.get("/api/v1/users"), 403)
                expect(
                    reader_client.post(
                        "/api/v1/imports/upload",
                        headers=mutation_headers(reader_csrf),
                        files={
                            "upload": (
                                "tenable_vm.csv",
                                (FIXTURES / "tenable_vm.csv").read_bytes(),
                                "text/csv",
                            )
                        },
                        data={"source_type": "tenable_csv"},
                    ),
                    403,
                )
                reader_view = json_response(
                    reader_client.post(
                        "/api/v1/saved-views",
                        headers=mutation_headers(reader_csrf),
                        json={
                            "name": "Reader personal view - validation",
                            "description": "Personal read-only reporting view",
                            "shared": False,
                            "query": {
                                "schema_version": 1,
                                "canonical_hostnames": ["db-01.example.test"],
                            },
                        },
                    ),
                    201,
                )
                reader_export = create_export(
                    reader_client,
                    reader_csrf,
                    asset_scope={"mode": "saved_view", "saved_view_id": reader_view["id"]},
                    output_format="html",
                )
                reader_completed = wait_for_export(reader_client, reader_export["id"])
                reader_path, reader_hash = download_export(
                    reader_client,
                    reader_export["id"],
                    "reader-owned-validation.html",
                )
                expect(
                    reader_client.get(f"/api/v1/exports/{xlsx_export['id']}/download"),
                    404,
                )
                summary["exports"]["read_only_owned"] = {
                    "id": reader_completed["id"],
                    "path": str(reader_path),
                    "sha256": reader_hash,
                }
            summary["checks"].extend(
                [
                    "read_only_inventory_access",
                    "read_only_admin_mutation_denied",
                    "read_only_personal_view_and_export",
                    "export_owner_permission_check",
                ]
            )

            audit = json_response(
                admin.get("/api/v1/audit", params={"page": 1, "page_size": 200}),
                200,
            )
            audit_types = {item["event_type"] for item in audit["items"]}
            required_audit_types = {
                "auth.first_run_admin_created",
                "user.created",
                "import.submitted",
                "import.completed",
                "import.duplicate_detected",
                "identity.review_resolved",
                "export.previewed",
                "export.submitted",
                "export.completed",
                "export.downloaded",
            }
            missing_audit_types = sorted(required_audit_types - audit_types)
            check(
                not missing_audit_types,
                f"Audit history is missing required event types: {missing_audit_types}",
            )
            summary["audit_event_count"] = audit["total"]
            summary["audit_types_verified"] = sorted(required_audit_types)
            summary["checks"].append("audit_and_export_provenance")

        summary["status"] = "passed"
        summary["completed_at_epoch"] = time.time()
        summary_path = OUTPUT_DIR / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        summary["status"] = "failed"
        summary["failure"] = f"{type(exc).__name__}: {exc}"
        summary["completed_at_epoch"] = time.time()
        summary_path = OUTPUT_DIR / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        print(summary["failure"], file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
