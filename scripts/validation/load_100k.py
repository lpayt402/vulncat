from __future__ import annotations

import csv
import hashlib
import json
import os
import sys
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = ROOT / "tmp" / "load-100k"
CSV_PATH = OUTPUT_DIR / "scanner-100k.csv"
XLSX_PATH = OUTPUT_DIR / "vulnerability-workbench-100k-validation.xlsx"
SUMMARY_PATH = OUTPUT_DIR / "summary.json"

if os.environ.get("VULNERABILITY_WORKBENCH_DISPOSABLE_TEST") != "1":
    raise SystemExit("Use this validator only with an explicitly designated disposable synthetic test stack.")
BASE_URL = os.environ["VULNERABILITY_WORKBENCH_TEST_BASE_URL"].rstrip("/")
ADMIN_USERNAME = os.environ.get("VULNERABILITY_WORKBENCH_TEST_ADMIN_USERNAME", "validation-admin")
ADMIN_PASSWORD = os.environ["VULNERABILITY_WORKBENCH_TEST_ADMIN_PASSWORD"]

ASSET_COUNT = 100
FINDINGS_PER_ASSET = 1_000
EXPECTED_FINDINGS = ASSET_COUNT * FINDINGS_PER_ASSET

HEADERS = [
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


class ValidationFailure(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationFailure(message)


def expect(response: httpx.Response, *status_codes: int) -> httpx.Response:
    if response.status_code not in status_codes:
        raise ValidationFailure(
            f"{response.request.method} {response.request.url} returned "
            f"{response.status_code}, expected {status_codes}: {response.text[:2_000]}"
        )
    return response


def json_response(response: httpx.Response, *status_codes: int) -> Any:
    return expect(response, *status_codes).json()


def generate_csv() -> tuple[int, str]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    log(f"Generating {EXPECTED_FINDINGS:,}-row scanner CSV fixture...")
    with CSV_PATH.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(HEADERS)
        for asset_index in range(ASSET_COUNT):
            asset_uuid = uuid.uuid5(
                uuid.NAMESPACE_DNS,
                f"vulnerability-workbench-load-asset-{asset_index:03d}.invalid",
            )
            agent_uuid = uuid.uuid5(
                uuid.NAMESPACE_DNS,
                f"vulnerability-workbench-load-agent-{asset_index:03d}.invalid",
            )
            fqdn = f"load-{asset_index:03d}.workbench.invalid"
            for plugin_index in range(FINDINGS_PER_ASSET):
                plugin_id = str(900_000 + plugin_index)
                severity = "Medium" if plugin_index % 2 == 0 else "Low"
                writer.writerow(
                    [
                        str(asset_uuid),
                        str(agent_uuid),
                        fqdn,
                        "",
                        "",
                        "Vulnerability Workbench Load Test OS",
                        "load-100k;synthetic",
                        plugin_id,
                        f"Synthetic load finding {plugin_id}",
                        "Vulnerability Workbench Validation",
                        severity,
                        severity,
                        "6.0" if severity == "Medium" else "3.0",
                        "4.0" if severity == "Medium" else "2.0",
                        f"CVE-2026-{plugin_index:04d}",
                        1_000 + (plugin_index % 50),
                        "tcp",
                        "synthetic",
                        "Synthetic scalability validation",
                        "Safe generated data used only to validate Vulnerability Workbench capacity.",
                        "Apply the synthetic validation update.",
                        f"Generated evidence for asset {asset_index:03d}, plugin {plugin_id}.",
                        "2026-01-01T00:00:00Z",
                        "2026-07-15T00:00:00Z",
                        "2025-12-01",
                        "2026-01-15",
                        "no",
                        "no",
                        "vulnerability-workbench-100k-load-validation",
                        "2026-07-15T01:00:00Z",
                    ]
                )
    digest = hashlib.sha256()
    with CSV_PATH.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return CSV_PATH.stat().st_size, digest.hexdigest()


def wait_for_import(
    client: httpx.Client,
    import_id: str,
    *,
    timeout_seconds: float = 1_800,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    next_log = 0.0
    while time.monotonic() < deadline:
        result = json_response(client.get(f"/api/v1/imports/{import_id}"), 200)
        if result["status"] == "completed":
            return result
        if result["status"] == "failed":
            raise ValidationFailure(
                f"Import {import_id} failed: {result.get('failure_reason') or result.get('job')}"
            )
        now = time.monotonic()
        if now >= next_log:
            job = result.get("job") or {}
            log(
                f"Import status={result['status']}, progress={job.get('progress', 0)}%, "
                f"records={result.get('total_records', 0):,}"
            )
            next_log = now + 15
        time.sleep(2)
    raise ValidationFailure(f"Import {import_id} exceeded {timeout_seconds:.0f} seconds.")


def wait_for_export(
    client: httpx.Client,
    export_id: str,
    *,
    timeout_seconds: float = 1_800,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    next_log = 0.0
    while time.monotonic() < deadline:
        result = json_response(client.get(f"/api/v1/exports/{export_id}"), 200)
        if result["status"] == "completed":
            return result
        if result["status"] in {"failed", "cancelled"}:
            raise ValidationFailure(
                f"Export {export_id} ended as {result['status']}: {result.get('failure_reason')}"
            )
        now = time.monotonic()
        if now >= next_log:
            log(f"Export status={result['status']}, progress={result['progress']}%")
            next_log = now + 15
        time.sleep(2)
    raise ValidationFailure(f"Export {export_id} exceeded {timeout_seconds:.0f} seconds.")


def verify_xlsx(path: Path) -> None:
    check(path.is_file() and path.stat().st_size > 0, "XLSX artifact is missing or empty.")
    with zipfile.ZipFile(path) as archive:
        workbook_xml = archive.read("xl/workbook.xml").decode("utf-8")
        check("Host Summary" in workbook_xml, "XLSX is missing the Host Summary sheet.")
        check("Finding Detail" in workbook_xml, "XLSX is missing the Finding Detail sheet.")
        check("Export Metadata" in workbook_xml, "XLSX is missing the Export Metadata sheet.")


def main() -> int:
    summary: dict[str, Any] = {
        "status": "running",
        "base_url": BASE_URL,
        "asset_count_expected": ASSET_COUNT,
        "finding_count_expected": EXPECTED_FINDINGS,
        "started_at_epoch": time.time(),
    }
    try:
        csv_bytes, csv_sha256 = generate_csv()
        summary["input"] = {
            "path": str(CSV_PATH),
            "byte_size": csv_bytes,
            "sha256": csv_sha256,
        }
        log(f"Fixture ready: {csv_bytes / (1024 * 1024):.1f} MiB")

        timeout = httpx.Timeout(1_200, connect=30)
        with httpx.Client(
            base_url=BASE_URL,
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            expect(client.get("/readyz"), 200)
            session = json_response(
                client.post(
                    "/api/v1/auth/login",
                    json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
                ),
                200,
            )
            csrf_token = session["csrf_token"]
            headers = {"X-CSRF-Token": csrf_token}

            log("Uploading fixture through the Vulnerability Workbench import API...")
            upload_started = time.monotonic()
            with CSV_PATH.open("rb") as upload:
                submitted = json_response(
                    client.post(
                        "/api/v1/imports/upload",
                        headers=headers,
                        files={"upload": (CSV_PATH.name, upload, "text/csv")},
                        data={
                            "source_type": "tenable_csv",
                            "force_reprocess": "false",
                            "complete_comparable_scope": "false",
                        },
                    ),
                    202,
                )
            upload_seconds = time.monotonic() - upload_started
            log(f"Upload accepted in {upload_seconds:.1f}s; import id {submitted['id']}")

            import_started = time.monotonic()
            completed_import = wait_for_import(client, submitted["id"])
            import_seconds = time.monotonic() - import_started
            check(
                completed_import["total_records"] == EXPECTED_FINDINGS,
                f"Import read {completed_import['total_records']:,} rows, expected {EXPECTED_FINDINGS:,}.",
            )
            check(
                completed_import["included_records"] == EXPECTED_FINDINGS,
                "Not all generated Medium/Low rows were included.",
            )
            check(
                completed_import["new_findings"] == EXPECTED_FINDINGS,
                f"Import created {completed_import['new_findings']:,} findings, "
                f"expected {EXPECTED_FINDINGS:,}.",
            )
            log(
                f"Import completed in {import_seconds:.1f}s: "
                f"{completed_import['new_assets']:,} assets, "
                f"{completed_import['new_findings']:,} findings"
            )

            query = {"schema_version": 1, "q": "load-"}
            query_started = time.monotonic()
            hosts = json_response(
                client.post(
                    "/api/v1/assets/query",
                    json={"query": query, "page": 1, "page_size": 200},
                ),
                200,
            )
            preview = json_response(
                client.post(
                    "/api/v1/assets/query/preview",
                    json={
                        "query": query,
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
                    },
                ),
                200,
            )
            query_seconds = time.monotonic() - query_started
            check(hosts["total"] == ASSET_COUNT, f"Query matched {hosts['total']} assets, expected 100.")
            check(
                preview["estimated_matching_finding_count"] == EXPECTED_FINDINGS,
                f"Query counted {preview['estimated_matching_finding_count']:,} findings, "
                f"expected {EXPECTED_FINDINGS:,}.",
            )
            log(f"Query and finding count completed in {query_seconds:.1f}s")

            log("Creating a durable 100,000-finding XLSX export snapshot...")
            snapshot_started = time.monotonic()
            submitted_export = json_response(
                client.post(
                    "/api/v1/exports",
                    headers=headers,
                    json={
                        "asset_scope": {"mode": "host_query", "query": query},
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
                        "format": "xlsx",
                        "confirm_large_export": True,
                    },
                ),
                202,
            )
            snapshot_seconds = time.monotonic() - snapshot_started
            check(
                submitted_export["matched_finding_count"] == EXPECTED_FINDINGS,
                "The export snapshot did not contain all 100,000 findings.",
            )
            log(f"Export snapshot queued in {snapshot_seconds:.1f}s")

            export_started = time.monotonic()
            completed_export = wait_for_export(client, submitted_export["id"])
            export_seconds = time.monotonic() - export_started
            log(f"XLSX generation completed in {export_seconds:.1f}s")

            log("Downloading and checking the generated workbook...")
            digest = hashlib.sha256()
            with client.stream(
                "GET",
                f"/api/v1/exports/{completed_export['id']}/download",
            ) as response:
                expect(response, 200)
                with XLSX_PATH.open("wb") as output:
                    for chunk in response.iter_bytes():
                        output.write(chunk)
                        digest.update(chunk)
                advertised_sha256 = response.headers.get("X-Content-SHA256")
            xlsx_sha256 = digest.hexdigest()
            check(
                not advertised_sha256 or advertised_sha256 == xlsx_sha256,
                "Downloaded workbook hash does not match the server hash.",
            )
            check(
                completed_export["output_sha256"] == xlsx_sha256,
                "Downloaded workbook hash does not match export metadata.",
            )
            verify_xlsx(XLSX_PATH)

            summary.update(
                {
                    "status": "passed",
                    "import": {
                        "id": completed_import["id"],
                        "total_records": completed_import["total_records"],
                        "included_records": completed_import["included_records"],
                        "new_assets": completed_import["new_assets"],
                        "new_findings": completed_import["new_findings"],
                        "upload_seconds": round(upload_seconds, 3),
                        "processing_seconds": round(import_seconds, 3),
                    },
                    "query": {
                        "matching_host_count": hosts["total"],
                        "matching_finding_count": preview["estimated_matching_finding_count"],
                        "seconds": round(query_seconds, 3),
                    },
                    "export": {
                        "id": completed_export["id"],
                        "matched_host_count": completed_export["matched_host_count"],
                        "matched_finding_count": completed_export["matched_finding_count"],
                        "snapshot_seconds": round(snapshot_seconds, 3),
                        "generation_seconds": round(export_seconds, 3),
                        "path": str(XLSX_PATH),
                        "byte_size": XLSX_PATH.stat().st_size,
                        "sha256": xlsx_sha256,
                    },
                    "completed_at_epoch": time.time(),
                }
            )
            log(
                f"PASS: {EXPECTED_FINDINGS:,} findings imported, queried, snapshotted, "
                "exported, downloaded, and verified."
            )
    except Exception as exc:
        summary.update(
            {
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "completed_at_epoch": time.time(),
            }
        )
        log(f"FAILED: {summary['error']}")
        SUMMARY_PATH.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        return 1

    SUMMARY_PATH.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
