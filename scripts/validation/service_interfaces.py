"""Real browser/CLI/MCP parity on the explicitly disposable local QA application."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

ORIGIN = "http://127.0.0.1:8787"
OUTPUT = Path("output/playwright")


async def mcp_reports(session_file: Path, expected: dict[str, Any]) -> dict[str, str]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from vulnbatch.reporting import REPORT_COLUMNS, render_payload

    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "vulnbatch.mcp_server", "--session-file", str(session_file)],
        env=dict(os.environ),
    )
    formats: dict[str, str] = {}
    async with stdio_client(parameters) as (reader, writer), ClientSession(reader, writer) as session:
        await session.initialize()
        listed = await session.list_tools()
        assert "exposure_report" in {tool.name for tool in listed.tools}
        for format in ("json", "csv", "markdown"):
            result = await session.call_tool("exposure_report", {"limit": 50, "format": format})
            assert not result.isError, result
            structured = result.structuredContent
            assert structured and structured["ok"] is True
            assert structured["data"] == expected
            assert structured["formatted"] == render_payload(expected, format, REPORT_COLUMNS)
            formats[format] = "passed"
        denied = await session.call_tool(
            "exposure_undo",
            {
                "decision_id": str(secrets.token_hex(16)),
                "expected_revision": 0,
                "request_key": "denied-qa",
                "reason": "Denied mutation",
                "confirm": True,
            },
        )
        assert denied.isError
    return formats


def main() -> None:
    if os.environ.get("VWB_SERVICE_QA") != "1":
        raise RuntimeError("Run only against an explicitly disposable QA database")
    from playwright.sync_api import expect, sync_playwright
    from sqlalchemy import select
    from sqlalchemy.engine import make_url

    from vulnbatch.client.transport import ApiClient
    from vulnbatch.core.security import hash_password
    from vulnbatch.db.models import Role, User
    from vulnbatch.db.session import SessionLocal
    from vulnbatch.reporting import REPORT_COLUMNS, render_payload

    database = make_url(os.environ["DATABASE_URL"])
    if (
        database.drivername != "postgresql+psycopg"
        or database.host != "127.0.0.1"
        or database.port != 5432
        or database.database != "vwb_test"
    ):
        raise RuntimeError("QA requires the fixed disposable CI PostgreSQL database")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    private_dir = Path(".validation-temp")
    private_dir.mkdir(exist_ok=True)
    session_file = private_dir / ("service-qa-session-" + secrets.token_hex(6) + ".json")
    username, password = "service-qa-" + secrets.token_hex(6), secrets.token_urlsafe(32)
    with SessionLocal.begin() as db:
        role = db.scalar(select(Role).where(Role.name == "administrator"))
        if role is None:
            role = Role(name="administrator")
            db.add(role)
            db.flush()
        db.add(
            User(
                username=username,
                display_name="Synthetic example reviewer",
                password_hash=hash_password(password),
                role_id=role.id,
            )
        )
    with (OUTPUT / "service-server.log").open("w") as log:
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "vulnbatch.main:app", "--host", "127.0.0.1", "--port", "8787"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(120):
                try:
                    ready = httpx.get(ORIGIN + "/readyz", timeout=1, trust_env=False)
                    if ready.status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if server.poll() is not None:
                    raise RuntimeError("QA application exited")
                time.sleep(0.25)
            else:
                raise RuntimeError("QA application readiness timeout")
            with ApiClient(session_file=session_file) as client:
                client.login(username, password)
                spec = importlib.util.spec_from_file_location(
                    "synthetic_loader", "examples/service-exposure/load.py"
                )
                assert spec and spec.loader
                loader = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(loader)
                seeded = loader.load_example(client)
                ids = seeded["node_ids"]
                report = seeded["report"]
                by_ref = {
                    item["evidence"]["raw"]["fixture_ref"]: item
                    for item in report["items"]
                    if item["evidence"].get("raw", {}).get("fixture_ref")
                }
                assert by_ref["vip-tls"]["node_id"] == ids["vip"]
                assert by_ref["vip-tls"]["service_id"] is None
                assert by_ref["checkout-vuln"]["service_id"] == ids["checkout"]
                assert by_ref["management-vuln"]["service_id"] is None
                assert by_ref["mgmt-unreachable"]["observation_kind"] == "coverage"
                assert by_ref["mgmt-unreachable"]["coverage_outcome"] == "unreachable"
                assert by_ref["data-scan"]["coverage_outcome"] == "successful"
                assert by_ref["directory-logon"]["age_days"] is None
                assert by_ref["unknown-fingerprint"]["age_days"] is None
                assert ids["east-a"] != ids["west-a"]
                service_report = client._request(
                    "GET", "/api/v1/exposure/report", params={"node_id": ids["checkout"]}
                )
                assert service_report["total"] == 1
                node = client._request("GET", "/api/v1/exposure/nodes/" + ids["east-a"])
                assert node["node"]["facts"]["fingerprint"] == "Ubuntu 24.04"
                assert node["fact_total"] == 2
                assert node["node"]["fact_summary"]["has_disagreement"]
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch()
                    context = browser.new_context(
                        viewport={"width": 1440, "height": 1100}, reduced_motion="reduce"
                    )
                    context.tracing.start(screenshots=True, snapshots=True)
                    page = context.new_page()
                    page.set_default_timeout(15_000)
                    errors: list[str] = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(ORIGIN)
                    page.get_by_label(re.compile(r"^Username\b")).fill(username)
                    page.get_by_label(re.compile(r"^Password\b")).fill(password)
                    page.get_by_role("button", name="Sign in", exact=True).click()
                    page.get_by_role("link", name="Services & exposure", exact=True).click()
                    page.get_by_role("button", name=re.compile(r"^Select Checkout application \(")).click()
                    expect(page.get_by_text("SYNTHETIC-HTTP-002", exact=True)).to_be_visible()
                    expect(page.get_by_text("SYNTHETIC-TLS-001", exact=True)).to_have_count(0)
                    page.evaluate("scrollTo(0, 0)")
                    page.screenshot(path=str(OUTPUT / "services-light.png"), full_page=True)
                    page.get_by_role("button", name="Switch to dark theme", exact=True).click()
                    page.reload()
                    expect(page.locator("html")).to_have_attribute("data-mantine-color-scheme", "dark")
                    page.get_by_role("button", name=re.compile(r"^Select Shared HTTPS VIP \(")).click()
                    expect(page.get_by_text("SYNTHETIC-TLS-001", exact=True)).to_be_visible()
                    page.evaluate("scrollTo(0, 0)")
                    page.screenshot(path=str(OUTPUT / "services-dark.png"), full_page=True)
                    page.get_by_role("button", name="Review all observations", exact=True).click()
                    page.get_by_role(
                        "button", name="Review attribution for SYNTHETIC-TLS-001", exact=True
                    ).click()
                    dialog = page.get_by_role("dialog", name="Review observation attribution")
                    dialog.get_by_label("Target for this observation", exact=True).select_option(
                        ids["checkout-https"]
                    )
                    dialog.get_by_role(
                        "textbox", name=re.compile(r"^Reason for attribution(?:\s*\*)?$")
                    ).fill("Fictional browser attribution correction")
                    dialog.get_by_role("button", name="Preview attribution", exact=True).click()
                    dialog.get_by_label(
                        "I reviewed this attribution and want to save it.", exact=True
                    ).check()
                    with page.expect_response(
                        lambda r: r.request.method == "POST" and r.url.endswith("/exposure/apply")
                    ) as applied:
                        dialog.get_by_role("button", name="Apply reviewed attribution", exact=True).click()
                    assert applied.value.status == 200, applied.value.text()
                    decision = applied.value.json()["decision_id"]
                    expect(dialog).not_to_be_visible()
                    page.get_by_role("tab", name="Change history", exact=True).click()
                    page.get_by_role("button", name="Undo change " + decision, exact=True).click()
                    undo = page.get_by_role("dialog", name="Review undo of connection change")
                    undo.get_by_role("textbox", name=re.compile(r"^Reason for undo(?:\s*\*)?$")).fill(
                        "Restore hypothetical VIP attribution"
                    )
                    undo.get_by_label("I reviewed this change and want to undo it.", exact=True).check()
                    with page.expect_response(
                        lambda r: r.request.method == "POST" and r.url.endswith("/exposure/undo")
                    ) as undone:
                        undo.get_by_role("button", name="Confirm undo", exact=True).click()
                    assert undone.value.status == 200, undone.value.text()
                    page.get_by_role("tab", name="Exposure", exact=True).click()
                    page.get_by_role("button", name="Review all observations", exact=True).click()
                    with page.expect_response(
                        lambda r: "/exposure/report?" in r.url and r.request.method == "GET"
                    ) as browser_report:
                        page.get_by_role("button", name="Refresh exposure", exact=True).click()
                    gui_report = browser_report.value.json()
                    page.get_by_label("Download format", exact=True).select_option("json")
                    with page.expect_download() as download:
                        page.get_by_role("button", name="Download current page", exact=True).click()
                    downloaded = OUTPUT / "exposure-page.json"
                    download.value.save_as(downloaded)
                    assert json.loads(downloaded.read_text()) == gui_report
                    page.set_viewport_size({"width": 390, "height": 844})
                    page.keyboard.press("Tab")
                    page.locator(".vb-skip-link").focus()
                    page.keyboard.press("Enter")
                    expect(page.locator("#main-content")).to_be_focused()
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    assert page.evaluate("matchMedia('(prefers-reduced-motion: reduce)').matches")
                    page.evaluate("scrollTo(0, 0)")
                    page.screenshot(path=str(OUTPUT / "services-mobile.png"), full_page=True)
                    assert not errors, errors
                    context.tracing.stop(path=str(OUTPUT / "service-trace.zip"))
                    browser.close()
                expected = client._request("GET", "/api/v1/exposure/report", params={"limit": 50})
                assert expected["items"] == gui_report["items"]
                formats = {}
                for format in ("json", "csv", "markdown"):
                    command = [
                        sys.executable,
                        "-m",
                        "vulnbatch.cli",
                        "--session-file",
                        str(session_file),
                        "--format",
                        format,
                        "exposure",
                        "report",
                        "--limit",
                        "50",
                    ]
                    completed = subprocess.run(  # noqa: S603 -- fixed local CLI and arguments
                        command, capture_output=True, text=True, check=True, timeout=60
                    )
                    assert completed.stdout == render_payload(expected, format, REPORT_COLUMNS)
                    assert not completed.stderr
                    formats[format] = "passed"
                mcp = asyncio.run(mcp_reports(session_file, expected))
                client.logout()
                summary = {
                    "synthetic": True,
                    "observations": expected["total"],
                    "gui_cli_mcp_parity": True,
                    "cli_formats": formats,
                    "mcp_formats": mcp,
                    "browser_attribution_undo": True,
                    "dark_persisted": True,
                    "mobile_no_overflow": True,
                    "reduced_motion": True,
                    "javascript_errors": errors,
                }
                (OUTPUT / "service-interfaces.json").write_text(json.dumps(summary, indent=2))
                print(json.dumps(summary))
        finally:
            server.terminate()
            server.wait(timeout=15)


if __name__ == "__main__":
    main()
