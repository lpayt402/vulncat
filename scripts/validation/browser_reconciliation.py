"""Real Chromium QA against a fresh disposable PostgreSQL CI application."""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen


def main() -> None:
    if os.environ.get("VWB_BROWSER_QA") != "1":
        raise RuntimeError("Run only in the disposable CI browser QA job")
    from playwright.sync_api import expect, sync_playwright

    output = Path("output/playwright")
    output.mkdir(parents=True, exist_ok=True)
    origin = "http://127.0.0.1:8787"
    now = datetime.now(UTC).isoformat()
    fixture = [
        {"native_id": "qa-a", "hostname": "qa-a.example.test", "ip": "192.0.2.20", "observed_at": now},
        {"native_id": "qa-b", "hostname": "qa-b.example.test", "ip": "192.0.2.21", "observed_at": now},
        {"native_id": "", "hostname": "qa-alias.example.test", "ip": "192.0.2.20", "observed_at": now},
        {
            "native_id": "qa-a-duplicate",
            "hostname": "qa-a.example.test",
            "ip": "192.0.2.22",
            "observed_at": now,
        },
        {"native_id": "qa-id-only", "hostname": "", "ip": "", "observed_at": now},
    ]
    export = output / "synthetic.json"
    export.write_text(json.dumps(fixture))
    with (output / "server.log").open("w") as log:
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "vulnbatch.main:app", "--host", "127.0.0.1", "--port", "8787"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(120):
                try:
                    with urlopen(origin + "/readyz", timeout=1):  # noqa: S310 -- fixed loopback URL
                        break
                except URLError:
                    if server.poll() is not None:
                        raise RuntimeError("QA application exited; inspect server.log") from None
                    time.sleep(0.25)
            else:
                raise RuntimeError("QA application did not become ready")
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                context = browser.new_context(viewport={"width": 1440, "height": 1100})
                context.tracing.start(screenshots=True, snapshots=True)
                page = context.new_page()
                page.set_default_timeout(15_000)
                errors: list[str] = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                try:
                    page.goto(origin)
                    page.get_by_label(re.compile(r"^Username\b")).fill("synthetic-browser")
                    page.get_by_label(re.compile(r"^Display name\b")).fill("Synthetic QA")
                    password = secrets.token_urlsafe(24)
                    page.get_by_label(re.compile(r"^Password\b")).fill(password)
                    page.get_by_label(re.compile(r"^Confirm password\b")).fill(password)
                    page.get_by_role("button", name="Create administrator", exact=True).click()
                    page.get_by_role("link", name="Imports", exact=True).click()
                    page.get_by_role("button", name="Offline reconciliation preview", exact=True).click()
                    page.locator('input[type="file"]').first.set_input_files(export)
                    page.get_by_label(re.compile(r"^Instance\b")).fill("synthetic-ci")

                    def open_choices(label: str):
                        picker = page.get_by_role("textbox", name=label, exact=True)
                        picker.focus()
                        choices = page.get_by_role("listbox", name=label, exact=True)
                        if not choices.is_visible():
                            picker.click()
                        expect(choices).to_be_visible()
                        return choices

                    def choose(label: str, option: str) -> None:
                        open_choices(label).get_by_role("option", name=option, exact=True).click()

                    choose("Timestamp meaning", "When the source says it was observed")
                    preview = page.get_by_role("button", name="Preview reconciliation", exact=True)
                    expect(preview).to_be_enabled()
                    with page.expect_response(
                        lambda r: r.request.method == "POST" and "/reconciliation/preview?" in r.url
                    ) as previewed:
                        preview.click()
                    assert previewed.value.status == 200, previewed.value.text()
                    first_preview = previewed.value.json()
                    assert first_preview["valid_rows"] == 5, first_preview["errors"]
                    assert first_preview["error_rows"] == 0, first_preview["errors"]
                    assert first_preview["preview_token"]
                    assert isinstance(first_preview["revision"], int)
                    # Chromium does not expose file-backed multipart request bodies to Playwright.
                    # Observe the actual FormData passed to fetch without changing its request.
                    page.evaluate("""() => {
                        const originalFetch = window.fetch;
                        window.fetch = function(input, init) {
                            if (String(input).endsWith('/reconciliation/imports') &&
                                init?.body instanceof FormData) {
                                window.qaImportFields = Object.fromEntries(
                                    [...init.body.entries()].filter(([, value]) => typeof value === 'string')
                                );
                            }
                            return originalFetch.apply(this, arguments);
                        };
                    }""")
                    with page.expect_response(lambda r: r.url.endswith("/reconciliation/imports")) as saved:
                        page.get_by_role("button", name="Save evidence", exact=True).click()
                    assert saved.value.status == 200
                    save_fields = page.evaluate("window.qaImportFields")
                    assert save_fields["preview_token"] == first_preview["preview_token"]
                    assert int(save_fields["expected_revision"]) == first_preview["revision"]
                    assert saved.value.json()["new_observations"] == 5, saved.value.json()
                    expect(page.get_by_role("button", name="Evidence saved", exact=True)).to_be_visible()

                    # The same export should now be retained with its current assignment details.
                    with page.expect_response(
                        lambda r: r.request.method == "POST" and "/reconciliation/preview?" in r.url
                    ) as repeated_preview:
                        preview.click()
                    replayed_preview = repeated_preview.value.json()
                    assert len(replayed_preview["items"]) == 5
                    assert all(item["decision"]["action"] == "retain" for item in replayed_preview["items"])
                    assert all("current_assignment" in item for item in replayed_preview["items"])
                    assigned_count = sum(
                        item["current_assignment"] is not None for item in replayed_preview["items"]
                    )
                    assert assigned_count >= 2

                    def row_for(identity: str):
                        return (
                            page.get_by_role("row")
                            .filter(has=page.get_by_role("checkbox"), has_text=identity)
                            .first
                        )

                    def decide(reason: str) -> dict:
                        page.get_by_label(re.compile(r"^Reason\b")).fill(reason)
                        page.get_by_role("button", name="Review action", exact=True).click()
                        with page.expect_response(
                            lambda r: r.url.endswith("/reconciliation/decisions")
                        ) as result:
                            page.get_by_role("button", name="Save decision", exact=True).click()
                        assert result.value.status == 200, result.value.text()
                        expect(page.get_by_text(re.compile("saved for .* evidence row"))).to_be_visible()
                        return result.value.json()

                    def create_asset(identity: str, reason: str) -> dict:
                        row_for(identity).get_by_role("checkbox").check()
                        choose("Action", "Create a separate asset")
                        return decide(reason)

                    duplicate_create = create_asset("192.0.2.22", "QA create duplicate hostname asset")
                    choose("Action", "Assign to an asset")

                    def asset_label(asset: dict) -> str:
                        name = asset.get("display_name") or asset.get("canonical_hostname") or "Unnamed asset"
                        return f"{name} (ID: {asset['id']})"

                    def search_assets(query: str = "") -> dict:
                        search = page.get_by_label("Find assets by name or ID", exact=True)
                        search.fill(query)
                        button = "Search assets" if query else "Browse assets"
                        with page.expect_response(lambda r: "/reconciliation/assets?" in r.url) as result:
                            page.get_by_role("button", name=button, exact=True).click()
                        assert result.value.status == 200, result.value.text()
                        parameters = parse_qs(urlparse(result.value.url).query, keep_blank_values=True)
                        assert parameters.get("q") == [query]
                        assert parameters.get("offset") == ["0"]
                        assert parameters.get("limit") == ["20"]
                        return result.value.json()

                    assets_page = search_assets("")
                    assert assets_page["items"]
                    assert len(assets_page["items"]) <= 20
                    duplicate_page = search_assets("qa-a.example.test")
                    duplicates = [
                        asset
                        for asset in duplicate_page["items"]
                        if asset.get("canonical_hostname") == "qa-a.example.test"
                    ]
                    assert len(duplicates) >= 2, duplicates
                    assert len({asset["id"] for asset in duplicates}) == len(duplicates)
                    unnamed_page = search_assets("Unnamed asset")
                    unnamed_assets = [
                        asset for asset in unnamed_page["items"] if not asset.get("canonical_hostname")
                    ]
                    assert unnamed_assets, unnamed_page["items"]
                    asset_a = duplicates[0]
                    unnamed_asset = unnamed_assets[0]

                    # Searching by ID returns the exact choice; duplicate hostnames still have unique labels.
                    by_id = search_assets(asset_a["id"])
                    assert any(asset["id"] == asset_a["id"] for asset in by_id["items"]), by_id
                    search_assets("qa-a.example.test")
                    target_choices = open_choices("Target asset")
                    for duplicate in duplicates:
                        expect(
                            target_choices.get_by_role("option", name=asset_label(duplicate), exact=True)
                        ).to_be_visible()
                    page.keyboard.press("Escape")

                    row = (
                        page.get_by_role("row")
                        .filter(has=page.get_by_role("checkbox"), has_text="qa-alias.example.test")
                        .first
                    )
                    row.get_by_role("checkbox").check()
                    search_assets(asset_a["id"])
                    choose("Target asset", asset_label(asset_a))
                    first = decide("QA reviewed alias")
                    choose("Review status", "All evidence")
                    row = (
                        page.get_by_role("row")
                        .filter(has=page.get_by_role("checkbox"), has_text="qa-alias.example.test")
                        .first
                    )
                    row.get_by_role("button", name=re.compile(r"^Details for\b")).click()
                    expect(page.get_by_text("Saved copies (1)", exact=True)).to_be_visible()
                    expect(page.get_by_text("Assignment history (2)", exact=True)).to_be_visible()
                    row.get_by_role("checkbox").check()
                    search_assets(unnamed_asset["id"])
                    choose("Target asset", asset_label(unnamed_asset))
                    corrected = decide("QA wrong-match correction")
                    expect(
                        page.get_by_role("heading", name=re.compile(r"^Evidence details:"))
                    ).not_to_be_visible()

                    def undo(reason: str, explanation: str) -> dict:
                        history_row = (
                            page.get_by_role("row")
                            .filter(has=page.get_by_role("button", name="Undo", exact=True), has_text=reason)
                            .first
                        )
                        history_row.get_by_role("button", name="Undo", exact=True).click()
                        return decide(explanation)

                    undo("QA wrong-match correction", "QA restore reviewed alias")
                    row_for("qa-id-only").get_by_role("checkbox").check()
                    choose("Action", "Split selected evidence")
                    search_assets(unnamed_asset["id"])
                    choose("Source asset", asset_label(unnamed_asset))
                    split = decide("QA split only selected evidence")
                    undo("QA split only selected evidence", "QA restore before split")
                    choose("Action", "Merge assets")
                    search_assets(unnamed_asset["id"])
                    choose("Source asset", asset_label(unnamed_asset))
                    asset_b_page = search_assets("qa-b.example.test")
                    asset_b = next(
                        asset
                        for asset in asset_b_page["items"]
                        if asset.get("canonical_hostname") == "qa-b.example.test"
                    )
                    search_assets(asset_b["id"])
                    choose("Target asset", asset_label(asset_b))
                    merged = decide("QA merge evidence assignments")
                    undo("QA merge evidence assignments", "QA restore before merge")
                    response = context.request.get(origin + "/api/v1/reconciliation/observations?limit=50")
                    assert response.status == 200
                    evidence = response.json()["items"]
                    alias = next(
                        item
                        for item in evidence
                        if item["observation"]["asset"]["fqdn"] == "qa-alias.example.test"
                    )
                    assert alias["asset_id"] == asset_a["id"]
                    assert alias["version"] == 4
                    assert not errors, errors
                    page.screenshot(path=str(output / "evidence-workflow.png"), full_page=True)
                    print(
                        json.dumps(
                            {
                                "browser": "Chromium",
                                "observations": len(evidence),
                                "alias_version": 4,
                                "verified": [
                                    "setup",
                                    "preview",
                                    "save",
                                    "asset_browse",
                                    "asset_id_search",
                                    "duplicate_asset_labels",
                                    "unnamed_asset_correction",
                                    "unnamed_asset_split",
                                    "unnamed_asset_merge",
                                    "signed_preview_save",
                                    "same_export_retention",
                                    "provenance",
                                    "assign",
                                    "correct",
                                    "split",
                                    "merge",
                                    "undo",
                                ],
                                "decision_ids": [
                                    duplicate_create["id"],
                                    first["id"],
                                    corrected["id"],
                                    split["id"],
                                    merged["id"],
                                ],
                            }
                        )
                    )
                except Exception:
                    page.screenshot(path=str(output / "failure.png"), full_page=True)
                    raise
                finally:
                    context.tracing.stop(path=str(output / "workflow-trace.zip"))
                    browser.close()
        finally:
            server.terminate()
            server.wait(timeout=10)


if __name__ == "__main__":
    main()
