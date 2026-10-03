# Persistent reconciliation validation

This record covers the additive evidence implementation while it was developed in a private draft PR. The migration preserves legacy tables and does not backfill or rewrite scanner findings. All source fixtures and disposable database/browser data are synthetic.

## Local checks

On 2026-10-02, the full backend suite passed 228 tests. Seventeen PostgreSQL integration tests skip unless `VWB_TEST_DATABASE_URL` explicitly identifies a disposable test database. Ruff passed; mypy passed across 75 backend modules. Cedar Ridge validation passed with four formats, six records and zero network requests.

The full frontend suite passed 35 tests. Lint, TypeScript and the production build passed. The final detail-card regression was reproduced before correction: refreshing or saving a decision left an old card visible, and a late detail response could reopen it. The regression tests now require stale cards to clear and late responses to be ignored.

## Review corrections

Independent review at `52d7717` reproduced three blockers. Regression tests first showed the lost Nessus host fields, missing unnamed-asset search and divergent preview/save decisions. The correction retains full raw host evidence, adds bounded browse/UUID/fallback search with IDs in labels, and uses one matching plan for preview and save. Repeated observations retain their saved assignment/rejection/defer status. Signed preview context freezes evaluation time and binds actor/files/options/revision; stale, expired, changed and non-ASCII contexts reject with 409 before writes. Completed retries still replay safely.

The recheck also reproduced unchanged revisions after legacy alias edits, stale ORM projections and XML evidence expansion. Legacy imports and identity writes now share the mutation lock/revision; projection reads refresh; staged expanded evidence is capped at 64 MiB with atomic rejection. A real synthetic legacy CSV import changes a proposed create to review and invalidates the old signed preview. Tests cover historical clone conflicts, rejected repeats, malformed contexts, a freshness-boundary time change, empty asset names and cached assignment versions.

| Reproduction | Corrected result |
| --- | --- |
| Two Nessus hosts differ only in an unmapped `aws-instance-id` or unknown host attribute | Both inventory and vulnerability observations retain ordered raw attributes/properties, including repeated tags, and have distinct fingerprints. |
| Two assets contain only native IDs | Empty-query browsing pages both; full UUID, UUID prefix and fallback display-name searches find each asset. Browser choices include full IDs, including duplicate hostname choices. |
| Fresh legacy hardware UUID is the only matching evidence | Preview and save both use `no_safe_match` and create a separate provisional asset; the unscoped legacy UUID cannot silently identify it. Durable source-scoped history still matches, and repeated rejected evidence remains rejected. |

The focused regressions are in [parser tests](../tests/unit/test_reconciliation.py), [real API tests](../tests/unit/test_persistent_reconciliation_api.py), [PostgreSQL tests](../tests/integration/test_persistent_postgres.py) and [production browser QA](../scripts/validation/browser_reconciliation.py). Existing immutable Nessus observations cannot recover raw fields discarded by the prior adapter; new imports retain them and generate the richer fingerprints.

The correction adds no schema change. Hosted validation below exercises the corrected implementation; the draft PR remains the implementation-review gate.

## Hosted PostgreSQL, browser and restoration

[CI run 36967082817](https://github.com/lpayt402/vulnerability-workbench/actions/runs/36967082817) passed all four jobs on commit `50957be8f983ff0025f54de187f3837a264a28f8`: backend, frontend, container build and PostgreSQL/browser/restoration. Its browser trace and screenshot are in the seven-day `persistence-browser-qa` artifact.

The PostgreSQL suite passed 17 tests in 18.06 seconds. It exercises populated legacy upgrade, idempotent upgrade, empty downgrade, populated-downgrade refusal, immutable database triggers, concurrent import replay, concurrent decision replay/stale rejection, interleaved page and preview revisions, a downgrade racing ingestion, legacy retirement racing assignment, malformed-row isolation and 5,000-observation import/reimport/paging. The review regressions also verify unnamed UUID/fallback search, competing signed-preview saves, legacy alias mutation invalidation and cached-assignment refresh.

Real Chromium used the production frontend, authenticated API and PostgreSQL. It verified initial setup, column discovery, signed preview/save, same-export retention, empty-query asset browse, UUID search, duplicate-hostname labels containing distinct IDs, provenance and assignment history. It assigned an alias, corrected it to an unnamed asset and undid that correction; it then split, merged and undid native-ID-only evidence using the unnamed asset choices. Five observations remained, and the alias returned to its reviewed asset at version 4. The test observes the actual FormData sent by the frontend without changing the request; it also requires all mapped fixture rows to preview successfully before save.

A full custom-format PostgreSQL dump restored into a separate UUID-named disposable database. All 39 table-content hashes matched; the original database stayed unchanged and the restored immutability trigger rejected evidence modification. The restoration script refuses to run outside the explicitly enabled, fixed loopback CI database. No user or vendor database was contacted.

## Synthetic scale measurement

The [benchmark script](../scripts/validation/benchmark_persistence.py) runs only against in-memory SQLite. Its final local run used Windows / Python 3.12, with other validation running concurrently; this is a fixture measurement and does not establish production PostgreSQL capacity.

| Operation | Result | Elapsed | SQL statements |
| --- | --- | ---: | ---: |
| First import | 5,000 assets; 15,000 distinct inventory/vulnerability/coverage observations; 100 duplicate supported rows; 25 errors | 29.876 s | 223 |
| Reordered export | Zero new observations; supported locators retained | 5.156 s | 72 |
| End-of-list page | 50 observations including current asset names | 0.059 s | 3 |

Peak Python allocations during the first import were 197.59 MiB with tracemalloc enabled. Repeat/page timings exclude tracemalloc. The final locator count was 30,200. A composite import-order index removed the earlier full-page sort bottleneck; pagination does not perform one asset-name query per observation.

## Remaining implementation and validation gaps

See [workflow and migration notes](persistent-reconciliation.md) and [format provenance](offline-source-formats.md). Exact endpoint management CSV headers, tenant-specific endpoint security JSON envelopes, infrastructure inventory IP/interface joins and directory export conventions remain unverified. Those presets are labeled synthetic/configurable, not vendor compatibility claims. Direct XLSX, background persistence, legacy backfill, source-status lifecycle aggregation and production capacity testing remain outside this increment. Failed coverage and missing rows never resolve vulnerabilities or retire assets in this path. At the recorded validation checkpoint, the repository was private and the PR was draft and unmerged.
