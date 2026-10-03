# Private migration validation

## Migration rerun

Fresh checks on October 1, 2026 passed: 25 backend tests, Ruff, mypy over 61 backend source files, the four-format hypothetical example, frontend lint and TypeScript checks, eight frontend tests, and a production build. A newly built disposable Docker stack passed 21 API checks, database backup and restore, and persisted-state/report-hash verification. All five PowerShell scripts parsed. The temporary stack and its volumes were removed.

The final import preserves the dependency metadata and adds test-only GitHub checks. Browser state, raw evidence, runtime secrets, generated reports, and backups are excluded. The POSIX helper scripts are executable in Git. No project license was added.

GitHub backend checks exposed SQLAlchemy 2.1 compatibility issues: removal of `sqlalchemy.ext.mypy.plugin` and changed row/statement typing. The obsolete plugin setting was removed, and SQLAlchemy is limited to the supported 2.0 series (`>=2.0.41,<2.1`). Strict mypy checks and the Pydantic plugin remain enabled. Application code is unchanged; the frontend lockfile and other dependency ranges are preserved. See [SQLAlchemy's release notes](https://docs.sqlalchemy.org/en/21/changelog/changelog_21.html).

## Preparation checks

Validated on Windows on 2026-10-01 with Python 3.12, Node 24, npm 11, and a disposable Docker Compose stack. Runtime inputs were synthetic local files. No scanner was contacted and no real account, target inventory, or scan result was used.

| Stage | Result |
| --- | --- |
| Source transfer | Passed: 148 committed files matched their Git blob identities before editing. No history, symlinks, submodules, archive, or image assets were copied. |
| Backend unit suite | Passed: 25 tests, including parser safety, asset identity, lifecycle/date rules, required database configuration, and frontend route fallback. |
| Offline hypothetical example | Passed: four formats, six records, four included records, two skipped High records, and an unmapped owner-note column. |
| Python lint | Passed: Ruff over backend, tests, validators, and examples. |
| Python type check | Blocked: Windows Application Control prevented mypy from loading its compiled `copytype` DLL. No policy setting was changed and no alternate route was used. |
| Frontend | Passed: lint, TypeScript check, eight tests in three files, and production build. The sandbox initially denied esbuild spawning; the supported command approval route allowed the same checks to run. |
| Compose and image | Passed: configuration validation, multi-stage build, and health checks for isolated web, worker, and database services. |
| Synthetic API workflow | Passed: 21 smoke checks, all four import formats, duplicate handling, identity review, query/export scope and snapshots, XLSX/CSV/HTML downloads and hashes, roles/CSRF, and 34 audit events. |
| Recovery | Passed: database backup, checksum-checked restore, and persisted-state/report hash verification in the disposable stack. |
| Rendered UI | Passed: desktop and mobile dashboard review, Hosts page review and direct reload. The new brand fits both viewport sizes. |
| Static routes | Passed: direct `/login` and `/hosts` navigation returns the app; missing API routes and assets remain 404. |
| PowerShell | Passed: all five scripts parse without syntax errors; backup and restore helpers ran under the existing execution policy. |
| Final privacy/tree audit | Passed: all files reviewed as UTF-8 text, synthetic CSV/JSON/XML checked, local Markdown links resolved, and dependency lock metadata preserved. No old account references, embedded credential defaults, provider-token patterns, private keys, or real email addresses found. |

## Fixes made during verification

Browser review exposed a missing fallback for client-side routes: reloading `/login` returned a server 404. A small static-file subclass now serves the app entry point for known frontend routes. Regression tests cover nested Windows paths and preserve 404 behavior for APIs and missing assets. The first Windows regression run exposed a separator mismatch; the corrected suite passes.

The hypothetical example checker initially used an incorrect normalized-model field name. It now uses the actual parser fields and passes. These corrected failures are not counted as passing checks.

Docker’s default address pools were exhausted. The disposable validation used an unused explicit subnet; no existing network or daemon setting was modified. A test-only isolation flag blocked published localhost ports and was removed from the validation overlay before the successful run. This overlay is outside the candidate.

## Checks still open

- The synthetic 100,000-row capacity test was not run. This migration establishes no capacity limit. JSON/NDJSON still reads the full input into memory, and import progress commits in a long transaction.
- Full browser end-to-end coverage, every host-filter combination, and merge/split/undo scenarios remain open.
- A favicon is not supplied; browser requests for `/favicon.ico` return 404.
- The Windows Start/Stop launcher workflow and an external HTTPS deployment were not run. No global execution-policy, authentication, or security setting was changed.
- Project ownership and licensing need confirmation before public release. The source supplied no project license or notice file; no new license was selected. Dependency names and existing license metadata remain intact.

Screenshots and generated synthetic reports/backups are validation evidence outside the candidate. The private import contains application files and hypothetical fixtures, without runtime secrets, test browser state, build output, or generated databases.
