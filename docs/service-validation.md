# Service, CLI and MCP validation

All source data, users, addresses and application examples used here are hypothetical. The development scope is the existing private repository; no repository migration, live connector, active probe or deployment is part of these checks.

## Local checks on 2026-10-02

The service implementation backend suite passed 311 tests; 19 PostgreSQL tests skipped because no disposable database URL was supplied locally. Ruff passed, and strict mypy passed across 89 backend files with both Linux and Windows platform settings. Those skipped tests run in the hosted PostgreSQL job below.

The service implementation frontend passed 52 tests in eight files, ESLint, TypeScript and the production build. These preserve the offline import and persistent reconciliation tests while adding attribution, preview invalidation, undo, paging, themes, reduced motion and selected contrast-token checks. They do not establish a complete accessibility audit.

CLI/MCP checks passed against the isolated official MCP SDK 1.30.0, including actual stdio initialize/list/call operations, structured errors, closed input schemas, permission failures, signed mutation guards and Windows private session storage. Lexical network/device/path-alias rejection is tested with filesystem metadata/open forbidden; no external network probes were used. A built wheel installed into isolated storage, its four entrypoints were inspected, and base CLI discovery worked while MCP imports were deliberately unavailable. Global packages were not changed.

Independent review reproduced and verified corrections for normalized duplicate graph references, future timestamp poisoning, stale source exports overriding analyst corrections, and historical proposals being rejected before effective-state validation. It found no remaining material blocker after focused in-memory/mock checks.

## Measured fixture

The service fixture exercised 3,000 nodes, 2,000 explicit relationships and 3,000 observations through four bounded write batches. On this workstation the final isolated run took 6.119 seconds. Write batches used 15, 15, 17 and 17 SELECT statements; a 500-row report page used six; a four-decision history page used 45. Tests enforce statement bounds and disjoint pages. This is a synthetic SQLite/API measurement, not a production capacity guarantee or PostgreSQL concurrency proof.

## CI checks

CI installs the package with the optional SDK, runs the full backend/frontend checks and builds the container. Its disposable PostgreSQL 16 job checks populated upgrade, immutability, empty/populated rollback, concurrent replay and competing-import preview rejection. Existing reconciliation browser QA remains, followed by `service_interfaces.py`: actual browser attribution/undo, light/dark/mobile/reduced-motion checks, and equal GUI/API/CLI/MCP reports in JSON/CSV/Markdown. `restore_persistence.py` compares every table and verifies restored source and service-history triggers.

The real parity/browser validator requires the fixed disposable PostgreSQL database. Local SQLite does not implement the supported session timestamp/database behavior and is not used as evidence for those gates. Later branding validation at [`935c254`](https://github.com/lpayt402/vulnerability-workbench/commit/935c2543e4b7101c31fc69cd6683991b1b36de24)
passed 328 backend tests and 52 frontend tests locally. The [exact-commit CI run](https://github.com/lpayt402/vulnerability-workbench/actions/runs/37042302931)
passed backend, frontend, Docker and PostgreSQL/browser jobs, including interface parity and restoration.
The local run skipped the 19 PostgreSQL tests; CI ran them against its disposable database.

## Unverified schemas and processing limits

Vendor-specific endpoint-security and endpoint-management export schemas remain unverified; configurable mappings and clearly labeled canonical fixtures are supported. Topology requires explicit graph input and reviewed attribution. JSON imports and preview/history responses are bounded but not streaming; very large graph history should use smaller batches/pages. There is no automatic discovery, finding fan-out, absent-row resolution or graph-based asset merge. Legacy maintenance exports and account bootstrap remain compatible.
