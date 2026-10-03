# Feature and validation map

This table lists implemented features, their checks and remaining gaps. Each validation record
identifies its own scope: [original import](../VALIDATION.md), [persistent reconciliation](persistent-validation.md)
and [service/CLI/MCP](service-validation.md). A test listed here is not evidence that it passed.

| Area | Implementation | Validation | Remaining gap |
| --- | --- | --- | --- |
| Deployment | Local Compose web, worker, PostgreSQL; first-run setup; persistent volumes | Compose validation and a disposable-stack smoke run | Capacity and recovery need their own validation |
| Accounts | Argon2id, local roles, server sessions, CSRF and throttling | Auth/role paths in `scripts/validation/smoke_e2e.py` | Broader adversarial auth coverage |
| Imports | Tenable CSV/JSON/NDJSON, defused Nessus XML, mapped generic CSV; immutable source evidence | `tests/unit/test_import_parsers.py`, Cedar Ridge example, smoke validator | JSON/NDJSON is held in memory; reusable mapping-profile management UI is incomplete |
| Offline multi-source evidence | CSV/JSON/NDJSON configurable source adapters, native Nessus XML, immutable observations, reversible matching/review | Persistent reconciliation unit/PG/browser suites | Tenant-specific endpoint-security and endpoint-management exports and exact vendor-version mappings remain unverified |
| Service exposure | Source-native nodes, scoped endpoints, VIPs, services, typed backends, explicit attribution, immutable facts and guarded undo | Service API/migration/scale tests and interface browser QA | Topology is supplied explicitly; no vendor-native topology adapters or automatic discovery |
| CLI / MCP | Installable CLI, optional maintained-SDK stdio MCP, shared authenticated service/client and report formatter | CLI/MCP real protocol tests, wheel check, GUI/CLI/MCP parity validator | No extra harness-specific integrations or background connectors |
| Asset identity | Normalized identifiers, conservative matching, review, manual identity events | `tests/unit/test_identity.py`, conflict-review smoke path | Full database-backed merge/split/undo and future-import scenarios |
| Findings | Stable asset/source/plugin/port/protocol identity, history, distinct maturity/SLA clocks | `tests/unit/test_findings.py`, recurring-import smoke path | Comparable-scope reconciliation still relies on an explicit administrator declaration |
| Hosts and views | Versioned typed query contract shared by lists, previews, saved views, and exports | Query/export smoke paths and host page tests | Exhaustive filter combinations and browser coverage |
| Reports | Durable snapshots, XLSX, CSV ZIP, printable HTML, formula protection, hashes | Export paths in the smoke validator | Large import/export capacity proof |
| Audit and retention | Administrative audit events, configurable report cleanup, backup/restore helpers | Smoke audit checks; disposable backup/restore test | Backup/restore is destructive to its target and must be isolated |
| Browser UI | Dashboard, hosts, findings, imports, identity review, views, reports, users, settings | Frontend lint, typecheck, unit tests, build, browser review | Full end-to-end browser coverage |

## Data rules to retain

- Ambiguous assets enter review rather than being silently merged.
- Raw source values and observation provenance remain available; missing values remain null.
- A partial import’s silence does not mean remediation. Explicit comparable reconciliation can produce `not_observed`, never automatic `remediated`.
- Maturity and SLA use separate dates; upload time is not a vulnerability publication date.
- Export jobs read the submitted snapshots rather than re-running a mutable view.
- Untrusted values are data, with typed query allowlists and spreadsheet formula protection.

## Capacity limits

A synthetic 100,000-row validator is included, but production capacity remains unverified.
Import processing uses a long database transaction. Standard scanner JSON/NDJSON parsing
reads the entire input into memory; offline adapters have separate staging bounds. Account
for those limits when evaluating large inputs.
