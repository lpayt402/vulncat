# Offline reconciliation design and migration requirements

This document records the preview design and the options considered for persistence.
The additive observations and versioned assignments option was approved and implemented afterward. See [persistent reconciliation](persistent-reconciliation.md) for the delivered workflow, transaction semantics, migration/restoration checks and remaining limits. The preview described here remains available.

## Baseline

Baseline: `0cf132362a81d3b2b1d8b1c2f83a66be0f215e7d`. FastAPI/SQLAlchemy/PostgreSQL, durable import worker, React/Mantine, existing server pagination. There are no repository AGENTS.md or .agents skill files in this tree. Existing parsers require an asset plus finding; generic CSV requires plugin ID and severity. Identity already retains identifier observations and supports review, merge, split and guarded undo. These operations have incomplete integration coverage. Existing FQDN/IP matching and finding absence processing are scanner-oriented.

## Initial preview implementation

Add a separate administrator-only **Offline reconciliation preview**. CSV, JSON/NDJSON mappings cover endpoint security, endpoint management, infrastructure inventory, directory computer exports and spreadsheets saved as CSV. Nessus XML bridges the existing hardened parser while preserving hosts with no findings. Every adapter emits inventory, vulnerability occurrence or coverage observations, source/native identifiers, observed and imported times, raw evidence and deterministic fingerprints. Missing timestamps remain unknown; import time never substitutes for observation time. Source statuses remain evidence, never automatic remediation or asset retirement.

The preview accepts multiple files, counts errors and duplicates, uses an indexed matcher and returns a bounded page of explanations. Existing inventory supplies historical candidates. Within-preview provisional identities are suggestions; they never write assets, findings, review items or identity events. IP, FQDN, shortnames and MAC addresses cannot independently auto-match. Source-native IDs are scoped by source instance and ID type. Fresh unique native/hardware matches must pass conflict checks; stale/unknown/future times, duplicate IDs and incompatible hardware evidence go to review. Network scopes prevent IP collisions across subnets/VRFs; omitted scope makes IP evidence weak and visible.

The preview stage changed no database schema or existing resolver and included no merge
or publication. Its review list is transient; durable identity review uses a separate queue.

## Persistence options

1. **Selected: additive immutable observations and versioned assignments.** Add explicit `source_instances`, `source_observations`, `observation_locators`, `asset_observation_assignments`, `vulnerability_occurrences`, `coverage_observations` and `reconciliation_decisions`. Keep asset UUIDs, legacy finding keys and current reports. Unique event fingerprints include source instance, mapping/parser version and evidence; each repeated export keeps its file/row locator. Index native IDs, scoped weak identifiers and observed time. Assignments, decisions and their inverse operations must record actor, reason, before/after version and affected observation IDs.
2. Extend existing scanner import/finding tables: less initial SQL but forces inventory/coverage into finding rows, conflates source statuses and leaves source instance scope underspecified. Rejected.
3. Replace the identity/finding subsystem: potentially cleaner but requires a broad rewrite and risks existing reports/history. Outside authorized scope.

### Migration requirements

Create explicit additive Alembic revisions with fixed table definitions, never modify the historical create-all revision. A future separately reviewed backfill would retain original import/record IDs and raw/normalized evidence, mark inferred source instance and unknown time explicitly, and never silently coalesce historical assets. The preview stage left legacy imports untouched. Before enabling writes, prove upgrade on a populated PostgreSQL snapshot, idempotent rerun, count/checksum preservation, merge/split/undo with subsequent imports, and rollback of new assignments without deletion of legacy evidence. Backups follow existing documentation.

Persistent source-native IDs must not be mapped into generic `agent_uuid` or Tenable UUID columns. Finding keys need source instance and native occurrence ID or a documented scoped derived key, including software/port when present. Native closed/suppressed/unknown statuses need per-source policy and an observation-time ordering gate. Failed/unreachable/DNS failure/partial coverage and absent rows do not resolve vulnerabilities. Inventory updates do not establish successful scans or reachability.

## Tests and scale

Preserve the existing unit suite and Cedar Ridge examples. Add source scope, mapping, malformed rows, missing/invalid/naive time, idempotent fingerprints, duplicate agents, conflicting IDs, reimages, renames, DHCP reuse, stale/future history, shortname and VRF collisions, empty Nessus hosts and unsafe XML tests. Measure synthetic 5,000-asset preview with candidate lookup counts, elapsed time and peak Python allocations. This is a local fixture benchmark, not a production PostgreSQL throughput claim. API response pages and sample errors are bounded; JSON arrays and uploads have explicit limits.

## Research notes

Official-source references and verified schema boundaries are maintained in [offline-source-formats.md](offline-source-formats.md). Vendor account exports are unavailable; example mappings are labeled synthetic presets, never verified vendor compatibility. No real employer data or live source connections are requested.

## Remaining work

Remaining work: exact vendor export schema verification, direct spreadsheet formats, background batch persistence and scanner coverage completeness/aggregation policies. Additive persistence, durable review UI and PostgreSQL merge/split/undo checks are implemented
and described in [persistent reconciliation](persistent-reconciliation.md). The draft-PR and
README-diagram review steps applied to the original design stage.
