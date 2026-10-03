# Data model

## Offline signal and service layers

The additive reconciliation tables retain source-scoped observations and locators separately from current asset assignments and assignment versions. Inventory, native vulnerability occurrences and coverage outcomes retain different semantics. The service layer adds six tables without rewriting that evidence:

| Table | Purpose |
| --- | --- |
| `exposure_nodes` | Current source/instance/native-ID node projections and optional explicit asset binding |
| `exposure_relationships` | Current typed, explicitly evidenced topology relations |
| `exposure_attributions` | Current one-observation-to-one-target mapping or review-needed state |
| `exposure_node_facts` | Immutable dated/undated node facts, including stale disagreements |
| `exposure_decisions` | Immutable actor, reason, before/after changes, request-key result and undo links |
| `exposure_versions` | Immutable per-entity version snapshots used by guarded undo |

Both layers share `reconciliation_state` for mutation serialization and preview invalidation. Observation provenance and source timestamps remain distinct from import and analyst-review times. See [service exposure](service-exposure.md) and [persistent reconciliation](persistent-reconciliation.md) for the complete contracts.

## Modeling principles

The PostgreSQL schema separates canonical state from scanner evidence. Scanner-controlled hostnames, IP
addresses, plugin names, CVEs, and dates are never used as convenient but unsafe primary keys. Missing values
remain null. Source files, normalized import rows, identifier observations, finding observations, history, and
audit events provide a trace from each current value back to an import.

Every entity uses foreign keys, explicit delete behavior, uniqueness constraints, and indexes suited to its
workflow. UUIDs are application identity; timestamps are timezone-aware.

## Users, sessions, and audit

| Entity | Purpose and important constraints |
|---|---|
| `roles` | Unique role name. Initial policy uses `administrator` and `read_only`. |
| `users` | Unique normalized username, Argon2id password hash, role FK, active state. |
| `user_sessions` | Unique SHA-256-sized token hash, CSRF hash, expiry/revocation, client metadata. Raw tokens are not stored. |
| `login_attempts` | Indexed username, client address, result, and time for bounded throttling. |
| `application_settings` | Unique setting key with JSON value and updater provenance. |
| `audit_events` | Append-oriented event time, actor, type, entity, outcome, request ID, client address, and structured details. |

Deleting a user does not erase security history: audit and administrative references use `SET NULL` where
historical actor retention is appropriate. Roles referenced by active users are restricted from deletion.

## Assets and identity evidence

`assets.id` is the only canonical asset key. `canonical_hostname` is display metadata and is not unique because
hostnames can be missing, renamed, or duplicated across domains.

`asset_identifiers` stores typed normalized identifiers and the original evidence:

- Tenable asset UUID
- Agent UUID
- Nessus host ID
- hardware/BIOS UUID
- MAC address
- FQDN
- short hostname
- IPv4/IPv6 address
- user alias

The `(asset_id, identifier_type, normalized_value)` constraint prevents duplicate relationships on one asset.
The `(identifier_type, normalized_value)` lookup index is not globally unique: shared/reassigned
IP addresses and conflicting evidence must be representable. `active`, validity dates,
`shared_or_non_identifying`, `manually_verified`, and `manual_override` govern eligibility.

`asset_identifier_observations` records import, normalized row, observation date, matching rule, confidence,
and evidence JSON. Its uniqueness constraint prevents the same identifier/import/record observation from being
inserted twice.

`identity_review_items` preserves incoming identifiers, candidates, conflicts, rule explanation, confidence,
source evidence, and resolution. `identity_events` records merge, split, identifier move, verification,
rejection, pinned-name, shared-IP, and undo actions. Merge does not delete the losing asset; it becomes an
inactive redirect through `merged_into_id`, preserving history and reversibility.

## Immutable imports

`source_files.sha256` is unique. The stored file is immutable and addressed by a persistent storage path.
Filename, content type, detected source type, byte count, uploader, and upload time are retained.

`imports` represents a processing execution. A force-reprocess operation references the same `source_files`
row rather than copying or modifying evidence. It records job state, mapping, scan-scope authority, summary
counts, warnings, and failure details.

`import_records` stores raw and normalized JSON, a stable content hash, warnings, and resolved asset/finding
references. `(import_id, record_number)` and `(import_id, content_hash)` enforce row-level idempotency within an
import.

`import_profiles` stores a reusable generic-CSV mapping. Names are unique per owner; profiles can be private or
shared.

## Findings and lifecycle

`vulnerability_definitions` identifies a scanner definition by `(scanner_source, plugin_id)`. Plugin name,
family, CVEs, descriptions, solutions, dates, and exploit indicators are mutable metadata and not finding
identity.

`asset_findings` identifies one host-specific instance by:

```text
(asset_id, scanner_source, plugin_id, normalized port, normalized protocol)
```

This preserves one evolving instance across recurring scans and creates separate instances when the same
plugin appears on different ports. Portless findings normalize to port zero and a consistent general protocol.
First Found is monotonic and is never reset by a later observation.

Current state includes severity, status, evidence/solution, observation count, maturity date and source,
maturity gate, SLA due/status, reopened count, and latest import.

`finding_observations` retains each import's scan time, evidence, severity, solution, and raw metadata. The
uniqueness constraint on finding/import/record prevents duplicate evidence.

`finding_status_history` records actor/import, previous and new state, reason, and metadata. Missing findings
from normal or partial scans cannot be marked remediated. Verified complete comparable scans may produce
`not_observed`; a later observation reopens `not_observed` or `remediated` findings.

`finding_notes` retains author and timestamps.

## Ownership, classifications, and tags

Operational ownership fields live on `assets`: system owner, administrative team, technical owner,
environment, data center, business service, server role, maintenance group, patch group, operating system,
notes, identity confidence, and last scan time.

`tags` has a unique name and joins assets through the composite-primary-key `asset_tags` table. Classification
values remain optional so vulnerability evidence can be imported before ownership enrichment.

## Durable queue

`jobs` stores import/export work with a typed payload, optional unique idempotency key, state, progress,
availability, lease token/expiry, heartbeat, attempts, and sanitized error. The claim index covers
`(status, available_at, job_type)`. Workers use PostgreSQL row locks with `SKIP LOCKED` so multiple workers do
not claim the same job.

Completed jobs cannot be reclaimed. An expired lease may be retried only within `max_attempts`, and domain
operations must remain idempotent.

## Saved views and export snapshots

`saved_views` has a per-owner unique name, private/shared flag, typed query JSON, schema version, and monotonic
revision.

`export_jobs` records the requester, exactly one asset scope mode, saved-view ID/name/revision where relevant,
original and normalized query JSON, query schema version, separate finding scope, output format, counts,
data-as-of/source cutoff, lifecycle timestamps, expiry, progress/failure, artifact path, byte size, application
version, and SHA-256 result hash.

`export_asset_snapshots` and `export_finding_snapshots` use `(export_id, entity_id)` composite primary keys and
retain deterministic order plus denormalized report JSON. The worker reads these rows; it never re-runs a
mutable query or saved view after submission. This ensures all XLSX, CSV, and printable HTML formats use the
same host and finding scope.

## Retention and deletion behavior

- Original uploads, normalized import evidence, and audit logs have no automatic deletion by default.
- Generated report artifacts may expire; export and audit metadata remain.
- Evidence FKs generally restrict or cascade only within a clearly owned aggregate.
- User deletion uses `SET NULL` for historical actor fields.
- Asset/finding deletion is restricted where it would break identity or export provenance.
- No migration may silently merge, delete, or reinterpret assets or findings.

Before enabling destructive retention, take and validate a complete backup, define which artifact class is in
scope, preserve required audit/provenance metadata, and test the cleanup against referenced storage paths.

## Indexing and performance

The schema indexes:

- normalized identifiers and identifier type;
- canonical hostname, ownership/classification fields, last scan, and confidence;
- plugin, severity, status, maturity, SLA, port, protocol, and finding dates;
- job claim/lease fields;
- import, export, audit, user/session, and saved-view relationships.

The canonical host-query service must use these indexes for allowlisted predicates and add deterministic asset
UUID tie-breaking. The 100,000-row synthetic import and large-export tests are the acceptance evidence for
memory behavior and query plans; a specific throughput claim requires measured benchmark results.
