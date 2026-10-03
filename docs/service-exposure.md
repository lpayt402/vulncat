# Service exposure and evidence

Services adds an explicit graph alongside the existing asset inventory. A host or device can bind to an existing active asset. A load balancer, VIP, logical service and observed endpoint remain distinct nodes even when they share an IP. Endpoint fields include protocol, port, DNS, SNI and network scope. Node identity is `(source, instance, native_id)`; kind cannot change under that identity. There is no address- or hostname-based graph matching.

Supported relationships are `endpoint_of`, `backed_by`, `routes_to`, `hosted_on` and `management_of`. Their ends have validated kinds. Operator evidence and provenance accompany each relation. Unmapped backends remain unassigned. Different source instances may disagree without replacing one another's native identities. Deactivate or rebind relationships through a reviewed graph delta; there is no automatic topology discovery.

## Report meaning

Inventory, vulnerability and coverage rows retain their original kind, source, instance, observation time, import time, native status and normalized source evidence. Source status strings are not a universal resolved/open lifecycle. Reports describe retained observations. Check observation time and coverage before treating
a result as evidence of current exposure.

Direct attribution associates one source observation with one node. A logical service report can also include observations attributed to endpoints linked through active, explicit `endpoint_of` relationships. The row retains its endpoint identity and identifies the confirmed service. Findings on VIPs or backend hosts do not spread across `backed_by` or `routes_to`. Multiple contradictory service mappings remain visibly uncertain.

Unmapped observations appear as **review needed**. In Services, an administrator can choose a report row, search/select a node, state a reason, preview the attribution and confirm it. Read-only users can inspect and export the report. Attribution can be returned to review needed; the original observation remains immutable.

`age_days` is computed only when `time_meaning` is `source_observed` and a timestamp exists. Export generation, directory last logon and undated evidence do not establish scan or reachability freshness. Future timestamps require review. An old conflicting topology fact is appended to history while a newer dated projection remains current. A fact count/disagreement marker describes retained topology evidence; it does not settle an identity conflict.

Failed, partial, DNS-failed or unreachable scans remain coverage observations. Successful coverage on an appliance's data plane does not prove management-plane coverage. Missing findings or exports do not retire an asset or resolve prior findings.

## Review guards and history

`POST /api/v1/exposure/preview` validates a bounded graph delta without committing it. It returns explicit before/after changes, warnings, current global revision and an actor-bound signed preview token. Apply accepts the same graph and fresh revision, with a request key and reason. The browser and CLI/MCP require explicit confirmation. Existing node, relationship and attribution changes require the current `expected_version`.

Apply uses the signed preview's evaluation time for source-clock credibility and age warnings. A future timestamp becoming plausible while the reviewer reads the preview cannot change the reviewed projection. Import and audit times still record when the write occurred; a fresh preview can accept facts that have become credible.

All exposure and reconciliation mutations share one database row lock/revision. A competing import or identity decision invalidates the preview. Reusing a request key with the exact payload and actor returns its saved result; different contents conflict. Graph envelopes are limited to 2,000 nodes, 4,000 relationships, 2,000 attributions and 4 MiB of expanded JSON. Reads are paged with a maximum of 500 rows.

Graph `intent` defaults to `source_facts`. Older or unknown-time source imports append evidence and proposed changes while preserving a newer dated current projection, including bindings and active state. Future source times are treated as unreliable for ordering; valid dated facts can replace a prior future-dated projection. Deliberate analyst changes use `intent: "manual_correction"`; they can correct bindings, active state and attribution while retaining newer source facts and provenance. The browser attribution form sets this intent explicitly.

A manual correction records its review time. Source evidence from before that review, or with unknown or future time, cannot reverse the correction. It remains available in history for review.

Decisions, node facts and version snapshots are immutable. Undo restores projections through a new recorded decision and version; it keeps the historical evidence. Undo is refused after later affected changes or dependencies would make restoration invalid. History shows the refusal reason. Explicit asset bindings block legacy retirement until an administrator reviews and removes/rebinds them; asset merges never silently retarget a service binding.

## Additive migration

Alembic `0003_service_exposure` adds six tables. `exposure_nodes`, `exposure_relationships` and `exposure_attributions` hold current projections. `exposure_decisions`, `exposure_node_facts` and `exposure_versions` retain immutable evidence/history. No existing observation, finding, asset or assignment is rewritten or backfilled into service relationships.

The frozen migration validates tables pre-created by the initial dynamic migration, creates indexes and immutability triggers, and refuses rollback once exposure tables contain data. Empty rollback preserves earlier data. PostgreSQL integration and dump/restore QA verify the database protections; ordinary SQLite unit tests are not evidence for PostgreSQL locking behavior. Take a complete backup before upgrading an operational installation.

## Report formats and examples

Services **Download current page**, CLI `exposure report`, and MCP `exposure_report` use the shared renderer. JSON retains the full paged envelope and evidence. CSV/Markdown export the page's stable report columns; nested evidence uses sorted JSON, null becomes an empty cell, and CSV prefixes formula-looking strings with an apostrophe for spreadsheet safety. Export each page explicitly. These commands export the current page, without fetching
the entire inventory.

See the [hypothetical Cedar example](../examples/service-exposure/README.md) and [CLI/MCP commands](cli-mcp.md). Vendor export validation remains bounded by the [schema support matrix](offline-source-formats.md). Topology imports use this application's documented graph schema. Vendor-native topology
compatibility has not been validated.
