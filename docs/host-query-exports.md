# Host query and export contract

## Shared query contract

`HostQueryV1` and `FindingScopeV1` in
[query.py](../backend/vulnbatch/schemas/query.py) are strict Pydantic models with unknown fields rejected.
The same query normalization and SQL service in
[service.py](../backend/vulnbatch/queries/service.py) is used for paginated host listing, preview/count,
saved-view persistence, and export asset resolution.

Every saved view and export records `query_schema_version=1`.

## Asset scope modes

Every export request contains exactly one discriminated asset scope:

- `selected_assets`: 1 to 50,000 explicit active canonical asset UUIDs;
- `host_query`: all active canonical assets matching one normalized `HostQueryV1`; or
- `saved_view`: the assets matching a permitted saved view at submission time.

Pydantic's `mode` discriminator rejects mixed shapes. Explicit selection verifies that every submitted UUID is
an active, unmerged canonical asset.

The finding scope is a separate object. Host scope determines which assets participate; finding scope
determines which findings on those assets are snapshotted.

## Queryable fields

The backend model currently accepts:

- bounded free text `q`;
- canonical hostname and aliases;
- IP address with `current`, `history`, or `both`;
- Tenable asset UUID, Agent UUID, Nessus host ID, hardware UUID, and MAC;
- operating system;
- system owner, administrative team, technical owner;
- environment, data center, business service, server role;
- maintenance group and patch group;
- tags with `any` or `all`;
- last-scan range;
- identity-confidence range and unresolved-review state;
- numeric ranges for open Medium, open Low, mature, new/deferred, and overdue counts;
- oldest-open-finding range;
- existence of open findings matching severity, status, maturity, SLA, plugin ID/family, CVE, exploit
  indicator, port, or protocol; and
- allowlisted sorting.

The free-text field is capped at 200 characters and searches canonical hostname and normalized identifier
values with escaped SQL `LIKE` wildcards. It is not interpreted as SQL or an expression language.

## Deterministic semantics

- Different filter categories are combined with AND.
- Multiple values within one category use OR/`IN`.
- `tags.match=any` requires at least one named tag.
- `tags.match=all` requires every named tag.
- Hostnames and classification strings are trimmed/lowercased; trailing hostname periods are removed.
- IP values are parsed by `ipaddress`.
- MAC values are normalized to lowercase colon-separated octets.
- `current` IP means an active identifier row.
- `history` currently means an inactive identifier row.
- `both` includes active and inactive rows.
- Only active, unmerged canonical assets are returned.
- Every requested sort is allowlisted, and asset UUID ascending is always the final tie-breaker.
- Browser pagination is applied only after the full server-side filter and count.

The normalized query is returned by list and preview and persisted for query/saved-view exports.

Implementation caveat: the query predicate currently maps `mac_addresses` to identifier type `mac`, while
ingestion stores `mac_address`. MAC filtering therefore needs correction and a PostgreSQL integration test
before it should be relied upon. The remaining identifier filters also require the full HQE parity test suite;
that suite is not currently present.

## Finding scope

`FindingScopeV1` can filter:

- severity;
- maturity state;
- SLA state;
- finding status;
- plugin ID;
- CVE;
- port and protocol;
- exploit indicator;
- owner and team; and
- First Found and Last Found ranges.

Defaults are Medium and Low with statuses `open`, `new_or_maturity_deferred`, `planned`, and `in_progress`.
An empty optional list means no restriction for that category.

## API

Host and preview:

- `POST /api/v1/assets/query`
- `POST /api/v1/assets/query/preview`

Saved views:

- `GET /api/v1/saved-views`
- `POST /api/v1/saved-views`
- `GET /api/v1/saved-views/{view_id}`
- `PUT /api/v1/saved-views/{view_id}`
- `DELETE /api/v1/saved-views/{view_id}`

Exports:

- `POST /api/v1/exports`
- `GET /api/v1/exports`
- `GET /api/v1/exports/{export_id}`
- `GET /api/v1/exports/{export_id}/download`
- `POST /api/v1/exports/{export_id}/cancel`
- `POST /api/v1/exports/{export_id}/retry`

Listing, preview, status, and download require authentication. Export submission, cancel, and retry require an
administrator plus CSRF. A non-administrator can see/download only exports they requested; the current
submission policy means new exports are administrator-only.

## Preview

Preview returns:

- normalized query;
- total matching host count;
- up to five sample hosts;
- estimated matching finding count; and
- warnings for zero hosts, unresolved identity items, and the configured large-finding threshold.

Preview records an audit event with query, human summary, finding scope, counts, user, request ID, and client
address. Zero-host preview is allowed so the UI can explain the result, but export submission rejects it.

Preview currently applies only to an ad hoc host query. The report builder does not provide an equivalent
preview operation for explicit selections or a saved-view scope.

## Durable submission snapshot

[exports/service.py](../backend/vulnbatch/exports/service.py) resolves the complete asset set at submission
time, not one browser page. It then:

1. rejects a zero-asset scope;
2. counts findings using the independent finding scope;
3. requires `confirm_large_export=true` when the finding count meets the configured threshold;
4. records original/normalized query, saved-view name/revision, schema version, requester, data-as-of time,
   source-import cutoff, counts, output format, and expiry timestamp;
5. writes one ordered `export_asset_snapshots` row per asset;
6. writes one ordered, denormalized `export_finding_snapshots` row per finding; and
7. queues a PostgreSQL job.

A saved-view edit after submission cannot change an existing export because the resolved rows and saved-view
revision are already persisted.

The worker generator reads only snapshot rows. A failed export retry resets the same job and uses the same
snapshot. Cancellation is limited to queued jobs. Artifact generation uses a temporary path followed by
atomic replacement.

## Output formats and provenance

Implemented formats:

- XLSX workbook with `Host Summary`, `Finding Detail`, and `Export Metadata`;
- ZIP CSV package containing `host_summary.csv`, `finding_detail.csv`, and `export_metadata.json`; and
- printable standalone HTML containing metadata and both tables.

XLSX uses XlsxWriter constant-memory mode and disables string-to-formula and string-to-URL conversion.
Every user/scanner-controlled cell is passed through formula protection for XLSX and CSV. HTML values and
metadata are escaped.

The generated artifact is SHA-256 hashed. Status and download responses expose hash/size metadata, and
download includes `X-Content-SHA256`. Submission, completion/failure, cancellation, retry, preview, and
download events are audited.

PDF output is not implemented; printable HTML is the supported print path.

## Retention and cleanup

Submission calculates `expires_at` using `EXPORT_RETENTION_DAYS`, which defaults to 30. When idle, the worker
runs bounded retention cleanup at most once per minute. It removes expired report artifacts only from the
configured report root and clears their output path while retaining export and audit metadata. Optional
upload, import-evidence, and audit retention remains disabled when its setting is blank.

## UI workflow

The current React UI provides:

- URL-backed common filters and readable chips on Hosts;
- server-side total count and pagination;
- current-page row selection separate from `Export all N matching`;
- query preview before all-matching export;
- a report builder with all three scope modes and separate finding controls;
- private/shared saved views with revision display;
- export directly from a saved view;
- export status/progress, failure, retry/cancel where allowed, hash, expiry, and download.

The saved-view editor currently accepts versioned query JSON rather than exposing every field through a
form-based builder. The Hosts and report-builder forms expose useful subsets of the backend contract, not every
available filter.

## Validation status

Frontend tests cover request/client helpers and host URL-query helpers. The PostgreSQL-backed end-to-end
validator covers shared list/preview semantics, all three scope modes, injection-like input, snapshot
stability, saved-view mutation, formula protection, administrator/read-only authorization, hashes, and audit
metadata.

Exhaustive per-filter/current-versus-history-IP tests, beyond-first-page browser proof, browser download, and
large-input memory validation remain incomplete. See
[requirements traceability](requirements-traceability.md) for exact status.
