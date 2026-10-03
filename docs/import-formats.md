# Import formats

## Current import workflow

The Imports interface offers Scanner CSV, Scanner JSON, Scanner XML (.nessus), and Generic CSV with mapping. The fixed scanner options accept the Tenable VM CSV and JSON/NDJSON schemas and the Nessus XML subset documented below. These labels do not imply support for arbitrary scanner schemas or live integrations.
Uploads require administrator and CSRF authorization, are written in 1 MiB chunks, are bounded by
`MAX_UPLOAD_BYTES`, and are queued to the PostgreSQL-backed worker.

Implementation:

- [imports API](../backend/vulnbatch/api/routes/imports.py)
- [normalization model](../backend/vulnbatch/imports/models.py)
- [common normalization](../backend/vulnbatch/imports/common.py)
- [worker processor](../backend/vulnbatch/imports/processor.py)

API surface:

- `POST /api/v1/imports/upload`
- `POST /api/v1/imports/generic/preview`
- `POST /api/v1/imports/generic/commit`
- `GET /api/v1/imports`
- `GET /api/v1/imports/{import_id}`

The general upload endpoint uses multipart fields `upload`, `source_type`, `force_reprocess`, and
`complete_comparable_scope`. The generic workflow uploads and previews first, then commits the stored source
file with an approved mapping.

## Immutable source files and duplicate handling

The upload service:

1. strips directory components from the submitted filename;
2. streams to a temporary file while calculating SHA-256;
3. enforces the configured byte limit;
4. checks extension and a bounded content signature;
5. stores a new file under `<upload-dir>/<hash-prefix>/<sha256><extension>`; and
6. creates one unique `source_files` row per SHA-256.

The source file is not modified after promotion. Its filename, content type, detected source type, byte size,
uploader, upload time, hash, and persistent path are recorded.

When a matching hash already has an import and `force_reprocess=false`, the API returns the prior import rather
than queueing duplicate processing. Force reprocessing creates a new import run referencing the same source
file. During force processing, a row whose content hash exists in a completed prior run reuses the prior
asset/finding references and does not create a duplicate observation.

## Extension and signature checks

Accepted extensions:

| Source type | Extensions |
|---|---|
| `tenable_csv` | `.csv` |
| `tenable_json` | `.json`, `.ndjson` |
| `nessus_xml` | `.nessus`, `.xml` |
| `generic_csv` | `.csv` |

Nessus input must begin with XML after leading whitespace. JSON must begin with `{` or `[`, or have a
first nonblank line beginning with `{` for NDJSON. Text imports containing NUL bytes are rejected.

These checks are defense in depth, not content authentication. Parsing and canonical validation remain the
authoritative checks.

## Tenable VM CSV

[tenable.py](../backend/vulnbatch/imports/tenable.py) uses `csv.DictReader`, requires a recognized Plugin ID
header, and processes records incrementally. Header matching ignores case and non-alphanumeric separators and
supports common Tenable flat and dotted aliases.

Recognized data includes scanner UUIDs, hostname/IP/MAC/OS/tags, plugin identity and family, severity/risk,
CVSS/VPR/EPSS, CVEs, network service, evidence and solution, first/last found, publication dates, exploit
indicators, and scan metadata.

Unexpected columns remain in `raw_record`. Missing values remain null.

## Tenable VM JSON and NDJSON

The parser accepts:

- a JSON array of objects;
- one JSON object;
- an object containing `findings`, `vulnerabilities`, `results`, or `items`;
- newline-delimited JSON objects.

Nested objects are flattened for alias lookup while the original object remains raw evidence.

Current memory limitation: the implementation calls `stream.read()` before JSON decoding. Therefore both
standard JSON and NDJSON are currently held in memory as text. Large Tenable JSON has not yet met the design's
streaming acceptance gate; prefer CSV for very large inputs until a streaming JSON decoder and load test are
implemented.

## Nessus XML

[nessus.py](../backend/vulnbatch/imports/nessus.py) uses `defusedxml.ElementTree.iterparse` with DTDs, entities,
and external access forbidden. It clears each completed `ReportHost`, so XML parsing is host-streamed rather
than building the entire document tree.

Host properties map Nessus IP, FQDN, NetBIOS name, operating system, MAC, host UUID, Agent UUID, hardware UUID,
and host start/end times. Each `ReportItem` maps plugin, severity, port/protocol/service, CVEs, risk scores,
text evidence, dates, and exploit indicators.

Unsafe entity payloads raise `UnsafeXmlError`; malformed documents and files without a `ReportItem` raise
`ImportParseError`.

## Generic CSV

[generic_csv.py](../backend/vulnbatch/imports/generic_csv.py) implements a strict canonical-field allowlist.
A valid mapping requires:

- `plugin_id`; and
- either `severity` or `risk_factor`.

Unknown canonical fields, missing source columns, duplicate normalized headers, and missing required mappings
block commit. Preview returns up to 20 normalized records, the original headers, mapping warnings, unmapped
columns, and a truncation flag.

Commit can store a named private mapping profile. Only administrators may mark a profile shared. The
`import_profiles` table and link from the import run are implemented, but the current REST/UI surface does not
list, select, edit, or delete saved import profiles. Reusable profile management is therefore incomplete.

## Canonical normalization

Each row produces a `NormalizedImportRecord` containing:

- `NormalizedAsset`;
- `NormalizedFinding`;
- deterministic raw-record SHA-256;
- raw evidence;
- inclusion decision; and
- bounded parse warnings.

Important behavior:

- dates are parsed into UTC-aware datetimes or dates where recognized;
- invalid UUID/MAC/IP values become null with warnings;
- CVEs are normalized to uppercase `CVE-YYYY-NNNN...`;
- severity numbers `0` through `4` map to informational through critical;
- port must be between 0 and 65535;
- unknown or missing severity is warned;
- missing Plugin ID prevents inventory inclusion;
- values are never synthesized.

`TRACKED_SEVERITIES` defaults to `medium,low`. Other severities still contribute to import severity counts but
are skipped from the active finding inventory.

## Worker processing and import status

For each normalized row, the worker stores raw and normalized evidence, resolves identity, creates an
identity-review item when ambiguous, and upserts the vulnerability definition and asset finding when the row
is included. Progress heartbeat is updated every 500 records. Parse warnings retained on the import summary
are capped at 1,000 entries; each row retains its own complete warning list.

Import status exposes totals, included/skipped counts, severity counts, asset matching results, finding
creation/update counts, warnings, failure reason, job status/progress, source metadata, and identity-review
count.

## Complete comparable scan flag

`complete_comparable_scope=true` enables absence reconciliation for canonical assets observed in the import
and scanner sources present in that import. The strongest automatic change is `not_observed`, never
`remediated`.

Current limitation: the application relies on the administrator flag plus observed assets/scanner sources; it
does not yet persist and independently verify a detailed comparable scan-target/plugin scope. Use this option
only when the export is known to represent a complete comparable scan. See
[finding-lifecycle.md](finding-lifecycle.md).

## Offline validation

[Parser unit tests](../tests/unit/test_import_parsers.py) cover all four formats, tracked severity, nested JSON, external-entity rejection, unmapped generic columns, and missing required mapping. The [hypothetical triage example](../examples/cedar-ridge/README.md) adds realistic recurring-import and ownership questions without contacting a scanner.

The [API smoke validator](../scripts/validation/smoke_e2e.py) checks imports through the web/worker/database path in an explicitly designated disposable stack. Its existence is not proof of a successful run; consult [VALIDATION.md](../VALIDATION.md) for the recorded import results.

Oversized uploads, full mapping-profile reuse, broad malformed input, and large-scale completion still need additional coverage.
