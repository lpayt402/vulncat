# Finding lifecycle, maturity and SLA

## Finding identity

Vulncat separates the scanner vulnerability definition from the asset-specific finding instance.

`vulnerability_definitions` is unique by `(scanner_source, plugin_id)`. An `asset_findings` instance is unique
by:

```text
(canonical asset UUID, scanner source, plugin ID, normalized port, normalized protocol)
```

Plugin name and CVE values are metadata and do not determine finding identity. A missing port normalizes to
`0`; missing, zero-like, or general protocol values normalize to `general`. The implementation is in
[identity.py](../backend/vulnbatch/findings/identity.py) and enforced by the database constraint documented in
[data-model.md](data-model.md).

## Supported statuses

The current status vocabulary is:

- `open`
- `new_or_maturity_deferred`
- `planned`
- `in_progress`
- `not_observed`
- `remediated`
- `risk_accepted`
- `false_positive`
- `not_applicable`

On its first observation, a finding is `new_or_maturity_deferred` when it is inside the maturity gate;
otherwise it is `open`.

Administrators can manually change a finding to any supported status using
`PUT /api/v1/findings/{finding_id}/status` with `new_status` and a nonblank `reason`. The change creates
`finding_status_history` and an audit event. Read-only users can view finding lists, plugin grouping, detail,
observations, and history but cannot change status.

## Recurring observations

[lifecycle.py](../backend/vulnbatch/findings/lifecycle.py) applies each observation to the existing instance:

- `first_seen_at` remains the earliest observation time;
- `last_seen_at` becomes the latest observation time;
- `first_found_at` remains the earliest reliable supplied First Found;
- `last_found_at` becomes the latest supplied Last Found;
- `times_observed` increments; and
- current evidence, solution, severity, and scoring metadata are updated from later non-null evidence where
  implemented.

An observation of a `not_observed` or `remediated` finding changes it to `open`, increments
`reopened_count`, and records a reopening history event. Other manual terminal states are not automatically
reopened by the lifecycle function.

Finding observations preserve import, normalized row, observed/scan time, evidence, severity, solution, and
raw normalized finding metadata.

## Absence reconciliation

Absence from a normal or partial import does nothing. It never means remediated.

When an import is marked `complete_comparable_scope=true`, the worker considers findings for assets
observed in that import and scanner sources present in that import. A finding not observed in that scope can
move to `not_observed`. Existing `remediated`, `risk_accepted`, `false_positive`, `not_applicable`, and
`not_observed` states are preserved.

Current limitation: detailed scan-target, credential, plugin-set, and export-filter comparability are not
independently verified. The reconciliation safeguard presently depends on the administrator's completeness
flag and the set of observed assets/scanner sources. Operators must not enable it for partial or filtered
exports.

## Vulnerability maturity

[calculations.py](../backend/vulnbatch/findings/calculations.py) selects the first available date in this order:

1. CVE publication date
2. vendor advisory or patch release date
3. plugin publication date
4. plugin modification date
5. First Found, only when `ALLOW_FINDING_DATE_MATURITY_FALLBACK=true`

Upload time is never used. The selected date and source are persisted. The default maturity gate is 30
calendar days.

Before the gate date, the stored maturity state is `deferred` and the initial lifecycle status is
`new_or_maturity_deferred`. At or after the gate date, maturity state is `mature`. When no date exists, it is
`unknown`.

The current emergency override treats any of these definition flags as sufficient to bypass the gate:

- exploit available;
- exploited by malware; or
- known exploited.

It can mark maturity as `mature` without inventing a maturity date.

## Environmental SLA

SLA is calculated independently from maturity:

- Medium default: 60 calendar days
- Low default: 90 calendar days
- other severities: not applicable

The calculated states are persisted as:

- `not_due`
- `approaching` when due today
- `overdue`
- `unknown`
- `not_applicable`

The host and finding APIs expose due date, state, and derived overdue days.

Import processing calculates SLA from the earlier of the persisted and incoming First Found values. A later
row therefore cannot reset the SLA clock. The unit suite covers the composition of recurring-observation
earliest-date preservation and SLA calculation; a dedicated database-backed recurring-import test remains
desirable.

## API and UI surfaces

Implemented API endpoints:

- `GET /api/v1/findings`
- `GET /api/v1/findings/plugins`
- `GET /api/v1/findings/{finding_id}`
- `PUT /api/v1/findings/{finding_id}/status`

The list supports severity, status, maturity, SLA, plugin ID/family, CVE, owner, team, environment,
maintenance group, port, protocol, and bounded free-text filters. Detail includes definition text, current
evidence, observations, and status history. The plugin view groups affected hosts under each vulnerability
definition.

Host details and export snapshots also expose lifecycle, maturity, and SLA fields. See
[host-query-exports.md](host-query-exports.md).

## History behavior

Status history is written for:

- initial finding creation;
- automatic reopening;
- authoritative transition to `not_observed`; and
- manual status change.

An ordinary repeat observation that does not change status creates a finding observation but not another
status-history row.

## Validation evidence

[test_findings.py](../tests/unit/test_findings.py) proves:

- plugin renaming does not change the normalized key;
- a different port creates a different key;
- earliest First Found is preserved by the lifecycle function;
- remediated findings reopen on observation;
- partial absence does not change state;
- authoritative absence becomes `not_observed`, not `remediated`;
- maturity-date precedence and optional fallback;
- emergency maturity override; and
- severity-specific SLA arithmetic.

These are unit tests. Database-backed recurring imports, authoritative-scope verification, manual history,
and the SLA consistency limitation remain integration gates.
