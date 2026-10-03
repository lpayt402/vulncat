# Asset identity

## Purpose and current status

Vulncat treats asset identity as a conservative evidence-reconciliation problem. The canonical key is the
generated UUID on `assets`; scanner UUIDs, hostnames, IP addresses, MAC addresses, and aliases are evidence
attached to that asset, not primary keys.

The current implementation includes deterministic normalization, automatic resolution, an identity-review
queue, merge preview and merge, identifier move and split, canonical-name pinning, verification, shared-IP
marking, review rejection/defer, safe event undo, and event history. The principal implementation files are
[normalization.py](../backend/vulnbatch/identity/normalization.py),
[resolver.py](../backend/vulnbatch/identity/resolver.py), and
[identity.py](../backend/vulnbatch/api/routes/identity.py).

## Identifier model

Implemented identifier types are:

- `tenable_asset_uuid`
- `agent_uuid`
- `nessus_host_id`
- `hardware_uuid`
- `mac_address`
- `fqdn`
- `short_hostname`
- `ipv4`
- `ipv6`
- `user_alias`

Each `asset_identifiers` row retains normalized and original values, first and last observation dates, source
import, confidence, verification/override flags, active state, shared/non-identifying state, and optional
validity dates. `asset_identifier_observations` records the import row, matching rule, confidence, observation
time, and structured evidence.

The schema permits one normalized identifier to appear on more than one asset. This is deliberate: duplicated
or reassigned evidence must be representable so it can enter review rather than being silently collapsed.
See [data-model.md](data-model.md) and
[models.py](../backend/vulnbatch/db/models.py).

## Normalization

Normalization is deterministic:

- Blank values and scanner placeholders such as `unknown`, `n/a`, `null`, and `not set` become null.
- Hostnames are trimmed, case-folded, and stripped of a trailing period.
- A dotted host value is inferred as FQDN; an undotted value is inferred as short hostname.
- IPv4 and IPv6 use Python's `ipaddress` parser and compressed canonical representation.
- Unspecified IP addresses are treated as missing.
- MAC addresses become lowercase colon-separated octets; all-zero and malformed values become missing.
- Tenable, Agent, and hardware UUID values must parse as UUIDs.
- Nessus host IDs are trimmed and case-folded.
- Original source values remain in evidence even when normalization rejects them.

FQDN and short hostname remain separate identifiers. A short name is never derived as an authoritative key
from the leftmost FQDN label.

## Automatic resolution order

The resolver evaluates only active canonical candidates and follows this order:

1. A matching manual override.
2. Exact Tenable asset UUID or Agent UUID.
3. Exact hardware UUID.
4. Exact MAC address.
5. Exact FQDN.
6. One manually verified short hostname.
7. Unique recent IP history.
8. A bounded weighted combination.

Strong matches are still reviewed when other incoming strong evidence or evidence already assigned to another
asset conflicts. Duplicate strong identifiers on multiple assets also enter review.

The weighted rule uses these components:

- matching Nessus host ID: `0.60`
- matching short hostname: `0.15`
- equal operating-system text: `0.15`

One candidate must reach `IDENTITY_AUTO_MATCH_THRESHOLD`, which defaults to `0.85`. Multiple qualifying
candidates enter review. IP address and generic "prior observations" are not additional weighted components
in the current implementation.

If no safe match is found, the resolver creates a new canonical asset. If a weak or conflicting candidate
exists, it creates an identity-review item instead.

## IP-only association

An IP-only observation can match automatically only when the same normalized IP has exactly one:

- active association;
- recent association inside `IP_ASSOCIATION_STALENESS_DAYS`;
- non-shared association; and
- non-conflicting candidate.

The default staleness window is 90 days, and the rule confidence is `0.90`. If the configured threshold is
higher than that confidence, the observation enters review. A recently observed inactive association also
prevents a unique automatic match, which is conservative for reassignment.

An IP marked `shared_or_non_identifying` is excluded from automatic matching. The implementation performs no
reverse DNS, directory, CMDB, scanner API, or other network enrichment.

## Identity review

Ambiguous import records preserve:

- incoming normalized and original identifiers;
- candidate asset UUIDs;
- conflicting evidence;
- matching rule and explanation;
- confidence;
- source import and normalized import record;
- first and last observation dates.

Authenticated users can view the queue and candidate evidence. Administrator plus CSRF authorization is
required to resolve an item by:

- matching the record to an existing active asset;
- creating a new asset;
- marking matching incoming IP evidence shared;
- rejecting the proposal; or
- deferring the decision.

Matching or creating an asset applies the normalized import record, creates manually verified overrides for
the incoming identifiers, and creates or updates its finding when the row is in the tracked inventory.

API surface:

- `GET /api/v1/identity/review`
- `GET /api/v1/identity/review/{review_id}`
- `POST /api/v1/identity/review/{review_id}/resolve`

## Manual identity operations

Implemented administrator operations are:

- `POST /api/v1/identity/merge/preview`
- `POST /api/v1/identity/merge`
- `POST /api/v1/identity/identifiers/{identifier_id}/move`
- `POST /api/v1/identity/identifiers/{identifier_id}/split`
- `POST /api/v1/identity/assets/{asset_id}/pin-name`
- `POST /api/v1/identity/identifiers/{identifier_id}/verify`
- `POST /api/v1/identity/identifiers/{identifier_id}/mark-shared`
- `POST /api/v1/identity/events/{event_id}/undo`
- `GET /api/v1/identity/events`

Merge preview reports strong-identifier conflicts and source/target finding counts. Merge requires an explicit
source and target UUID plus a reason. The source asset becomes inactive and redirects to the target. Findings
with the same target key are consolidated; evidence and status rows are reassigned and a detailed event
payload is retained.

Move and split set the affected identifier as manually verified and overridden. Pinning normalizes the new
display hostname and prevents later metadata imports from replacing it. Verification sets confidence to
`1.0`. Shared marking is limited to IPv4/IPv6 identifiers. Undo validates that affected assets, identifiers,
and findings are still in the expected post-event state before reversing a merge, move, split, pin, verify,
or shared-IP event; otherwise it fails without a partial reversal.

Current gaps:

- no dedicated add/remove user-alias endpoint;
- no endpoint to remove a manual override or unmark a shared IP;
- review-to-existing events are currently recorded as non-reversible;
- merge/split integration and undo scenarios are not covered by the present automated suite; and
- the React interface exposes review resolution, while the lower-level merge/split/undo operations currently
  require the API.

## Validation evidence

[test_identity.py](../tests/unit/test_identity.py) currently proves:

- deterministic hostname, IP, and MAC normalization;
- one recent unambiguous IP-only association;
- conflicting UUID plus IP enters review;
- duplicate unverified short hostnames do not merge;
- manual overrides take precedence;
- shared IPs do not identify an asset;
- cross-asset strong conflicts enter review; and
- the current weighted rule can meet the threshold.

These are unit tests of the resolver. The end-to-end smoke test also proves a database-backed conflicting
identifier review and manual match-existing resolution. Database-backed merge, split, future-import manual
precedence, and undo remain separate integration gates.
