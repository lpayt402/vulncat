# Offline preview validation

This record covers the initial preview stage on baseline
`0cf132362a81d3b2b1d8b1c2f83a66be0f215e7d`. That stage preserved the persisted schema,
legacy resolver and finding lifecycle. The repository was private and the work had not
been merged or published. Later checks are recorded in [persistent validation](persistent-validation.md)
and [service validation](service-validation.md).

## Local measured benchmark

On 2026-10-02, `PYTHONPATH=backend python scripts/validation/benchmark_reconciliation.py --assets 5000 --history-observations 10000` ran on Windows / Python 3.12.10 with the offline-v2 validation fixes:

| Measure | Result |
|---|---:|
| Synthetic existing assets | 5,000 |
| Input logical rows | 15,125 |
| Unique vulnerability observations | 15,000 |
| Duplicate observations counted | 100 |
| Row errors counted | 25 |
| Indexed candidate checks | 15,000 |
| Response page items | 50 |
| Elapsed with allocation tracing | 18.217 seconds |
| Peak traced Python allocations | 124.67 MiB |
| Fixture input size | 2,028,393 bytes |

Measurement includes index construction, parsing, normalization, conflict preflight, matching and page slicing. Synthetic fixture/candidate generation occurs before the timed section. `tracemalloc` is enabled and adds runtime overhead. Memory is Python allocations during the measured section, not whole-process RSS. This is not a production PostgreSQL benchmark or browser latency measurement. CSV and NDJSON parsers stream; bundle-wide conflict checking stages bounded observations. HTTP pagination recomputes the preview.

The separate history measurement resolved and added 10,000 distinct fresh observations of one source ID in 0.232 seconds, with 10,000 candidate checks and tracing disabled. This checks the repeated-history path, not concurrent requests or database loading.

## Verification scope

New tests exercise source/instance scoping, unknown infrastructure inventory object type, DNS/shortname/IP-only review, source-native conflicts, late cloned-agent evidence, renamed hosts, reimage evidence, stale/future/missing time, timezone errors, record-update versus observed time, network scopes, duplicate fingerprints and row accounting across all seven hypothetical source fixtures. API tests exercise CSRF, column/envelope discovery, invalid options/encoding, file-count limits, bounded response pages and preservation of inventory counts on a SQLite fixture. UI tests verify the transient warning and actual multipart fields/mapping/result contract through a mocked API.

The original unit suite and Cedar Ridge validator are preserved. Windows sandbox restrictions prevented pytest temporary-directory access and esbuild process launch; the authorized test commands were run with sandbox escalation. Frontend dependencies were installed from the unchanged lockfile with lifecycle scripts disabled. No vendor or directory connections were made.

The offline-v2 backend checks passed: 154 tests, Ruff, mypy (68 source files), and the existing Cedar Ridge offline validator. The validator made zero network requests. No dependency or lockfile changes were needed.

Frontend checks passed: 23 tests across four files, lint, TypeScript checks and production build. Format-transition tests cover JSON to CSV/NDJSON/Nessus XML, returning to JSON, changing away from the Nessus source and preserving mapping edits during same-format discovery. Non-JSON requests omit records_path and ignore JSON path suggestions. Infrastructure inventory guidance distinguishes missing object types that need review from unsupported object types that reject.

The validation follow-up first reproduced 48 failures across 55 path/kind/format/CVE/infrastructure inventory regression cases, then 14 additional failures for Boolean identifiers and invalid empty containers. These cases now pass. Missing mapped paths produce explicit row errors; present null optional leaves remain distinct. Kind inference rejects conflicting evidence, coverage requires an outcome, infrastructure inventory matching accepts only device/VM native IDs, and CVEs accept only strings or lists of strings. Configuration rejects incompatible records paths and unknown/blank mappings. The parser version is offline-v2; full policies are documented in [offline source formats](offline-source-formats.md#explicit-validation-policy-offline-v2).

Independent follow-up review passed 18 in-memory checks for the additional identifier/container cases, supported optional empty values, numeric IDs and continued processing of later valid rows.

Independent review found and regression tests now cover placeholder native/hardware IDs, duplicated hardware with simultaneous primary names, Nessus IP/IPv6 scan targets, UTC conversion overflow and nested JSON column discovery. UI regressions also exercise revisiting both previously successful and previously failed JSON records paths. Repeated source-ID histories now use earliest/latest/unknown time bounds instead of scanning every snapshot during every match. The benchmark also supports `--history-observations 10000` to exercise this case separately.

Local Docker engine access was denied at the engine pipe during the initial increment; that action was stopped without retry. The validation follow-up makes no local Docker attempts. Container build validation uses the existing private PR CI workflow. PostgreSQL migration/runtime and full browser validation remain unrun.

Local Git staging was denied because the execution workspace exposes `.git` as read-only; that action was stopped without retry. The validation follow-up makes no local Git metadata writes. The explicitly authorized GitHub connection updates the existing draft PR branch, retaining the first increment as the fix commit's parent and the upstream main commit in its ancestry. Repository visibility remains private.

## Persistence requirements at the preview stage

This preview does not write source observations, assignments, findings or durable identity-review items. It does not supply a new merge/split/undo interface. Persistent source consolidation, migration/backfill, source-specific lifecycle policy, completeness decisions and guarded reversible assignments required a separate design review and the PostgreSQL integration tests described in [the design proposal](offline-reconciliation-design.md). Existing legacy matching remains unchanged, including its FQDN/unique-IP behavior; use the new preview's conservative explanations before accepting legacy associations.

Unverified export schemas, directory CSV conversion requirements, infrastructure inventory interface/IP joins, JSON-array memory, no persistent preview cache and lack of full browser/Docker runtime coverage remain explicit limitations. README diagrams were deferred until review of the persistence contracts.
