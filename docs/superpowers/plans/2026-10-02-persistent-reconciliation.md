# Persistent Reconciliation Implementation Plan

> Execute inline with test-driven development; delegate the bounded React workflow after these API contracts are fixed. Architecture approval covers additive persistence and reversible matching. Keep the PR draft and private; use the authorized GitHub connector, never local Git metadata or Docker.

**Goal:** Retain immutable offline source evidence and make observation assignments reviewable, versioned and reversible without changing scanner finding lifecycle.

**Architecture:** Separate additive tables for source instances, import batches, immutable observations/locators/native IDs, vulnerability/coverage evidence, mutable current assignment projections, immutable assignment versions and decisions. A single database mutation lock serializes imports and decisions; a revision and per-observation versions reject stale requests. No automatic backfill or destructive rewrite of legacy records.

**Tech Stack:** Existing SQLAlchemy 2.0/PostgreSQL, Alembic, FastAPI and React/Mantine; SQLite unit fixtures and ephemeral hosted PostgreSQL integration tests.

## Contracts

- POST `/api/v1/reconciliation/imports`: preview multipart files/options plus a nonblank `request_key`. Return immutable batch ID/counts/error sample, new-observation/assigned/review counts, current revision and replay flag. The same key and payload/actor replay the original batch; changed payload/actor returns 409. Every repeat export with a new key retains file/row locators; event fingerprints deduplicate observations, not import history. All bounded rows are staged before matching to catch later conflicts.
- GET `/api/v1/reconciliation/observations`: bounded page (default 50, maximum 500) with optional review status, asset and source filters. Return revision, total, items containing observation ID, current asset ID/version/status, rule/rationale/confidence/candidates and immutable normalized evidence.
- GET `/api/v1/reconciliation/observations/{id}`: evidence, bounded locators, assignment versions and decision IDs. GET `/assets`: searchable bounded asset choices. GET `/decisions` and `/{id}`: paged audit and operation details.
- POST `/api/v1/reconciliation/decisions`: `request_key`, `expected_revision`, nonblank reason, action (`assign`, `create`, `reject`, `defer`, `merge`, `split`, `undo`), selected `observation_ids`, their `expected_versions`, optional source/target asset IDs or undo decision ID. Assignment/correction selects an active target; creation creates a separate provisional asset. Split moves selected evidence from one asset into a new asset; merge moves all current source-asset evidence into an active target. Both preserve the asset rows, immutable evidence and legacy scanner findings. Undo appends inverse assignment versions only when affected versions still equal the original operation's after-state; unrelated subsequent imports are retained. Undo of import or undo operations is unsupported.
- Read endpoints require authentication. All writes require administrator and CSRF. Decisions and batches retain actor identity; replay keys cannot disclose another actor's result. Failed scans, native statuses and absence never alter finding status, asset active/retired state or scan timestamps.

## Steps

- [x] Write `tests/unit/test_persistent_reconciliation.py`: repeated imports/locators, scoped IDs, late clone conflicts, stale/IP-only review, native statuses, wrong-match correction/undo, merge/split, replay/stale versions, atomic rollback and immutable ORM records. Run `PYTHONPATH=backend python -m pytest tests/unit/test_persistent_reconciliation.py -q`; confirm missing implementation failures before adding production code.
- [x] Add `backend/vulnbatch/db/reconciliation.py` and register model discovery in `db/models.py`. Implement `reconciliation/storage.py` for lock/index/batched import persistence and `reconciliation/decisions.py` for guarded transitions. Extend preview staging through a reusable helper while keeping its contract unchanged. Batch inserts/queries in groups of 500; never issue a per-row observation lookup.
- [x] Add fixed-definition Alembic `0002_persistent_reconciliation.py`. Preserve historical revision 0001. Its existing dynamic create-all may already create these tables on a fresh database, so revision 0002 checks existing tables and creates missing ones. Install immutability triggers; seed the mutation lock. Empty downgrade drops only additive tables. Populated downgrade refuses and directs operators to retain tables during application rollback or restore a tested backup; never delete evidence to make rollback succeed.
- [x] Add `schemas/reconciliation.py` and routes in `api/routes/reconciliation_storage.py`; register them in `main.py`. Reuse bounded offline parsing helpers, not the legacy import lifecycle. Guard legacy asset merge/undo against retiring assets that have current persistent evidence. Add API tests for write/read permissions, CSRF, 422/409, pagination and all-or-nothing writes.
- [x] Delegate `frontend/src/components/PersistentReconciliation.tsx` plus tests, and bounded preview save integration, with the contracts above. Provide an explicit save action, paged review/evidence, target search, reason/version guards, correction/merge/split and audit/undo. Keep transient preview independent and disclose that scanner reports are unchanged.
- [x] Add `tests/integration/test_persistent_postgres.py` for populated upgrade/empty rollback/refused populated rollback, trigger immutability and actual concurrent import/decision transactions. Run in a dedicated ephemeral PostgreSQL CI job using a disposable database; never connect to a vendor or user database. Include realistic synthetic repeated sources and snapshot preservation.
- [x] Add `scripts/validation/benchmark_persistence.py`: measured 5,000-asset import/reimport and 50-item review page, including statement counts and memory/runtime methodology. Document results and migrations in `docs/persistent-reconciliation.md`, update earlier design gates without claiming vendor compatibility.
- [x] Run full pytest, Ruff, mypy, Cedar Ridge validator and frontend lint/typecheck/test/build. Review privacy and remote blob hashes. Commit through the connector onto corrected head `05e2b40a7482cd5ab162c79acec046d2d28b845e`, update existing draft PR #2, and verify hosted CI on the actual new commit. Report any unavailable browser/PostgreSQL QA precisely; hold merge for implementation review.

Transaction semantics follow [SQLAlchemy 2.0 transaction documentation](https://docs.sqlalchemy.org/en/20/orm/session_transaction.html) and [PostgreSQL row-lock documentation](https://www.postgresql.org/docs/current/explicit-locking.html). The global lock is a deliberate correctness-first limit on simultaneous persistent writes, not a claim of concurrent ingestion throughput.

Implementation and validation are recorded in [persistent-validation.md](../../persistent-validation.md); the private draft PR remains the review and merge gate.


## Independent review follow-up

- [x] Reproduce the three P2 findings at `52d7717` with failing regression tests.
- [x] Preserve unknown/repeated Nessus host evidence and bound expanded normalized bundles.
- [x] Browse unnamed assets and search UUID/fallback labels; display IDs in choice labels.
- [x] Share ordered preview/save planning, retained analyst decisions and historical conflicts.
- [x] Bind preview/save to signed context and serialized revision, including legacy identity/import writers.
- [x] Refresh cached current assignments; reject malformed contexts and stale decisions safely.
- [x] Local backend 228 tests, frontend 35 tests, lint/typecheck/build and scale benchmark.
- [x] Push correction and complete hosted PostgreSQL/Chromium/container/restoration checks. Run `36967082817` passed all four jobs, including 17 PostgreSQL regressions, the expanded real browser workflow and all 39 restored table hashes.
- [x] Record corrected behavior and reproduction tests in `docs/persistent-validation.md` for independent rereview; keep draft/unmerged/private. The final handoff includes the exact PR head after the validation-document update and its hosted checks.
