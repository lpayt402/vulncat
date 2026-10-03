# Offline Reconciliation Preview Implementation Plan

> Execute inline using test-driven development. Core owns contracts and matching; bounded UI work may be delegated after the contract is defined.

**Goal:** Testable multi-source offline observation preview without changes to persisted identity or finding lifecycle.

**Architecture:** Separate reconciliation package, immutable observations, streaming row adapters, indexed explainable matcher, bounded multipart endpoint and a mapping-driven UI. Existing imports remain operational.

**Stack:** Python 3.12, Pydantic, existing defusedxml, FastAPI and React/Mantine.

- [x] Add tests in `tests/unit/test_reconciliation.py` for source-scoped IDs, strict times, row accounting, duplicate events and conservative identity decisions; run to confirm missing feature.
- [x] Implement `backend/vulnbatch/reconciliation/{models,adapters,matching,preview}.py`. Keep native status and source instance on every observation; no fallback to import time.
- [x] Add `backend/vulnbatch/api/routes/reconciliation.py` with administrator/CSRF checks, upload/row limits and page slicing; register it in `main.py`. Cover malformed input, authorization, file bounds and pagination in API tests.
- [x] Build a separate preview panel in `frontend/src/components/OfflinePreview.tsx`, linked from Imports, with multiple file options, column mappings and bounded results. Label transient preview and synthetic presets clearly. Test mapping edits and rendering error/review states.
- [x] Add hypothetical offline fixtures and source-provenance documentation. Run a 5,000-asset synthetic benchmark; record exact methodology and measured limits.
- [x] Run existing/new pytest, Ruff, mypy, Cedar Ridge validation and frontend lint/typecheck/tests/build. Review diff and privacy framing, then push an incremental private draft PR through the authorized GitHub connection. Do not merge or change visibility.

## Authorized validation follow-up

- [x] Reproduce missing JSON-path, record-kind, unsupported NetBox namespace, CVE structure and incompatible format-option failures with regression tests.
- [x] Define explicit missing/null/kind/format policy and version the transient parser as offline-v2.
- [x] Align UI format transitions, run full non-Docker checks and independent review, and commit through the authorized repository connector. Local Git metadata writes and Docker access remain prohibited; persistence and merge remain on hold.
