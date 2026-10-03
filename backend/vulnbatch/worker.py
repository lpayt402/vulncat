from __future__ import annotations

import logging
import signal
import time
from collections.abc import Callable

from sqlalchemy.orm import Session

from vulnbatch.core.config import get_settings
from vulnbatch.core.security import utcnow
from vulnbatch.db.models import ImportRun, Job
from vulnbatch.db.session import SessionLocal
from vulnbatch.jobs.service import claim_next_job, complete_job, fail_job
from vulnbatch.maintenance.service import run_retention_cleanup

logger = logging.getLogger("vulnerability_workbench.worker")
running = True


def _stop(_: int, __: object) -> None:
    global running
    running = False


def _import_handler(db: Session, job: Job) -> None:
    from vulnbatch.imports.processor import process_import_job

    process_import_job(db, job)


def _export_handler(db: Session, job: Job) -> None:
    from vulnbatch.exports.generator import process_export_job

    process_export_job(db, job)


HANDLERS: dict[str, Callable[[Session, Job], None]] = {
    "import": _import_handler,
    "export": _export_handler,
}


def run() -> None:
    settings = get_settings()
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    logger.info("Worker started")
    last_cleanup = 0.0
    while running:
        with SessionLocal.begin() as db:
            job = claim_next_job(db, tuple(HANDLERS))
            job_id = job.id if job else None
        if job_id is None:
            if time.monotonic() - last_cleanup >= 60:
                try:
                    with SessionLocal.begin() as db:
                        result = run_retention_cleanup(db)
                    if any(result.values()):
                        logger.info("Retention cleanup result=%s", result)
                except Exception:
                    logger.exception("Retention cleanup failed")
                last_cleanup = time.monotonic()
            time.sleep(settings.worker_poll_seconds)
            continue

        job_type = "unknown"
        job_payload: dict[str, object] = {}
        try:
            with SessionLocal.begin() as db:
                job = db.get(Job, job_id, with_for_update=True)
                if job is None or job.status != "running":
                    continue
                job_type = job.job_type
                job_payload = dict(job.payload)
                handler = HANDLERS.get(job.job_type)
                if handler is None:
                    fail_job(db, job, f"Unsupported job type: {job.job_type}")
                    continue
                handler(db, job)
                complete_job(db, job)
        except Exception as exc:
            logger.exception("Job failed id=%s type=%s", job_id, job_type)
            with SessionLocal.begin() as db:
                failed_job = db.get(Job, job_id, with_for_update=True)
                if failed_job is None:
                    continue
                if job_type == "import":
                    import_id = job_payload.get("import_id")
                    import_run = db.get(ImportRun, import_id) if import_id else None
                    if import_run is not None:
                        import_run.status = "failed"
                        import_run.failed_at = utcnow()
                        import_run.failure_reason = str(exc)[:8000]
                fail_job(db, failed_job, str(exc))
    logger.info("Worker stopped")


def main() -> None:
    logging.basicConfig(
        level=getattr(logging, get_settings().log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    run()
