from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from vulnbatch.core.config import get_settings
from vulnbatch.core.security import utcnow
from vulnbatch.db.models import Job


def enqueue_job(
    db: Session,
    *,
    job_type: str,
    payload: dict[str, Any],
    unique_key: str | None = None,
    max_attempts: int = 3,
) -> Job:
    job = Job(
        job_type=job_type,
        payload=payload,
        unique_key=unique_key,
        max_attempts=max_attempts,
    )
    db.add(job)
    db.flush()
    return job


def claim_next_job(db: Session, job_types: tuple[str, ...] | None = None) -> Job | None:
    settings = get_settings()
    now = utcnow()
    conditions = [
        Job.available_at <= now,
        Job.attempts < Job.max_attempts,
        or_(
            Job.status == "queued",
            (Job.status == "running") & (Job.lease_expires_at < now),
        ),
    ]
    if job_types:
        conditions.append(Job.job_type.in_(job_types))
    job = db.scalar(
        select(Job)
        .where(*conditions)
        .order_by(Job.available_at.asc(), Job.requested_at.asc(), Job.id.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if job is None:
        return None
    job.status = "running"
    job.attempts += 1
    job.started_at = job.started_at or now
    job.heartbeat_at = now
    job.lease_token = uuid.uuid4()
    job.lease_expires_at = now + timedelta(seconds=settings.worker_lease_seconds)
    job.error_message = None
    db.flush()
    return job


def heartbeat(db: Session, job: Job, progress: int | None = None) -> None:
    settings = get_settings()
    now = utcnow()
    job.heartbeat_at = now
    job.lease_expires_at = now + timedelta(seconds=settings.worker_lease_seconds)
    if progress is not None:
        job.progress = max(0, min(100, progress))
    db.flush()


def complete_job(db: Session, job: Job) -> None:
    now = utcnow()
    job.status = "completed"
    job.progress = 100
    job.completed_at = now
    job.heartbeat_at = now
    job.lease_token = None
    job.lease_expires_at = None
    db.flush()


def fail_job(db: Session, job: Job, message: str) -> None:
    now = utcnow()
    job.error_message = message[:8000]
    job.heartbeat_at = now
    job.lease_token = None
    job.lease_expires_at = None
    if job.attempts < job.max_attempts:
        job.status = "queued"
        job.available_at = now + timedelta(seconds=min(60, 2**job.attempts))
    else:
        job.status = "failed"
        job.failed_at = now
    db.flush()
