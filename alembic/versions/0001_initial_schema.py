"""Initial Vulnerability Workbench schema.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-07-16
"""

from __future__ import annotations

from alembic import op

from vulnbatch.db.base import Base
from vulnbatch.db import models  # noqa: F401


revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind(), checkfirst=True)
