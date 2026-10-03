from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictIdentityModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IdentityReviewResolution(StrictIdentityModel):
    action: Literal["match_existing", "create_asset", "mark_shared", "reject", "defer"]
    asset_id: uuid.UUID | None = None
    reason: str = Field(min_length=3, max_length=2000)


class MergeRequest(StrictIdentityModel):
    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    reason: str = Field(min_length=3, max_length=2000)


class MoveIdentifierRequest(StrictIdentityModel):
    target_asset_id: uuid.UUID
    reason: str = Field(min_length=3, max_length=2000)


class SplitIdentifierRequest(StrictIdentityModel):
    canonical_hostname: str | None = Field(default=None, max_length=255)
    reason: str = Field(min_length=3, max_length=2000)


class PinNameRequest(StrictIdentityModel):
    canonical_hostname: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=3, max_length=2000)


class IdentityReason(StrictIdentityModel):
    reason: str = Field(min_length=3, max_length=2000)
