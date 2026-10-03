from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    request_key: str = Field(min_length=1, max_length=128)
    expected_revision: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=2000)
    action: Literal["assign", "create", "reject", "defer", "merge", "split", "undo"]
    observation_ids: list[uuid.UUID] = Field(default_factory=list, max_length=5000)
    expected_versions: dict[str, int] = Field(default_factory=dict)
    source_asset_id: uuid.UUID | None = None
    target_asset_id: uuid.UUID | None = None
    undo_decision_id: uuid.UUID | None = None

    @field_validator("request_key", "reason")
    @classmethod
    def sql_text(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("NUL characters are not supported")
        return value
