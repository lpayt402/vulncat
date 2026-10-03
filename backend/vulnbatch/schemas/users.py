from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictUserModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UserCreate(StrictUserModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=14, max_length=256)
    role: Literal["administrator", "read_only"] = "read_only"


class UserUpdate(StrictUserModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    role: Literal["administrator", "read_only"] | None = None
    is_active: bool | None = None


class PasswordReset(StrictUserModel):
    password: str = Field(min_length=14, max_length=256)


class ManagedUserResponse(StrictUserModel):
    id: uuid.UUID
    username: str
    display_name: str
    role: str
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime
