from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field


class SetupStatusResponse(BaseModel):
    setup_required: bool


class SetupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=14, max_length=256)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class UserSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    display_name: str
    role: str


class SessionResponse(BaseModel):
    authenticated: bool = True
    user: UserSummary
    csrf_token: str


class MessageResponse(BaseModel):
    message: str
