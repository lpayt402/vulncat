from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AssetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    system_owner: str | None = Field(default=None, max_length=255)
    administrative_team: str | None = Field(default=None, max_length=255)
    technical_owner: str | None = Field(default=None, max_length=255)
    environment: str | None = Field(default=None, max_length=128)
    data_center: str | None = Field(default=None, max_length=128)
    business_service: str | None = Field(default=None, max_length=255)
    server_role: str | None = Field(default=None, max_length=255)
    maintenance_group: str | None = Field(default=None, max_length=128)
    patch_group: str | None = Field(default=None, max_length=128)
    notes: str | None = Field(default=None, max_length=20_000)
    tags: list[str] | None = Field(default=None, max_length=100)

    @field_validator(
        "system_owner",
        "administrative_team",
        "technical_owner",
        "environment",
        "data_center",
        "business_service",
        "server_role",
        "maintenance_group",
        "patch_group",
        "notes",
        mode="before",
    )
    @classmethod
    def blank_string_to_none(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return sorted({item.strip() for item in value if item.strip()}, key=str.casefold)
