from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "Vulncat"
    app_version: str = "0.1.0"
    environment: str = "development"
    log_level: str = "INFO"
    database_url: str = Field(min_length=1)
    public_url: str = "http://localhost:8787"
    secret_key: str = Field(min_length=32)
    session_cookie_name: str = "vulnerability_workbench_session"
    session_timeout_minutes: int = Field(default=480, ge=15, le=10_080)
    secure_cookies: bool = False
    upload_dir: Path = Path("/data/uploads")
    report_dir: Path = Path("/data/reports")
    max_upload_bytes: int = Field(default=536_870_912, ge=1_048_576)
    tracked_severities: Annotated[tuple[str, ...], NoDecode] = ("medium", "low")
    ip_association_staleness_days: int = Field(default=90, ge=1, le=3650)
    identity_auto_match_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    maturity_gate_days: int = Field(default=30, ge=0, le=3650)
    medium_sla_days: int = Field(default=60, ge=1, le=3650)
    low_sla_days: int = Field(default=90, ge=1, le=3650)
    allow_finding_date_maturity_fallback: bool = False
    large_export_finding_threshold: int = Field(default=10_000, ge=1)
    export_retention_days: int = Field(default=30, ge=1, le=3650)
    upload_retention_days: int | None = Field(default=None, ge=1)
    import_evidence_retention_days: int | None = Field(default=None, ge=1)
    audit_retention_days: int | None = Field(default=None, ge=1)
    worker_poll_seconds: float = Field(default=1.0, ge=0.1, le=60.0)
    worker_lease_seconds: int = Field(default=300, ge=30, le=3600)
    login_max_attempts: int = Field(default=5, ge=2, le=50)
    login_window_minutes: int = Field(default=15, ge=1, le=1440)
    static_dir: Path = Path("/app/static")

    @field_validator("tracked_severities", mode="before")
    @classmethod
    def parse_tracked_severities(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(part.strip().lower() for part in value.split(",") if part.strip())
        return value

    @field_validator(
        "upload_retention_days",
        "import_evidence_retention_days",
        "audit_retention_days",
        mode="before",
    )
    @classmethod
    def parse_optional_retention_days(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
