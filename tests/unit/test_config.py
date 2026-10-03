from __future__ import annotations

import secrets

import pytest
from pydantic import ValidationError

from vulnbatch.core.config import Settings


def test_database_configuration_has_no_embedded_credential_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError) as error:
        Settings(_env_file=None, secret_key=secrets.token_hex(32))
    assert any(item["loc"] == ("database_url",) for item in error.value.errors())


def test_explicit_local_configuration_keeps_new_application_name() -> None:
    settings = Settings(
        _env_file=None,
        database_url="postgresql+psycopg://localhost/workbench",
        secret_key=secrets.token_hex(32),
    )
    assert settings.app_name == "Vulncat"
    assert settings.session_cookie_name == "vulnerability_workbench_session"
