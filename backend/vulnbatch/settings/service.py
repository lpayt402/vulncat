from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnbatch.db.models import ApplicationSetting


def effective_setting(db: Session, key: str, default: Any) -> Any:
    setting = db.scalar(select(ApplicationSetting).where(ApplicationSetting.key == key))
    if setting is None:
        return default
    value = setting.value
    if isinstance(default, tuple):
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return tuple(value)
        return default
    if default is None:
        return value if value is None or isinstance(value, int) else default
    if isinstance(default, bool):
        return value if isinstance(value, bool) else default
    if isinstance(default, int):
        return value if isinstance(value, int) and not isinstance(value, bool) else default
    if isinstance(default, float):
        return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else default
    return value if isinstance(value, type(default)) else default
