from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from vulnbatch.core.config import get_settings

_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65_536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)
_username_pattern = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


@dataclass(frozen=True)
class PasswordValidation:
    valid: bool
    errors: tuple[str, ...]


def utcnow() -> datetime:
    return datetime.now(UTC)


def normalize_username(value: str) -> str:
    return value.strip().lower()


def validate_username(value: str) -> bool:
    return bool(_username_pattern.fullmatch(normalize_username(value)))


def validate_password(password: str, username: str | None = None) -> PasswordValidation:
    errors: list[str] = []
    if len(password) < 14:
        errors.append("Password must contain at least 14 characters.")
    if len(password) > 256:
        errors.append("Password must contain no more than 256 characters.")
    if username and normalize_username(username) in password.lower():
        errors.append("Password must not contain the username.")
    if password.strip() != password:
        errors.append("Password must not begin or end with whitespace.")
    return PasswordValidation(valid=not errors, errors=tuple(errors))


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password_hash: str, candidate: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, candidate)
    except (VerifyMismatchError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return _password_hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def generate_token(byte_length: int = 32) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(byte_length)).rstrip(b"=").decode("ascii")


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def csrf_token_for_session(session_token: str) -> str:
    settings = get_settings()
    digest = hmac.new(
        settings.secret_key.encode("utf-8"),
        f"csrf:{session_token}".encode(),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
