from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Mapping
from typing import Final, Literal

IdentifierType = Literal[
    "tenable_asset_uuid",
    "agent_uuid",
    "nessus_host_id",
    "hardware_uuid",
    "mac_address",
    "fqdn",
    "short_hostname",
    "ipv4",
    "ipv6",
    "user_alias",
]

IDENTIFIER_TYPES: Final[tuple[IdentifierType, ...]] = (
    "tenable_asset_uuid",
    "agent_uuid",
    "nessus_host_id",
    "hardware_uuid",
    "mac_address",
    "fqdn",
    "short_hostname",
    "ipv4",
    "ipv6",
    "user_alias",
)

_PLACEHOLDERS: Final[frozenset[str]] = frozenset(
    {
        "",
        "-",
        "--",
        "n/a",
        "na",
        "none",
        "null",
        "not available",
        "not set",
        "unknown",
        "(none)",
        "(null)",
    }
)
_HOSTNAME_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$", re.IGNORECASE)
_MAC_HEX = re.compile(r"^[0-9a-f]{12}$")
_UUID_TYPES: Final[frozenset[str]] = frozenset({"tenable_asset_uuid", "agent_uuid", "hardware_uuid"})


def clean_text(value: object) -> str | None:
    if value is None:
        return None
    text = value.decode("utf-8", errors="replace").strip() if isinstance(value, bytes) else str(value).strip()
    if text.casefold() in _PLACEHOLDERS:
        return None
    return text or None


def normalize_hostname(value: object) -> str | None:
    text = clean_text(value)
    if text is None:
        return None
    normalized = text.rstrip(".").casefold()
    if not normalized or len(normalized) > 253:
        return None
    labels = normalized.split(".")
    if any(not label or not _HOSTNAME_LABEL.fullmatch(label) for label in labels):
        return None
    return normalized


def normalize_ip(value: object, *, version: Literal[4, 6] | None = None) -> str | None:
    text = clean_text(value)
    if text is None:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.is_unspecified:
        return None
    if version is not None and address.version != version:
        return None
    return address.compressed


def normalize_mac(value: object) -> str | None:
    text = clean_text(value)
    if text is None:
        return None
    compact = re.sub(r"[^0-9a-fA-F]", "", text).casefold()
    if not _MAC_HEX.fullmatch(compact) or compact == "000000000000":
        return None
    return ":".join(compact[offset : offset + 2] for offset in range(0, 12, 2))


def normalize_uuid(value: object) -> str | None:
    text = clean_text(value)
    if text is None:
        return None
    try:
        return str(uuid.UUID(text))
    except ValueError:
        return None


def normalize_identifier(identifier_type: str, value: object) -> str | None:
    if identifier_type not in IDENTIFIER_TYPES:
        raise ValueError(f"Unsupported identifier type: {identifier_type}")
    if identifier_type in _UUID_TYPES:
        return normalize_uuid(value)
    if identifier_type == "mac_address":
        return normalize_mac(value)
    if identifier_type == "ipv4":
        return normalize_ip(value, version=4)
    if identifier_type == "ipv6":
        return normalize_ip(value, version=6)
    if identifier_type in {"fqdn", "short_hostname", "user_alias"}:
        return normalize_hostname(value)
    text = clean_text(value)
    return text.casefold() if text is not None else None


def infer_host_identifier(value: object) -> Mapping[str, str]:
    text = clean_text(value)
    if text is None:
        return {}
    address = normalize_ip(text)
    if address is not None:
        kind = "ipv4" if ipaddress.ip_address(address).version == 4 else "ipv6"
        return {kind: address}
    hostname = normalize_hostname(text)
    if hostname is None:
        return {}
    return {"fqdn": hostname} if "." in hostname else {"short_hostname": hostname}
