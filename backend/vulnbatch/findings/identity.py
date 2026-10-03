from __future__ import annotations

from dataclasses import dataclass

from vulnbatch.identity.normalization import clean_text


@dataclass(frozen=True, slots=True)
class FindingKey:
    asset_id: str
    scanner_source: str
    plugin_id: str
    port: int
    protocol: str


def normalize_finding_key(
    *,
    asset_id: object,
    scanner_source: object,
    plugin_id: object,
    port: object = None,
    protocol: object = None,
) -> FindingKey:
    asset = clean_text(asset_id)
    scanner = clean_text(scanner_source)
    plugin = clean_text(plugin_id)
    if asset is None:
        raise ValueError("asset_id is required")
    if scanner is None:
        raise ValueError("scanner_source is required")
    if plugin is None:
        raise ValueError("plugin_id is required")
    return FindingKey(
        asset_id=asset,
        scanner_source=scanner.casefold(),
        plugin_id=plugin,
        port=normalize_port(port),
        protocol=normalize_protocol(protocol),
    )


def normalize_port(value: object) -> int:
    text = clean_text(value)
    if text is None:
        return 0
    try:
        port = int(float(text))
    except ValueError as exc:
        raise ValueError(f"Invalid port: {text}") from exc
    if not 0 <= port <= 65_535:
        raise ValueError("port must be between 0 and 65535")
    return port


def normalize_protocol(value: object) -> str:
    text = clean_text(value)
    if text is None:
        return "general"
    normalized = text.casefold()
    if normalized in {"0", "none", "n/a", "na", "general", "unknown"}:
        return "general"
    return normalized
