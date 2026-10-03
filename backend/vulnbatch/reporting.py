"""Deterministic report rendering shared by HTTP exports, CLI, and MCP."""

from __future__ import annotations

import csv
import html
import json
from collections.abc import Sequence
from io import StringIO
from typing import Any

REPORT_COLUMNS = (
    "observation_id",
    "observation_kind",
    "vulnerability_id",
    "native_status",
    "coverage_outcome",
    "source",
    "instance",
    "observed_at",
    "imported_at",
    "age_days",
    "time_warning",
    "time_meaning",
    "asset_id",
    "asset_name",
    "node_id",
    "node_kind",
    "node_label",
    "service_id",
    "service_label",
    "network_scope",
    "protocol",
    "port",
    "dns_name",
    "sni",
    "attribution_id",
    "attribution_version",
    "attribution_status",
    "attribution_reason",
    "evidence",
)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, bool)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)


def _visible(value: str) -> str:
    return "".join(
        f"\\u{ord(character):04x}" if ord(character) < 32 and character not in "\n\r\t" else character
        for character in value
    )


def render_payload(
    payload: dict[str, Any] | list[Any], format: str, columns: Sequence[str] | None = None
) -> str:
    """JSON keeps metadata; tabular formats use items with stable columns and safe cells.

    CSV neutralizes formula-looking strings with a leading apostrophe. Numeric cells
    retain their numeric text. Nested cells use compact, sorted-key JSON.
    """
    if format == "json":
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if format not in {"csv", "markdown"}:
        raise ValueError("Format must be json, csv, or markdown.")
    source = payload.get("items", [payload]) if isinstance(payload, dict) else payload
    rows = source if isinstance(source, list) else [source]
    normalized = [row if isinstance(row, dict) else {"value": row} for row in rows]
    names = list(columns) if columns is not None else sorted({key for row in normalized for key in row})
    if format == "csv":
        target = StringIO(newline="")
        writer = csv.writer(target, lineterminator="\n")
        writer.writerow(names)
        for row in normalized:
            values = []
            for name in names:
                raw = row.get(name)
                value = _visible(_cell(raw))
                if isinstance(raw, str) and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
                    value = "'" + value
                values.append(value)
            writer.writerow(values)
        return target.getvalue()

    def markdown_cell(value: Any) -> str:
        return (
            html.escape(_visible(_cell(value)), quote=False)
            .replace("\\", "\\\\")
            .replace("|", "\\|")
            .replace("\r\n", "<br>")
            .replace("\n", "<br>")
            .replace("\r", "<br>")
        )

    if not names:
        return "No rows.\n"
    lines = [
        "| " + " | ".join(markdown_cell(name) for name in names) + " |",
        "| " + " | ".join("---" for _ in names) + " |",
    ]
    lines.extend(
        "| " + " | ".join(markdown_cell(row.get(name)) for name in names) + " |" for row in normalized
    )
    return "\n".join(lines) + "\n"
