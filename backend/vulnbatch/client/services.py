from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter, ValidationError

from vulnbatch.client.paths import checked_input_root, checked_local_path, lexical_local_path
from vulnbatch.client.transport import ApiClient, ClientError
from vulnbatch.reconciliation.models import SourceOptions
from vulnbatch.schemas.reconciliation import DecisionRequest

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_TOTAL_BYTES = 30 * 1024 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_FILES = 8
SOURCE_NAMES = ("crowdstrike", "pdq_connect", "nessus", "netbox", "active_directory", "inventory")
NODE_KINDS = ("host", "device", "load_balancer", "vip", "service", "endpoint")


def read_bytes(path: Path, maximum: int, *, input_root: Path | None = None) -> bytes:
    try:
        absolute = lexical_local_path(path)
        root = lexical_local_path(input_root) if input_root is not None else None
        # Do this before *any* metadata on either caller-selected path. In
        # particular, a different mapped drive is rejected without touching it.
        if root is not None and not absolute.is_relative_to(root):
            raise ClientError("Input file is outside the configured input root.")
        resolved_root = checked_input_root(root) if root is not None else None
        absolute = checked_local_path(absolute)
        if not absolute.is_file():
            raise ClientError("Input must be a regular local file.")
        if resolved_root is not None and not absolute.resolve(strict=True).is_relative_to(resolved_root):
            raise ClientError("Input file resolves outside the configured input root.")
        with absolute.open("rb") as handle:
            content = handle.read(maximum + 1)
    except ValueError as exc:
        raise ClientError(str(exc)) from exc
    except OSError as exc:
        raise ClientError("Cannot read input file.") from exc
    if not content or len(content) > maximum:
        raise ClientError(f"Input file must contain 1-{maximum} bytes.")
    return content


def read_json(path: Path, *, input_root: Path | None = None) -> Any:
    try:
        return json.loads(read_bytes(path, MAX_JSON_BYTES, input_root=input_root))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ClientError("Input must be valid UTF-8 JSON.") from exc


def page(offset: int, limit: int) -> dict[str, int]:
    if isinstance(offset, bool) or isinstance(limit, bool) or offset < 0 or not 1 <= limit <= 500:
        raise ClientError("Page offset must be nonnegative; limit must be 1-500.")
    return {"offset": offset, "limit": limit}


def identifier(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ClientError("Identifier must be a UUID.") from exc


def revision(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ClientError("An explicit nonnegative expected revision is required.")
    return value


def preview_guards(preview: dict[str, Any]) -> tuple[int, str]:
    if not isinstance(preview, dict):
        raise ClientError("Preview must be a JSON object.")
    expected = revision(preview.get("revision"))
    token = preview.get("preview_token")
    if not isinstance(token, str) or not 1 <= len(token) <= 2048 or "\x00" in token:
        raise ClientError("A signed preview token is required. Run preview first.")
    return expected, token


def text_field(value: str, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise ClientError(f"{name} must contain 1-{maximum} non-NUL characters.")
    return value


def bounded_document(value: Any) -> None:
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ClientError("Document must contain finite, serializable JSON values.") from exc
    if len(encoded) > MAX_JSON_BYTES:
        raise ClientError("JSON documents are limited to 2 MiB.")


class WorkbenchService:
    def __init__(self, client: ApiClient, *, input_root: Path | None = None) -> None:
        self.client = client
        try:
            self.input_root = checked_input_root(input_root) if input_root is not None else None
        except (ValueError, OSError) as exc:
            raise ClientError(
                "MCP input root must be an existing local directory without links or reparse points."
            ) from exc

    def assets(self, q: str = "", offset: int = 0, limit: int = 50) -> dict[str, Any]:
        if len(q) > 255 or "\x00" in q:
            raise ClientError("Asset search is limited to 255 non-NUL characters.")
        return self.client._request(
            "GET", "/api/v1/reconciliation/assets", params={**page(offset, limit), "q": q}
        )

    def observations(
        self,
        review_status: str | None = "open",
        asset_id: str | None = None,
        source: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        params: dict[str, Any] = page(offset, limit)
        if review_status is not None:
            if review_status not in {"open", "deferred", "assigned", "rejected"}:
                raise ClientError("Invalid review status.")
            params["review_status"] = review_status
        if asset_id is not None:
            params["asset_id"] = identifier(asset_id)
        if source is not None:
            if source not in SOURCE_NAMES:
                raise ClientError("Invalid observation source.")
            params["source"] = source
        return self.client._request("GET", "/api/v1/reconciliation/observations", params=params)

    def observation(self, observation_id: str) -> dict[str, Any]:
        return self.client._request(
            "GET", f"/api/v1/reconciliation/observations/{identifier(observation_id)}"
        )

    def decisions(self, offset: int = 0, limit: int = 50) -> dict[str, Any]:
        return self.client._request("GET", "/api/v1/reconciliation/decisions", params=page(offset, limit))

    def decision(self, decision_id: str) -> dict[str, Any]:
        return self.client._request("GET", f"/api/v1/reconciliation/decisions/{identifier(decision_id)}")

    def decide(self, payload: dict[str, Any]) -> dict[str, Any]:
        bounded_document(payload)
        try:
            request = DecisionRequest.model_validate(payload)
        except (ValidationError, ValueError) as exc:
            raise ClientError(
                "Invalid decision document. Include request_key, reason, action, revision and versions."
            ) from exc
        return self.client._request(
            "POST", "/api/v1/reconciliation/decisions", json=request.model_dump(mode="json")
        )

    def _uploads(self, files: list[str], options: list[dict[str, Any]]) -> tuple[list[Any], str]:
        bounded_document(options)
        if not 1 <= len(files) <= MAX_FILES or len(options) != len(files):
            raise ClientError("Provide 1-8 local files and exactly one source configuration per file.")
        try:
            validated = TypeAdapter(list[SourceOptions]).validate_python(options)
        except (ValidationError, ValueError) as exc:
            raise ClientError(
                "Invalid source configuration. Use the documented SourceOptions contract."
            ) from exc
        uploads = []
        total = 0
        for filename in files:
            path = Path(filename)
            content = read_bytes(path, MAX_FILE_BYTES, input_root=self.input_root)
            total += len(content)
            if total > MAX_TOTAL_BYTES:
                raise ClientError("Combined import files must be 30 MiB or smaller.")
            uploads.append(("uploads", (path.name, content, "application/octet-stream")))
        return uploads, json.dumps([option.model_dump(mode="json") for option in validated])

    def columns(self, filename: str, format: str, records_path: str | None = None) -> dict[str, Any]:
        if format not in {"csv", "json", "ndjson"}:
            raise ClientError("Column discovery format must be csv, json, or ndjson.")
        path = Path(filename)
        data = {"format": format}
        if records_path is not None:
            data["records_path"] = text_field(records_path, "Records path", 256)
        return self.client._request(
            "POST",
            "/api/v1/reconciliation/columns",
            data=data,
            files={"upload": (path.name, read_bytes(path, MAX_FILE_BYTES, input_root=self.input_root))},
        )

    def preview(
        self, files: list[str], options: list[dict[str, Any]], offset: int = 0, limit: int = 50
    ) -> dict[str, Any]:
        uploads, options_json = self._uploads(files, options)
        return self.client._request(
            "POST",
            "/api/v1/reconciliation/preview",
            files=uploads,
            data={"options_json": options_json},
            params=page(offset, limit),
        )

    def import_bundle(
        self, files: list[str], options: list[dict[str, Any]], preview: dict[str, Any], request_key: str
    ) -> dict[str, Any]:
        expected, token = preview_guards(preview)
        uploads, options_json = self._uploads(files, options)
        return self.client._request(
            "POST",
            "/api/v1/reconciliation/imports",
            files=uploads,
            data={
                "options_json": options_json,
                "request_key": text_field(request_key, "Request key", 128),
                "expected_revision": str(expected),
                "preview_token": token,
            },
        )

    def exposure_read(
        self,
        kind: str,
        *,
        node_id: str | None = None,
        observation_kind: str | None = None,
        offset: int = 0,
        limit: int = 50,
        relationship_offset: int = 0,
        relationship_limit: int = 100,
    ) -> dict[str, Any]:
        if kind not in {"nodes", "graph", "report", "history"}:
            raise ClientError("Unsupported exposure read operation.")
        params: dict[str, Any] = page(offset, limit)
        if node_id is not None:
            if kind == "nodes":
                raise ClientError(
                    "Use exposure node detail for a node identifier; nodes supports q/kind filters."
                )
            params["node_id"] = identifier(node_id)
        if observation_kind is not None:
            if kind != "report" or observation_kind not in {"inventory", "vulnerability", "coverage"}:
                raise ClientError("Invalid observation kind filter.")
            params["observation_kind"] = observation_kind
        if kind == "graph":
            relationship_page = page(relationship_offset, relationship_limit)
            params.update(
                {
                    "relationship_offset": relationship_page["offset"],
                    "relationship_limit": relationship_page["limit"],
                }
            )
        return self.client._request("GET", f"/api/v1/exposure/{kind}", params=params)

    def exposure_nodes(
        self, q: str = "", kind: str | None = None, offset: int = 0, limit: int = 50
    ) -> dict[str, Any]:
        if len(q) > 255 or "\x00" in q:
            raise ClientError("Node search is limited to 255 non-NUL characters.")
        params: dict[str, Any] = {**page(offset, limit), "q": q}
        if kind is not None:
            if kind not in NODE_KINDS:
                raise ClientError("Invalid node kind.")
            params["kind"] = kind
        return self.client._request("GET", "/api/v1/exposure/nodes", params=params)

    def exposure_node(self, node_id: str, fact_offset: int = 0, fact_limit: int = 50) -> dict[str, Any]:
        fact_page = page(fact_offset, fact_limit)
        return self.client._request(
            "GET",
            f"/api/v1/exposure/nodes/{identifier(node_id)}",
            params={"fact_offset": fact_page["offset"], "fact_limit": fact_page["limit"]},
        )

    def exposure_preview(self, graph: dict[str, Any]) -> dict[str, Any]:
        bounded_document(graph)
        if not isinstance(graph, dict):
            raise ClientError("Graph must be a JSON object.")
        return self.client._request("POST", "/api/v1/exposure/preview", json={"graph": graph})

    def exposure_apply(
        self, graph: dict[str, Any], preview: dict[str, Any], request_key: str, reason: str
    ) -> dict[str, Any]:
        bounded_document(graph)
        expected, token = preview_guards(preview)
        if not isinstance(graph, dict):
            raise ClientError("Graph must be a JSON object.")
        return self.client._request(
            "POST",
            "/api/v1/exposure/apply",
            json={
                "graph": graph,
                "expected_revision": expected,
                "preview_token": token,
                "confirmed": True,
                "request_key": text_field(request_key, "Request key", 128),
                "reason": text_field(reason, "Reason", 2000),
            },
        )

    def exposure_undo(
        self, decision_id: str, expected_revision: int, request_key: str, reason: str
    ) -> dict[str, Any]:
        return self.client._request(
            "POST",
            "/api/v1/exposure/undo",
            json={
                "decision_id": identifier(decision_id),
                "expected_revision": revision(expected_revision),
                "request_key": text_field(request_key, "Request key", 128),
                "reason": text_field(reason, "Reason", 2000),
                "confirmed": True,
            },
        )
