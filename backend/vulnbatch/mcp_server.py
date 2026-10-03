"""Harness-neutral stdio MCP adapter; it never opens a listening socket."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from vulnbatch.client.paths import checked_input_root
from vulnbatch.client.services import WorkbenchService
from vulnbatch.client.transport import DEFAULT_API_URL, ApiClient, ClientError
from vulnbatch.reporting import REPORT_COLUMNS, render_payload

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

Offset = Annotated[int, Field(strict=True, ge=0)]
Limit = Annotated[int, Field(strict=True, ge=1, le=500)]
Confirm = Annotated[bool, Field(strict=True)]
Files = Annotated[list[str], Field(min_length=1, max_length=8)]
Format = Literal["json", "csv", "markdown"]


class ToolResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ok: bool
    data: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    formatted: str | None = None


def _error(message: str, code: int) -> Any:
    from mcp.types import CallToolResult, TextContent

    payload = ToolResponse(ok=False, error={"code": code, "message": message}).model_dump(mode="json")
    return CallToolResult(
        isError=True,
        structuredContent=payload,
        content=[TextContent(type="text", text=render_payload(payload, "json"))],
    )


def create_server(
    client: ApiClient, *, enable_writes: bool = False, input_root: Path | None = None
) -> FastMCP:
    try:
        from mcp.server.fastmcp import FastMCP
        from mcp.server.fastmcp.exceptions import ToolError
        from mcp.types import ToolAnnotations
    except ImportError as exc:
        raise ClientError("MCP is optional. Install vulnerability-workbench[mcp] to use stdio MCP.") from exc

    class SafeFastMCP(FastMCP[Any]):
        async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
            # SDK validation errors can contain raw arguments. Keep protocol errors
            # useful without reflecting arbitrary secrets supplied by a caller.
            try:
                return await super().call_tool(name, arguments)
            except ToolError:
                return _error(
                    "Unknown tool or invalid tool parameters. Check the advertised input schema.", 2
                )

    server = SafeFastMCP(
        "Vulncat",
        log_level="CRITICAL",
        instructions=(
            "Vulnerability Concatenator. Use existing Vulncat sessions. Read tools return bounded pages. "
            "Preview tools are transient. "
            "Persistent changes require startup --enable-writes AND per-call confirm=true, "
            "plus the API's signed previews, revisions, versions, permissions, and idempotency keys."
        ),
    )
    service = WorkbenchService(client, input_root=input_root or Path.cwd())
    read = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)
    write = ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False
    )

    def result(
        operation: Callable[[], dict[str, Any]],
        format: Format | None = None,
        columns: tuple[str, ...] | None = None,
    ) -> ToolResponse:
        try:
            data = operation()
            return ToolResponse(
                ok=True, data=data, formatted=render_payload(data, format, columns) if format else None
            )
        except ClientError as exc:
            return cast(ToolResponse, _error(str(exc), exc.code))
        except (ValueError, OSError, TypeError, RecursionError):
            return cast(ToolResponse, _error("Invalid or inaccessible local input.", 2))

    def mutation(confirm: bool, operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        if not enable_writes:
            raise ClientError(
                "MCP persistent writes are disabled. Restart with --enable-writes to authorize them."
            )
        if confirm is not True:
            raise ClientError("This mutation requires explicit confirm=true.")
        return operation()

    @server.tool(annotations=read)
    def workbench_status() -> ToolResponse:
        """Inspect the authenticated user's session without exposing cookies or CSRF tokens."""
        return result(client.status)

    @server.tool(annotations=read)
    def workbench_discover() -> ToolResponse:
        """Show adapter bounds, supported formats, and persistent-write policy."""
        return result(
            lambda: {
                "api_origin": client.origin,
                "writes_enabled": enable_writes,
                "mutations_require_confirm": True,
                "page_limit": 500,
                "max_files": 8,
                "max_file_bytes": 10 * 1024 * 1024,
                "max_total_file_bytes": 30 * 1024 * 1024,
                "formats": ["json", "csv", "markdown"],
            }
        )

    @server.tool(annotations=read)
    def assets_list(
        q: str = "", offset: Offset = 0, limit: Limit = 50, format: Format | None = None
    ) -> ToolResponse:
        """Search canonical assets using the same inventory query as the GUI."""
        return result(lambda: service.assets(q, offset, limit), format)

    @server.tool(annotations=read)
    def reconciliation_review(
        review_status: Literal["open", "deferred", "assigned", "rejected"] | None = "open",
        asset_id: str | None = None,
        source: str | None = None,
        offset: Offset = 0,
        limit: Limit = 50,
        format: Format | None = None,
    ) -> ToolResponse:
        """Read source observations and assignment versions for identity review."""
        return result(lambda: service.observations(review_status, asset_id, source, offset, limit), format)

    @server.tool(annotations=read)
    def reconciliation_observation(observation_id: str) -> ToolResponse:
        """Read one observation, its evidence locators and assignment history."""
        return result(lambda: service.observation(observation_id))

    @server.tool(annotations=read)
    def reconciliation_decisions(
        offset: Offset = 0, limit: Limit = 50, format: Format | None = None
    ) -> ToolResponse:
        """Read reconciliation decisions and their undo availability."""
        return result(lambda: service.decisions(offset, limit), format)

    @server.tool(annotations=read)
    def reconciliation_decision(decision_id: str) -> ToolResponse:
        """Read an immutable decision's before/after changes."""
        return result(lambda: service.decision(decision_id))

    @server.tool(annotations=read)
    def reconciliation_columns(
        filename: str, input_format: Literal["csv", "json", "ndjson"], records_path: str | None = None
    ) -> ToolResponse:
        """Discover columns in a local file under the configured input root, without importing."""
        return result(lambda: service.columns(filename, input_format, records_path))

    @server.tool(annotations=read)
    def reconciliation_preview(
        files: Files, options: list[dict[str, Any]], offset: Offset = 0, limit: Limit = 50
    ) -> ToolResponse:
        """Preview 1-8 local exports and return a signed token/revision for a later import."""
        return result(lambda: service.preview(files, options, offset, limit))

    @server.tool(annotations=write)
    def reconciliation_import(
        files: Files,
        options: list[dict[str, Any]],
        preview: dict[str, Any],
        request_key: str,
        confirm: Confirm = False,
    ) -> ToolResponse:
        """Persist the exact reviewed exports using signed preview, revision and idempotency guards."""
        return result(
            lambda: mutation(confirm, lambda: service.import_bundle(files, options, preview, request_key))
        )

    @server.tool(annotations=write)
    def reconciliation_decide(document: dict[str, Any], confirm: Confirm = False) -> ToolResponse:
        """Apply assign/create/reject/defer/merge/split/undo using an existing guarded DecisionRequest."""
        return result(lambda: mutation(confirm, lambda: service.decide(document)))

    @server.tool(annotations=read)
    def exposure_nodes(
        q: str = "",
        kind: Literal["host", "device", "load_balancer", "vip", "service", "endpoint"] | None = None,
        offset: Offset = 0,
        limit: Limit = 50,
        format: Format | None = None,
    ) -> ToolResponse:
        """Read endpoint/service nodes with scoped identities and provenance."""
        return result(lambda: service.exposure_nodes(q, kind, offset, limit), format)

    @server.tool(annotations=read)
    def exposure_node(node_id: str, fact_offset: Offset = 0, fact_limit: Limit = 50) -> ToolResponse:
        """Read one exposure node with a bounded page of historical source facts."""
        return result(lambda: service.exposure_node(node_id, fact_offset, fact_limit))

    @server.tool(annotations=read)
    def exposure_graph(
        node_id: str | None = None,
        offset: Offset = 0,
        limit: Limit = 50,
        relationship_offset: Offset = 0,
        relationship_limit: Limit = 100,
    ) -> ToolResponse:
        """Read a bounded exposure graph page with separate relationship metadata."""
        return result(
            lambda: service.exposure_read(
                "graph",
                node_id=node_id,
                offset=offset,
                limit=limit,
                relationship_offset=relationship_offset,
                relationship_limit=relationship_limit,
            )
        )

    @server.tool(annotations=read)
    def exposure_report(
        node_id: str | None = None,
        observation_kind: Literal["inventory", "vulnerability", "coverage"] | None = None,
        offset: Offset = 0,
        limit: Limit = 50,
        format: Format | None = None,
    ) -> ToolResponse:
        """Read report rows keeping inventory, vulnerabilities and scan coverage distinct."""
        return result(
            lambda: service.exposure_read(
                "report", node_id=node_id, observation_kind=observation_kind, offset=offset, limit=limit
            ),
            format,
            REPORT_COLUMNS,
        )

    @server.tool(annotations=read)
    def exposure_history(
        node_id: str | None = None, offset: Offset = 0, limit: Limit = 50, format: Format | None = None
    ) -> ToolResponse:
        """Read immutable exposure changes and decisions."""
        return result(
            lambda: service.exposure_read("history", node_id=node_id, offset=offset, limit=limit), format
        )

    @server.tool(annotations=read)
    def exposure_preview(graph: dict[str, Any]) -> ToolResponse:
        """Validate a GraphEnvelope and preview its changes without persisting them."""
        return result(lambda: service.exposure_preview(graph))

    @server.tool(annotations=write)
    def exposure_apply(
        graph: dict[str, Any],
        preview: dict[str, Any],
        request_key: str,
        reason: str,
        confirm: Confirm = False,
    ) -> ToolResponse:
        """Persist a reviewed graph with signed preview, revision, audit reason and idempotency key."""
        return result(
            lambda: mutation(confirm, lambda: service.exposure_apply(graph, preview, request_key, reason))
        )

    @server.tool(annotations=write)
    def exposure_undo(
        decision_id: str,
        expected_revision: Annotated[int, Field(strict=True, ge=0)],
        request_key: str,
        reason: str,
        confirm: Confirm = False,
    ) -> ToolResponse:
        """Undo one exposure decision with revision checks and an audited reason."""
        return result(
            lambda: mutation(
                confirm, lambda: service.exposure_undo(decision_id, expected_revision, request_key, reason)
            )
        )

    # FastMCP's default function argument models ignore unknown fields. Advertise
    # and enforce a closed schema to prevent silently accepting misspelled guards.
    for tool in server._tool_manager.list_tools():
        model = tool.fn_metadata.arg_model
        model.model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")
        model.model_rebuild(force=True)
        tool.parameters = model.model_json_schema()
    return server


def serve(
    *,
    api_url: str = DEFAULT_API_URL,
    session_file: Path | None = None,
    timeout: float = 30,
    enable_writes: bool = False,
    input_root: Path | None = None,
) -> None:
    try:
        root = checked_input_root(input_root or Path.cwd())
    except (ValueError, OSError) as exc:
        raise ClientError(
            "MCP input root must be an existing local directory without links or reparse points."
        ) from exc
    with ApiClient(api_url, session_file=session_file, timeout=timeout) as client:
        create_server(client, enable_writes=enable_writes, input_root=root).run(transport="stdio")


def main() -> None:
    parser = argparse.ArgumentParser(description="Vulncat MCP adapter (stdio only).")
    parser.add_argument("--api-url", default=DEFAULT_API_URL)
    parser.add_argument("--session-file", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--enable-writes", action="store_true")
    parser.add_argument("--input-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        serve(
            api_url=args.api_url,
            session_file=args.session_file,
            timeout=args.timeout,
            enable_writes=args.enable_writes,
            input_root=args.input_root,
        )
    except (ClientError, ValueError, OSError) as exc:
        import sys

        message = str(exc) if isinstance(exc, ClientError) else "Cannot start the stdio MCP adapter."
        print(message, file=sys.stderr)
        raise SystemExit(exc.code if isinstance(exc, ClientError) else 2) from None


if __name__ == "__main__":
    main()
