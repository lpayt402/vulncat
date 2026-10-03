from __future__ import annotations

import asyncio
import importlib.metadata
import json
import os
import secrets
import sys
import textwrap
from datetime import timedelta
from typing import Any

import httpx
import pytest

pytest.importorskip("mcp", reason="Install the optional mcp extra to run protocol tests")

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult

from vulnbatch.client.transport import ApiClient
from vulnbatch.mcp_server import create_server


def test_supported_sdk_release() -> None:
    parts = tuple(int(value) for value in importlib.metadata.version("mcp").split(".")[:2])
    assert parts >= (1, 30) and parts < (2, 0), (
        "Protocol checks must run against the declared optional dependency"
    )


SCRIPT = textwrap.dedent("""
    import secrets
    import httpx
    from pathlib import Path
    from vulnbatch.client.transport import ApiClient
    from vulnbatch.mcp_server import create_server

    def handler(request):
        if request.url.path.endswith('/auth/session'):
            return httpx.Response(401, json={'detail': 'do not reflect raw server detail'})
        if request.url.path.endswith('/exposure/report'):
            return httpx.Response(200, json={'revision': 7, 'total': 1, 'items': [
                {'observation_id': 'fixture', 'observation_kind': 'coverage', 'coverage_outcome': 'failed',
                 'native_status': 'scanner unreachable', 'node_label': 'fixture service', 'age_days': None,
                 'evidence': {'synthetic': True}}]})
        return httpx.Response(200, json={'revision': 7, 'items': []})

    with ApiClient(transport=httpx.MockTransport(handler)) as client:
        client.csrf_token = secrets.token_urlsafe(32)
        create_server(client, input_root=Path.cwd()).run(transport='stdio')
""")


def test_real_stdio_initialize_list_call_structured_errors_and_disabled_mutations() -> None:
    async def exercise() -> None:
        environment = dict(os.environ)
        environment["PYTHONWARNINGS"] = "ignore"
        params = StdioServerParameters(command=sys.executable, args=["-c", SCRIPT], env=environment)
        async with stdio_client(params) as (reader, writer):  # noqa: SIM117 - second context uses returned streams
            async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=15)) as session:
                initialized = await session.initialize()
                assert initialized.serverInfo.name == "Vulncat"
                listed = await session.list_tools()
                tools = {tool.name: tool for tool in listed.tools}
                assert {
                    "assets_list",
                    "reconciliation_preview",
                    "exposure_report",
                    "exposure_apply",
                } <= tools.keys()
                assert tools["exposure_report"].annotations.readOnlyHint is True
                assert tools["exposure_apply"].annotations.readOnlyHint is False
                assert tools["exposure_apply"].inputSchema["additionalProperties"] is False
                assert tools["exposure_report"].outputSchema is not None
                assert "request" not in tools
                report = await session.call_tool("exposure_report", {"format": "csv", "limit": 1})
                assert report.isError is False
                assert report.structuredContent["ok"] is True
                row = report.structuredContent["data"]["items"][0]
                assert row["observation_kind"] == "coverage"
                assert row["native_status"] == "scanner unreachable"
                assert report.structuredContent["formatted"].startswith("observation_id,observation_kind,")
                assert report.content and report.content[0].type == "text"
                auth = await session.call_tool("workbench_status", {})
                assert auth.isError is True
                assert auth.structuredContent["error"]["code"] == 3
                assert "raw server detail" not in str(auth)
                for tool in ("reconciliation_decide", "exposure_apply"):
                    arguments = (
                        {"document": {}, "confirm": True}
                        if tool == "reconciliation_decide"
                        else {
                            "graph": {},
                            "preview": {},
                            "request_key": "fixture",
                            "reason": "fixture",
                            "confirm": True,
                        }
                    )
                    blocked = await session.call_tool(tool, arguments)
                    assert blocked.isError is True
                    assert "disabled" in blocked.structuredContent["error"]["message"]
                sentinel = secrets.token_urlsafe(32)
                for arguments in ({"limit": 501}, {"limit": "50"}, {"limit": True}, {"password": sentinel}):
                    invalid = await session.call_tool("assets_list", arguments)
                    assert invalid.isError is True
                    assert invalid.structuredContent["error"]["code"] == 2
                    assert sentinel not in str(invalid)
                missing = await session.call_tool("nonexistent_tool", {})
                assert missing.isError is True
                assert missing.structuredContent["error"]["code"] == 2

    asyncio.run(exercise())


def test_enabled_write_still_requires_strict_per_call_confirm_and_signed_preview() -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={"revision": 2, "decision_id": "fixture", "replayed": False})

    async def exercise() -> None:
        with ApiClient(transport=httpx.MockTransport(handler)) as client:
            client.csrf_token = secrets.token_urlsafe(32)
            server = create_server(client, enable_writes=True)
            arguments: dict[str, Any] = {
                "graph": {},
                "preview": {"revision": 1, "preview_token": "signed-fixture"},
                "request_key": "fixture",
                "reason": "Synthetic test",
            }
            for confirm in (False, "true", 1):
                blocked = await server.call_tool("exposure_apply", {**arguments, "confirm": confirm})
                assert isinstance(blocked, CallToolResult) and blocked.isError is True
            assert sent == []
            no_token = await server.call_tool(
                "exposure_apply", {**arguments, "preview": {"revision": 1}, "confirm": True}
            )
            assert isinstance(no_token, CallToolResult) and no_token.isError is True
            assert sent == []
            applied = await server.call_tool("exposure_apply", {**arguments, "confirm": True})
            # SDK high-level calls return text/structured tuple before the protocol layer wraps it.
            assert isinstance(applied, tuple)
            assert applied[1]["ok"] is True
            body = json.loads(sent[0].content)
            assert body["expected_revision"] == 1
            assert body["preview_token"] == arguments["preview"]["preview_token"]
            assert body["confirmed"] is True
            assert sent[0].url.path == "/api/v1/exposure/apply"
            assert "X-CSRF-Token" in sent[0].headers

    asyncio.run(exercise())


def test_unauthenticated_and_conflict_tools_have_structured_errors() -> None:
    async def exercise() -> None:
        with ApiClient() as client:
            result = await create_server(client).call_tool("assets_list", {})
            assert isinstance(result, CallToolResult)
            assert result.structuredContent["error"]["code"] == 3
        with ApiClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(409, json={"detail": "stale"}))
        ) as client:
            client.csrf_token = secrets.token_urlsafe(32)
            result = await create_server(client).call_tool("exposure_preview", {"graph": {}})
            assert isinstance(result, CallToolResult)
            assert result.structuredContent["error"]["code"] == 4

    asyncio.run(exercise())
