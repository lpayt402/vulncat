"""Authenticated, bounded HTTP client shared by the CLI and stdio MCP adapter."""

from vulnbatch.client.transport import ApiClient, ClientError

__all__ = ["ApiClient", "ClientError"]
