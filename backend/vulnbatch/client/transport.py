from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import SecretStr

from vulnbatch.client.paths import lexical_local_path
from vulnbatch.client.session import SessionData, delete_session, load_session, save_session

DEFAULT_API_URL = "http://127.0.0.1:8787"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class ClientError(Exception):
    def __init__(self, message: str, code: int = 2) -> None:
        super().__init__(message)
        self.code = code


def validate_origin(value: str) -> str:
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError as exc:
        raise ClientError("Invalid API origin.") from exc
    if (
        url.scheme not in {"http", "https"}
        or not url.hostname
        or url.username is not None
        or url.password is not None
        or url.path not in {"", "/"}
        or url.query
        or url.fragment
        or "\\" in value
        or any(character.isspace() for character in value)
    ):
        raise ClientError("API URL must be an http(s) origin without credentials, path, query, or fragment.")
    hostname = url.hostname.lower()
    try:
        loopback = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        loopback = hostname == "localhost"
    if url.scheme == "http" and not loopback:
        raise ClientError("Non-loopback API origins require HTTPS.")
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 80 if url.scheme == "http" else 443
    return f"{url.scheme}://{host}" + (f":{port}" if port and port != default_port else "")


class ApiClient:
    """One fixed origin, no redirects/proxy discovery, bounded responses, existing session auth."""

    def __init__(
        self,
        api_url: str = DEFAULT_API_URL,
        *,
        session_file: Path | None = None,
        timeout: float = 30,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.origin = validate_origin(api_url)
        if not 1 <= timeout <= 120:
            raise ClientError("Timeout must be between 1 and 120 seconds.")
        try:
            self.session_file = lexical_local_path(session_file) if session_file is not None else None
        except ValueError as exc:
            raise ClientError(str(exc)) from exc
        self.csrf_token: str | None = None
        self.http = httpx.Client(
            base_url=self.origin,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            headers={"User-Agent": "vulncat-cli/0.1"},
        )

    def __enter__(self) -> ApiClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self.http.close()

    def authenticate(self) -> None:
        if self.csrf_token is not None:
            return
        if self.session_file is None:
            raise ClientError("Authentication requires an explicit --session-file.", 3)
        try:
            session = load_session(self.session_file, self.origin)
        except (ValueError, OSError) as exc:
            raise ClientError(
                str(exc) if isinstance(exc, ValueError) else "Cannot read session file.", 3
            ) from exc
        self.csrf_token = session.csrf_token.get_secret_value()
        # A fixed Cookie header avoids domain/path ambiguity; requests never leave this origin.
        self.http.headers["Cookie"] = f"{session.cookie_name}={session.cookie_value.get_secret_value()}"

    def _request(
        self, method: str, path: str, *, authenticated: bool = True, **kwargs: Any
    ) -> dict[str, Any]:
        if not path.startswith("/api/v1/") or ".." in path or "?" in path or "#" in path:
            raise ClientError("Unsupported API route.")
        if authenticated:
            self.authenticate()
        headers = {"X-CSRF-Token": self.csrf_token} if self.csrf_token and method != "GET" else {}
        try:
            with self.http.stream(method, path, headers=headers, **kwargs) as response:
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > MAX_RESPONSE_BYTES:
                        raise ClientError(
                            "API response exceeds the 8 MiB output bound. Request a smaller page.", 5
                        )
                code = response.status_code
        except httpx.HTTPError as exc:
            raise ClientError(
                "API transport failed. Check the configured origin, certificate, and timeout.", 5
            ) from exc
        if code in {401, 403, 429}:
            message = (
                "Authentication or permission denied." if code != 429 else "Login/API request throttled."
            )
            raise ClientError(message, 3)
        if code == 409:
            raise ClientError(
                "API conflict. Refresh the preview/revision and review the current versions.", 4
            )
        if code in {400, 404, 413, 422}:
            raise ClientError(
                f"API rejected the request (HTTP {code}). Check the document, identifiers, and bounds."
            )
        if not 200 <= code < 300:
            raise ClientError(f"API request failed (HTTP {code}).", 5)
        try:
            result = json.loads(content)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ClientError("API returned invalid JSON.", 5) from exc
        if not isinstance(result, dict):
            raise ClientError("API returned an unexpected response shape.", 5)
        return result

    def login(self, username: str, password: str) -> dict[str, Any]:
        if self.session_file is None:
            raise ClientError("Login requires an explicit --session-file.")
        if not 1 <= len(username) <= 128 or not 1 <= len(password) <= 256:
            raise ClientError("Invalid username or password length.")
        self.http.headers.pop("Cookie", None)
        self.http.cookies.clear()
        self.csrf_token = None
        result = self._request(
            "POST",
            "/api/v1/auth/login",
            authenticated=False,
            json={"username": username, "password": password},
        )
        cookies = list(self.http.cookies.jar)
        token = result.get("csrf_token")
        if len(cookies) != 1 or not isinstance(token, str) or not isinstance(result.get("user"), dict):
            raise ClientError("API returned an invalid authenticated session.", 5)
        cookie = cookies[0]
        try:
            data = SessionData(
                api_origin=self.origin,
                cookie_name=cookie.name,
                cookie_value=SecretStr(cookie.value or ""),
                csrf_token=SecretStr(token),
                expires_at=cookie.expires or int(time.time()) + 3600,
            )
            save_session(self.session_file, data)
        except (OSError, ValueError) as exc:
            raise ClientError("Cannot store a private session file. Check its path and permissions.") from exc
        self.csrf_token = token
        self.http.headers["Cookie"] = f"{cookie.name}={cookie.value}"
        return {"authenticated": True, "user": result["user"]}

    def status(self) -> dict[str, Any]:
        result = self._request("GET", "/api/v1/auth/session")
        return {"authenticated": result.get("authenticated", True), "user": result.get("user")}

    def logout(self) -> dict[str, Any]:
        result = self._request("POST", "/api/v1/auth/logout")
        if self.session_file:
            delete_session(self.session_file)
        self.http.headers.pop("Cookie", None)
        self.http.cookies.clear()
        self.csrf_token = None
        return result
