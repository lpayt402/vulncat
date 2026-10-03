from __future__ import annotations

import csv
import io
import json
import os
import secrets
import stat
import subprocess
import sys
import time
import types
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from pydantic import SecretStr

from vulnbatch import cli
from vulnbatch.client.paths import checked_input_root
from vulnbatch.client.services import MAX_FILE_BYTES, WorkbenchService, read_bytes
from vulnbatch.client.session import SessionData, delete_session, load_session, save_session
from vulnbatch.client.transport import MAX_RESPONSE_BYTES, ApiClient, ClientError, validate_origin
from vulnbatch.reporting import REPORT_COLUMNS, render_payload


def session_data(origin: str = "http://127.0.0.1:8787", *, expires_at: int | None = None) -> SessionData:
    return SessionData(
        api_origin=origin,
        cookie_name="vulnerability_workbench_session",
        cookie_value=SecretStr(secrets.token_urlsafe(32)),
        csrf_token=SecretStr(secrets.token_urlsafe(32)),
        expires_at=expires_at or int(time.time()) + 3600,
    )


def authenticated_client(tmp_path: Path, handler: Any) -> ApiClient:
    path = tmp_path / "session.json"
    save_session(path, session_data())
    return ApiClient(session_file=path, transport=httpx.MockTransport(handler))


def test_subprocess_help_and_discovery_do_not_need_backend_settings() -> None:
    environment = {
        key: value for key, value in os.environ.items() if key not in {"DATABASE_URL", "SECRET_KEY"}
    }
    environment["PYTHONPATH"] = str(Path("backend").resolve())
    for arguments in (["discover"], ["--help"], ["about"]):
        process = subprocess.run(  # noqa: S603 - fixed Python module and literal parser smoke cases
            [sys.executable, "-m", "vulnbatch.cli", *arguments],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert process.returncode == 0
        assert "boo." not in process.stdout
        assert "Traceback" not in process.stderr
        if arguments != ["--help"]:
            assert isinstance(json.loads(process.stdout), dict)


def test_legacy_admin_commands_preserve_bootstrap_behavior(monkeypatch: pytest.MonkeyPatch) -> None:
    db = MagicMock()
    db.scalar.side_effect = [None, None]
    factory = MagicMock()
    factory.begin.return_value.__enter__.return_value = db
    module = types.ModuleType("vulnbatch.db.session")
    module.SessionLocal = factory  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "vulnbatch.db.session", module)
    password = "CLI-test-" + secrets.token_urlsafe(24)
    args = cli.build_parser().parse_args(
        ["create-admin", "--username", "testadmin", "--display-name", "Test", "--password", password]
    )
    assert args.role == "administrator"
    assert args.func(args) == 0
    created = db.add.call_args_list[-1].args[0]
    assert created.username == "testadmin"
    assert created.password_hash != password
    admin = MagicMock()
    admin.role.name = "administrator"
    db.scalar.side_effect = [admin]
    reset = cli.build_parser().parse_args(
        ["reset-admin-password", "--username", "testadmin", "--password", password]
    )
    assert reset.func(reset) == 0
    assert admin.password_hash != password
    user = cli.build_parser().parse_args(["create-user", "--username", "reader", "--display-name", "Reader"])
    assert user.role == "read_only"


@pytest.mark.parametrize(
    "origin",
    [
        "ftp://localhost",
        "https://user:password@example.test",
        "http://example.test",
        "http://localhost/path",
        "http://localhost?url=evil",
        "http://localhost#secret",
        "http://localhost\\evil",
        "http://localhost:invalid",
    ],
)
def test_origin_validation(origin: str) -> None:
    with pytest.raises(ClientError):
        validate_origin(origin)


def test_session_permissions_origin_expiry_and_schema(tmp_path: Path) -> None:
    path = tmp_path / "session.json"
    data = session_data()
    save_session(path, data)
    assert load_session(path, data.api_origin).cookie_value == data.cookie_value
    assert data.cookie_value.get_secret_value() not in repr(data)
    with pytest.raises(ValueError, match="different API origin"):
        load_session(path, "https://example.test")
    save_session(path, session_data(expires_at=1))
    with pytest.raises(ValueError, match="expired"):
        load_session(path, data.api_origin)
    path.write_text(
        json.dumps({"version": 1, "api_origin": data.api_origin, "extra": "unexpected"}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="invalid format"):
        load_session(path, data.api_origin)


def test_session_rejects_broad_permissions(tmp_path: Path) -> None:
    path = tmp_path / "session.json"
    save_session(path, session_data())
    if os.name == "nt":
        executable = str(Path(os.environ["SYSTEMROOT"]) / "System32" / "icacls.exe")
        subprocess.run(  # noqa: S603 - OS utility and disposable synthetic credential fixture only
            [executable, str(path), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True, timeout=10
        )
    else:
        path.chmod(0o644)
    with pytest.raises(ValueError, match=r"another Windows account|0600"):
        load_session(path, "http://127.0.0.1:8787")


def test_login_status_csrf_and_logout_never_return_credentials(tmp_path: Path) -> None:
    cookie, csrf, password = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    user = {
        "id": str(uuid.uuid4()),
        "username": "fixture",
        "display_name": "Fixture",
        "role": "administrator",
    }
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/api/v1/auth/login":
            assert json.loads(request.content)["password"] == password
            return httpx.Response(
                200,
                json={"authenticated": True, "csrf_token": csrf, "user": user},
                headers={
                    "Set-Cookie": f"vulnerability_workbench_session={cookie}; Path=/; HttpOnly; Max-Age=3600"
                },
            )
        assert request.headers["Cookie"] == f"vulnerability_workbench_session={cookie}"
        if request.url.path.endswith("logout"):
            assert request.headers["X-CSRF-Token"] == csrf
            return httpx.Response(200, json={"message": "Signed out."})
        assert "X-CSRF-Token" not in request.headers
        return httpx.Response(200, json={"authenticated": True, "csrf_token": csrf, "user": user})

    path = tmp_path / "session.json"
    with ApiClient(session_file=path, transport=httpx.MockTransport(handler)) as client:
        result = client.login("fixture", password)
    with ApiClient(session_file=path, transport=httpx.MockTransport(handler)) as client:
        result.update(client.status())
        assert client.logout()["message"] == "Signed out."
    assert not path.exists()
    assert all(secret not in json.dumps(result) for secret in (cookie, csrf, password))
    assert len(seen) == 3


@pytest.mark.parametrize(("status", "expected"), [(401, 3), (403, 3), (409, 4), (422, 2), (500, 5), (302, 5)])
def test_api_error_mapping_redacts_server_details(tmp_path: Path, status: int, expected: int) -> None:
    secret = secrets.token_urlsafe(32)
    with authenticated_client(
        tmp_path,
        lambda _: httpx.Response(
            status, json={"detail": secret}, headers={"Location": "https://external.test"}
        ),
    ) as client:
        with pytest.raises(ClientError) as error:
            client.status()
        assert error.value.code == expected
        assert secret not in str(error.value)


def test_response_and_transport_bounds(tmp_path: Path) -> None:
    with (
        authenticated_client(
            tmp_path, lambda _: httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        ) as client,
        pytest.raises(ClientError, match="output bound"),
    ):
        client.status()

    def failing(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sensitive internal error", request=request)

    with authenticated_client(tmp_path, failing) as client:
        with pytest.raises(ClientError) as error:
            client.status()
        assert error.value.code == 5
        assert "sensitive" not in str(error.value)


def test_import_uses_signed_preview_revision_and_exact_multipart(tmp_path: Path) -> None:
    path = tmp_path / "inventory.csv"
    path.write_text("hostname\nfixture\n", encoding="utf-8")
    options = [
        {"source": "inventory", "instance": "fixture", "format": "csv", "mapping": {"hostname": "hostname"}}
    ]
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert "X-CSRF-Token" in request.headers
        assert 'name="uploads"' in request.content.decode()
        assert path.read_bytes() in request.content
        if request.url.path.endswith("preview"):
            return httpx.Response(200, json={"revision": 7, "preview_token": "signed-fixture", "items": []})
        assert b"signed-fixture" in request.content
        assert b'name="expected_revision"\r\n\r\n7' in request.content
        return httpx.Response(200, json={"revision": 8, "persisted": True})

    with authenticated_client(tmp_path, handler) as client:
        service = WorkbenchService(client)
        preview = service.preview([str(path)], options)
        assert service.import_bundle([str(path)], options, preview, "fixture-key")["persisted"] is True
        with pytest.raises(ClientError, match="signed preview"):
            service.import_bundle([str(path)], options, {"revision": 7}, "invalid")
        with pytest.raises(ClientError, match="nonnegative"):
            service.import_bundle([str(path)], options, {"revision": True, "preview_token": "x"}, "invalid")
    assert len(requests) == 2


def test_files_and_mcp_input_root_are_bounded(tmp_path: Path) -> None:
    path = tmp_path / "large.csv"
    with path.open("wb") as handle:
        handle.truncate(MAX_FILE_BYTES + 1)
    with pytest.raises(ClientError, match="bytes"):
        read_bytes(path, MAX_FILE_BYTES)
    root = tmp_path / "approved"
    root.mkdir()
    path.write_text("fixture", encoding="utf-8")
    with pytest.raises(ClientError, match="outside"):
        read_bytes(path, MAX_FILE_BYTES, input_root=root)


def test_unattended_mutation_and_login_fail_before_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    document = tmp_path / "decision.json"
    document.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert cli.run(["reconciliation", "decide", "--document", str(document)]) == 2
    assert "--confirm" in capsys.readouterr().err
    assert cli.run(["login", "--username", "fixture"]) == 2
    assert "--password-stdin" in capsys.readouterr().err


def test_cli_parser_confirmed_decision_routes_through_shared_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    observed = str(uuid.uuid4())
    document = {
        "action": "reject",
        "request_key": "fixture",
        "reason": "Reviewed synthetic fixture",
        "expected_revision": 3,
        "observation_ids": [observed],
        "expected_versions": {observed: 2},
    }
    path = tmp_path / "decision.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    client = authenticated_client(
        tmp_path, lambda request: httpx.Response(200, json={"received": json.loads(request.content)})
    )
    monkeypatch.setattr(cli, "ApiClient", lambda *args, **kwargs: client)
    assert cli.run(["reconciliation", "decide", "--document", str(path), "--confirm"]) == 0
    received = json.loads(capsys.readouterr().out)["received"]
    assert {key: received[key] for key in document} == document


def test_shared_report_renderer_preserves_envelope_and_escapes_cells() -> None:
    payload = {
        "revision": 3,
        "total": 1,
        "items": [
            {
                "observation_kind": "coverage",
                "native_status": 'failed,"dns"\nagain',
                "node_label": "=external()",
                "age_days": -1,
                "evidence": {"z": 2, "a": "pipe|<html>"},
            }
        ],
    }
    assert json.loads(render_payload(payload, "json", REPORT_COLUMNS)) == payload
    rows = list(csv.DictReader(io.StringIO(render_payload(payload, "csv", REPORT_COLUMNS))))
    assert list(rows[0]) == list(REPORT_COLUMNS)
    assert rows[0]["native_status"] == payload["items"][0]["native_status"]
    assert rows[0]["node_label"] == "'=external()"
    assert rows[0]["age_days"] == "-1"
    assert rows[0]["asset_id"] == ""
    assert rows[0]["evidence"] == '{"a":"pipe|<html>","z":2}'
    markdown = render_payload(payload, "markdown", REPORT_COLUMNS)
    assert "pipe\\|&lt;html&gt;" in markdown
    assert "<br>again" in markdown
    assert render_payload({"items": []}, "csv", REPORT_COLUMNS).strip().split(",") == list(REPORT_COLUMNS)


def test_exposure_read_routes_keep_node_search_and_relationship_pages_explicit(tmp_path: Path) -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"items": []})

    node_id = str(uuid.uuid4())
    with authenticated_client(tmp_path, handler) as client:
        service = WorkbenchService(client)
        service.exposure_nodes("gateway", "load_balancer", 2, 10)
        service.exposure_node(node_id, 10, 20)
        service.exposure_read(
            "graph", node_id=node_id, offset=20, limit=50, relationship_offset=100, relationship_limit=200
        )
    assert captured[0].url.path == "/api/v1/exposure/nodes"
    assert dict(captured[0].url.params) == {
        "q": "gateway",
        "kind": "load_balancer",
        "offset": "2",
        "limit": "10",
    }
    assert captured[1].url.path == f"/api/v1/exposure/nodes/{node_id}"
    assert dict(captured[1].url.params) == {"fact_offset": "10", "fact_limit": "20"}
    assert dict(captured[2].url.params) == {
        "node_id": node_id,
        "offset": "20",
        "limit": "50",
        "relationship_offset": "100",
        "relationship_limit": "200",
    }


@pytest.mark.parametrize(
    "spelling",
    [
        r"\\remote.invalid\share\file.csv",
        "//remote.invalid/share/file.csv",
        r"\\?\C:\file.csv",
        r"\\.\GLOBALROOT\Device\file.csv",
        r"\??\C:\file.csv",
        "file://remote.invalid/share/file.csv",
        "https://remote.invalid/file.csv",
        "smb://remote.invalid/share/file.csv",
        "C:relative.csv",
    ],
)
def test_remote_device_and_uri_paths_fail_before_metadata(
    spelling: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Rejected paths must not cause filesystem metadata, resolution or open calls")

    for operation in ("stat", "lstat", "is_file", "is_dir", "is_symlink", "resolve", "open", "exists"):
        monkeypatch.setattr(Path, operation, forbidden)
    monkeypatch.setattr(httpx, "Client", forbidden)
    path = Path(spelling)
    with pytest.raises(ClientError, match="local filesystem path"):
        read_bytes(path, 100)
    with pytest.raises(ValueError, match="local filesystem path"):
        checked_input_root(path)
    with pytest.raises(ValueError, match="local filesystem path"):
        load_session(path, "http://127.0.0.1:8787")
    with pytest.raises(ValueError, match="local filesystem path"):
        save_session(path, session_data())
    with pytest.raises(ValueError, match="local filesystem path"):
        delete_session(path)
    with pytest.raises(ClientError, match="local filesystem path"):
        ApiClient(session_file=path)


def test_mcp_lexical_root_containment_precedes_all_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Outside-root files must be rejected before metadata or resolution")

    for operation in ("stat", "lstat", "is_file", "is_dir", "is_symlink", "resolve", "open", "exists"):
        monkeypatch.setattr(Path, operation, forbidden)
    root = tmp_path / "approved"
    outsiders = [
        tmp_path / "outside.csv",
        root / ".." / "outside.csv",
        tmp_path / "approved-sibling" / "file.csv",
    ]
    if os.name == "nt":
        other_drive = "Z" if root.drive.casefold() != "z:" else "Y"
        outsiders.append(Path(f"{other_drive}:\\outside.csv"))
    for path in outsiders:
        with pytest.raises(ClientError, match="outside"):
            read_bytes(path, 100, input_root=root)


@pytest.mark.parametrize("link_mode", ["symlink", "junction"])
def test_linked_parent_is_rejected_before_child_lookup_or_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, link_mode: str
) -> None:
    root = tmp_path / "approved"
    link = root / "linked"
    child = link / "file.csv"
    looked_up: list[Path] = []
    resolved: list[Path] = []

    def metadata(path: Path) -> Any:
        assert path != child, "A parent link must be rejected before looking up its target child"
        looked_up.append(path)
        return types.SimpleNamespace(
            st_mode=stat.S_IFLNK if path == link and link_mode == "symlink" else stat.S_IFDIR,
            st_file_attributes=0x400 if path == link and link_mode == "junction" else 0,
        )

    def resolve(path: Path, *args: Any, **kwargs: Any) -> Path:
        assert path == root, "A linked caller path must not be resolved"
        resolved.append(path)
        return path

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("A linked path must not be followed or opened")

    monkeypatch.setattr(Path, "lstat", metadata)
    monkeypatch.setattr(Path, "is_dir", lambda _: True)
    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(Path, "is_file", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    with pytest.raises(ClientError, match="symbolic links, junctions or reparse"):
        read_bytes(child, 100, input_root=root)
    with pytest.raises(ValueError, match="symbolic links, junctions or reparse"):
        load_session(child, "http://127.0.0.1:8787")
    assert child not in looked_up
    assert resolved == [root]


def test_regular_relative_input_files_remain_supported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "fixture.csv").write_bytes(b"synthetic-local-file")
    monkeypatch.chdir(tmp_path)
    assert read_bytes(Path("fixture.csv"), 100) == b"synthetic-local-file"
    assert read_bytes(Path("fixture.csv"), 100, input_root=tmp_path) == b"synthetic-local-file"


@pytest.mark.skipif(os.name != "nt", reason="Win32 path component aliases")
@pytest.mark.parametrize(
    "spelling", [r"C:\approved\.. \file.csv", r"C:\approved\file.csv.", r"C:\approved\file.csv "]
)
def test_windows_trailing_component_aliases_fail_before_metadata(
    spelling: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Win32 alias spellings must be rejected before metadata")

    for operation in ("stat", "lstat", "is_file", "is_dir", "is_symlink", "resolve", "open", "exists"):
        monkeypatch.setattr(Path, operation, forbidden)
    with pytest.raises(ClientError, match="trailing spaces or dots"):
        read_bytes(Path(spelling), 100, input_root=Path(r"C:\approved"))
    with pytest.raises(ValueError, match="trailing spaces or dots"):
        load_session(Path(spelling), "http://127.0.0.1:8787")
