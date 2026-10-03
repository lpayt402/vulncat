from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Any, cast

from sqlalchemy import select

from vulnbatch.branding import FULL_NAME, NAME, launch_banner
from vulnbatch.client.services import NODE_KINDS, SOURCE_NAMES, WorkbenchService, read_json
from vulnbatch.client.transport import DEFAULT_API_URL, ApiClient, ClientError
from vulnbatch.core.security import (
    hash_password,
    normalize_username,
    validate_password,
    validate_username,
)
from vulnbatch.db.models import Role, User
from vulnbatch.reporting import REPORT_COLUMNS, render_payload


def _password_from_args(args: argparse.Namespace) -> str:
    if args.password:
        return cast(str, args.password)
    first = getpass.getpass("Password: ")
    second = getpass.getpass("Confirm password: ")
    if first != second:
        raise ValueError("Passwords do not match.")
    return first


def create_user(args: argparse.Namespace) -> int:
    from vulnbatch.db.session import SessionLocal

    username = normalize_username(args.username)
    if not validate_username(username):
        print("Invalid username.", file=sys.stderr)
        return 2
    password = _password_from_args(args)
    validation = validate_password(password, username)
    if not validation.valid:
        print(" ".join(validation.errors), file=sys.stderr)
        return 2
    with SessionLocal.begin() as db:
        existing = db.scalar(select(User).where(User.username == username))
        if existing is not None:
            print("User already exists.", file=sys.stderr)
            return 2
        role_name = cast(str, args.role)
        role = db.scalar(select(Role).where(Role.name == role_name))
        if role is None:
            description = (
                "Full administrative access"
                if role_name == "administrator"
                else "Read-only inventory and report access"
            )
            role = Role(name=role_name, description=description)
            db.add(role)
            db.flush()
        db.add(
            User(
                username=username,
                display_name=args.display_name,
                password_hash=hash_password(password),
                role_id=role.id,
            )
        )
    print(f"User {username} created with role {role_name}.")
    return 0


def reset_admin_password(args: argparse.Namespace) -> int:
    from vulnbatch.db.session import SessionLocal

    username = normalize_username(args.username)
    password = _password_from_args(args)
    validation = validate_password(password, username)
    if not validation.valid:
        print(" ".join(validation.errors), file=sys.stderr)
        return 2
    with SessionLocal.begin() as db:
        user = db.scalar(select(User).where(User.username == username))
        if user is None or user.role.name != "administrator":
            print("Administrator not found.", file=sys.stderr)
            return 2
        user.password_hash = hash_password(password)
    print(f"Password reset for {username}.")
    return 0


def _confirm(args: argparse.Namespace) -> None:
    if args.confirm:
        return
    if sys.stdin.isatty() and sys.stderr.isatty():
        print("This changes stored Vulncat data. Type yes to continue: ", end="", file=sys.stderr, flush=True)
        if sys.stdin.readline().strip() == "yes":
            return
    raise ClientError("Mutation requires --confirm, or typed yes in an interactive terminal.")


def _login_password(args: argparse.Namespace) -> str:
    if args.password_stdin:
        value = sys.stdin.readline(258)
        if len(value.rstrip("\r\n")) > 256:
            raise ClientError("Password exceeds 256 characters.")
        return value.rstrip("\r\n")
    if not sys.stdin.isatty():
        raise ClientError("Unattended login requires --password-stdin; passwords are never accepted in argv.")
    return getpass.getpass("Password: ", stream=sys.stderr)


def _object_file(path: Path) -> dict[str, Any]:
    result = read_json(path)
    if not isinstance(result, dict):
        raise ClientError("Document must be a JSON object.")
    return result


def _options_file(path: Path) -> list[dict[str, Any]]:
    result = read_json(path)
    if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
        raise ClientError("Options document must be a JSON array of source configurations.")
    return result


def api_command(args: argparse.Namespace) -> int:
    if args.command == "discover":
        result = {
            "commands": [
                "login",
                "logout",
                "status",
                "assets list",
                "reconciliation columns",
                "reconciliation preview",
                "reconciliation import",
                "reconciliation review",
                "reconciliation observation",
                "reconciliation decisions",
                "reconciliation decision",
                "reconciliation decide",
                "exposure nodes",
                "exposure node",
                "exposure graph",
                "exposure report",
                "exposure history",
                "exposure preview",
                "exposure apply",
                "exposure undo",
                "mcp",
            ],
            "formats": ["json", "csv", "markdown"],
            "writes_require_confirmation": True,
            "mcp_writes_disabled_by_default": True,
        }
        print(render_payload(result, args.format), end="")
        return 0
    if args.command == "about":
        print(
            render_payload(
                {"name": NAME, "alias": "vulncat", "full_name": FULL_NAME, "version": "0.1.0"}, args.format
            ),
            end="",
        )
        return 0
    if args.command == "mcp":
        from vulnbatch.mcp_server import serve

        serve(
            api_url=args.api_url,
            session_file=args.session_file,
            timeout=args.timeout,
            enable_writes=args.enable_writes,
            input_root=args.input_root,
        )
        return 0
    with ApiClient(args.api_url, session_file=args.session_file, timeout=args.timeout) as client:
        service = WorkbenchService(client)
        if args.command == "login":
            result = client.login(args.username, _login_password(args))
        elif args.command == "logout":
            result = client.logout()
        elif args.command == "status":
            result = client.status()
        elif args.command == "assets":
            result = service.assets(args.q, args.offset, args.limit)
        elif args.command == "reconciliation":
            operation = args.operation
            if operation == "columns":
                result = service.columns(args.file, args.input_format, args.records_path)
            elif operation == "preview":
                result = service.preview(args.files, _options_file(args.options), args.offset, args.limit)
            elif operation == "import":
                options, preview = _options_file(args.options), _object_file(args.preview)
                _confirm(args)
                result = service.import_bundle(args.files, options, preview, args.request_key)
            elif operation == "review":
                result = service.observations(
                    None if args.review_status == "all" else args.review_status,
                    args.asset_id,
                    args.source,
                    args.offset,
                    args.limit,
                )
            elif operation == "observation":
                result = service.observation(args.id)
            elif operation == "decisions":
                result = service.decisions(args.offset, args.limit)
            elif operation == "decision":
                result = service.decision(args.id)
            else:
                payload = _object_file(args.document)
                _confirm(args)
                result = service.decide(payload)
        elif args.command == "exposure":
            operation = args.operation
            if operation == "nodes":
                result = service.exposure_nodes(args.q, args.kind, args.offset, args.limit)
            elif operation == "node":
                result = service.exposure_node(args.node_id, args.fact_offset, args.fact_limit)
            elif operation in {"graph", "report", "history"}:
                result = service.exposure_read(
                    operation,
                    node_id=args.node_id,
                    observation_kind=getattr(args, "observation_kind", None),
                    offset=args.offset,
                    limit=args.limit,
                    relationship_offset=getattr(args, "relationship_offset", 0),
                    relationship_limit=getattr(args, "relationship_limit", 100),
                )
            elif operation == "preview":
                result = service.exposure_preview(_object_file(args.graph))
            elif operation == "apply":
                graph, preview = _object_file(args.graph), _object_file(args.preview)
                _confirm(args)
                result = service.exposure_apply(graph, preview, args.request_key, args.reason)
            else:
                _confirm(args)
                result = service.exposure_undo(
                    args.decision_id, args.expected_revision, args.request_key, args.reason
                )
        else:
            raise ClientError("Unsupported command.")
    columns = REPORT_COLUMNS if args.command == "exposure" and args.operation == "report" else None
    print(render_payload(result, args.format, columns), end="")
    return 0


def _pagination(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=50)


def _write_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--confirm", action="store_true", help="explicitly authorize this mutation")


def _upload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--file", dest="files", action="append", required=True, help="local input file; repeat 1-8 times"
    )
    parser.add_argument(
        "--options", type=Path, required=True, help="JSON array of SourceOptions, in file order"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulncat", description="Vulncat — Vulnerability Concatenator. Authenticated CLI."
    )
    parser.add_argument("--api-url", default=DEFAULT_API_URL, help="fixed API origin; default %(default)s")
    parser.add_argument(
        "--session-file", type=Path, help="explicit private session file; required for authenticated commands"
    )
    parser.add_argument("--timeout", type=float, default=30, help="HTTP timeout, 1-120 seconds")
    parser.add_argument("--format", choices=("json", "csv", "markdown"), default="json")
    parser.add_argument(
        "--quiet", "--no-cat", dest="no_cat", action="store_true", help="suppress interactive launch art"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create-user")
    create.add_argument("--username", required=True)
    create.add_argument("--display-name", required=True)
    create.add_argument("--password")
    create.add_argument(
        "--role",
        choices=("administrator", "read_only"),
        default="read_only",
    )
    create.set_defaults(func=create_user)

    create_admin = subparsers.add_parser("create-admin")
    create_admin.add_argument("--username", required=True)
    create_admin.add_argument("--display-name", required=True)
    create_admin.add_argument("--password")
    create_admin.set_defaults(func=create_user, role="administrator")

    reset = subparsers.add_parser("reset-admin-password")
    reset.add_argument("--username", required=True)
    reset.add_argument("--password")
    reset.set_defaults(func=reset_admin_password)

    login = subparsers.add_parser("login", help="sign in using existing Vulncat credentials")
    login.add_argument("--username", required=True)
    login.add_argument("--password-stdin", action="store_true", help="read one password line from stdin")
    login.set_defaults(func=api_command)
    for command in ("logout", "status", "discover", "about"):
        subparsers.add_parser(command).set_defaults(func=api_command)

    assets = subparsers.add_parser("assets").add_subparsers(dest="operation", required=True)
    asset_list = assets.add_parser("list")
    asset_list.add_argument("--q", default="")
    _pagination(asset_list)
    asset_list.set_defaults(func=api_command)

    reconciliation = subparsers.add_parser("reconciliation").add_subparsers(dest="operation", required=True)
    columns = reconciliation.add_parser("columns", help="discover local file columns without importing")
    columns.add_argument("--file", required=True)
    columns.add_argument("--input-format", choices=("csv", "json", "ndjson"), required=True)
    columns.add_argument("--records-path")
    columns.set_defaults(func=api_command)
    preview = reconciliation.add_parser("preview", help="review a signed, transient preview")
    _upload_args(preview)
    _pagination(preview)
    preview.set_defaults(func=api_command)
    importing = reconciliation.add_parser("import", help="persist exactly the reviewed files/options")
    _upload_args(importing)
    importing.add_argument(
        "--preview", type=Path, required=True, help="saved JSON preview containing token/revision"
    )
    importing.add_argument("--request-key", required=True, help="unique idempotency key")
    _write_args(importing)
    importing.set_defaults(func=api_command)
    review = reconciliation.add_parser("review")
    review.add_argument(
        "--review-status", choices=("open", "deferred", "assigned", "rejected", "all"), default="open"
    )
    review.add_argument("--asset-id")
    review.add_argument("--source", choices=SOURCE_NAMES)
    _pagination(review)
    review.set_defaults(func=api_command)
    for name in ("observation", "decision"):
        detail = reconciliation.add_parser(name)
        detail.add_argument("--id", required=True)
        detail.set_defaults(func=api_command)
    decisions = reconciliation.add_parser("decisions")
    _pagination(decisions)
    decisions.set_defaults(func=api_command)
    decide = reconciliation.add_parser(
        "decide", help="apply an existing guarded DecisionRequest JSON document"
    )
    decide.add_argument("--document", type=Path, required=True)
    _write_args(decide)
    decide.set_defaults(func=api_command)

    exposure = subparsers.add_parser("exposure").add_subparsers(dest="operation", required=True)
    for name in ("nodes", "graph", "report", "history"):
        read = exposure.add_parser(name)
        if name == "nodes":
            read.add_argument("--q", default="")
            read.add_argument("--kind", choices=NODE_KINDS)
        else:
            read.add_argument("--node-id")
        if name == "graph":
            read.add_argument("--relationship-offset", type=int, default=0)
            read.add_argument("--relationship-limit", type=int, default=100)
        if name == "report":
            read.add_argument("--observation-kind", choices=("inventory", "vulnerability", "coverage"))
        _pagination(read)
        read.set_defaults(func=api_command)
    node = exposure.add_parser("node", help="read one exposure node with paged fact history")
    node.add_argument("--node-id", required=True)
    node.add_argument("--fact-offset", type=int, default=0)
    node.add_argument("--fact-limit", type=int, default=50)
    node.set_defaults(func=api_command)
    exposure_preview = exposure.add_parser("preview")
    exposure_preview.add_argument("--graph", type=Path, required=True, help="GraphEnvelope JSON object")
    exposure_preview.set_defaults(func=api_command)
    apply = exposure.add_parser("apply")
    apply.add_argument("--graph", type=Path, required=True)
    apply.add_argument("--preview", type=Path, required=True)
    apply.add_argument("--request-key", required=True)
    apply.add_argument("--reason", required=True)
    _write_args(apply)
    apply.set_defaults(func=api_command)
    undo = exposure.add_parser("undo")
    undo.add_argument("--decision-id", required=True)
    undo.add_argument("--expected-revision", type=int, required=True)
    undo.add_argument("--request-key", required=True)
    undo.add_argument("--reason", required=True)
    _write_args(undo)
    undo.set_defaults(func=api_command)
    mcp = subparsers.add_parser("mcp", help="run the optional MCP adapter over stdio")
    mcp.add_argument("--enable-writes", action="store_true")
    mcp.add_argument(
        "--input-root", type=Path, default=Path.cwd(), help="bound MCP local file uploads to this directory"
    )
    mcp.set_defaults(func=api_command)
    return parser


def run(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    launch_banner(arguments)
    args = build_parser().parse_args(arguments)
    try:
        return cast(int, args.func(args))
    except ClientError as exc:
        print(str(exc), file=sys.stderr)
        return exc.code
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (OSError, EOFError):
        print("Cannot access the requested local resource.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 2


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    raise SystemExit(run())


if __name__ == "__main__":
    main()
