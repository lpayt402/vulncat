from __future__ import annotations

import csv
import io
import json
import sys
import types

import pytest

from vulnbatch import branding, cli


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.mark.parametrize("art", branding.BANNERS)
@pytest.mark.parametrize("format_name", ["json", "csv", "markdown"])
def test_launch_art_stays_on_stderr_and_exports_remain_parseable(
    monkeypatch: pytest.MonkeyPatch, art: str, format_name: str
) -> None:
    output, errors = Terminal(), Terminal()
    monkeypatch.setattr(sys, "stdin", Terminal())
    monkeypatch.setattr(sys, "stdout", output)
    monkeypatch.setattr(sys, "stderr", errors)
    monkeypatch.setattr(branding.secrets, "choice", lambda _: art)
    assert cli.run(["--format", format_name, "about"]) == 0
    assert errors.getvalue() == art + "\n\n"
    assert art not in output.getvalue()
    if format_name == "json":
        assert json.loads(output.getvalue())["name"] == "Vulncat"
    elif format_name == "csv":
        assert next(csv.DictReader(io.StringIO(output.getvalue())))["name"] == "Vulncat"
    else:
        assert "Vulncat" in output.getvalue()


@pytest.mark.parametrize("arguments", [["--quiet", "about"], ["--no-cat", "about"], ["mcp"]])
def test_quiet_and_mcp_never_emit_art(monkeypatch: pytest.MonkeyPatch, arguments: list[str]) -> None:
    errors = Terminal()
    monkeypatch.setattr(sys, "stdin", Terminal())
    monkeypatch.setattr(sys, "stdout", Terminal())
    monkeypatch.setattr(sys, "stderr", errors)
    branding.launch_banner(arguments)
    assert errors.getvalue() == ""


@pytest.mark.parametrize("redirected", ["stdin", "stdout", "stderr"])
def test_any_noninteractive_stream_suppresses_art(monkeypatch: pytest.MonkeyPatch, redirected: str) -> None:
    errors = Terminal()
    monkeypatch.setattr(sys, "stdin", Terminal())
    monkeypatch.setattr(sys, "stdout", Terminal())
    monkeypatch.setattr(sys, "stderr", errors)
    monkeypatch.setattr(sys, redirected, io.StringIO())
    branding.launch_banner(["discover"])
    assert errors.getvalue() == ""


def test_quiet_alias_and_brand_help() -> None:
    parser = cli.build_parser()
    assert parser.parse_args(["--quiet", "about"]).no_cat
    assert parser.parse_args(["--no-cat", "about"]).no_cat
    assert "Vulnerability Concatenator" in parser.format_help()
    assert parser.prog == "vulncat"


def test_cli_mcp_dispatch_is_silent_even_on_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    output, errors = Terminal(), Terminal()
    monkeypatch.setattr(sys, "stdin", Terminal())
    monkeypatch.setattr(sys, "stdout", output)
    monkeypatch.setattr(sys, "stderr", errors)
    calls: list[dict[str, object]] = []
    module = types.ModuleType("vulnbatch.mcp_server")
    module.serve = lambda **kwargs: calls.append(kwargs)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "vulnbatch.mcp_server", module)
    assert cli.run(["mcp"]) == 0
    assert len(calls) == 1
    assert calls[0]["enable_writes"] is False
    assert output.getvalue() == errors.getvalue() == ""
