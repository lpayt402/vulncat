"""Local path checks ordered to avoid following caller-selected network paths."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path, PureWindowsPath

_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[/\\]")
_REPARSE_POINT = 0x400


def _local_spelling(value: str) -> None:
    portable = value.replace("\\", "/")
    if (
        not value
        or len(value) > 4096
        or any(ord(character) < 32 for character in value)
        or portable.startswith("//")
        or portable.casefold().startswith(("/??/", "/device/"))
        or (_SCHEME.match(value) is not None and _DRIVE_ROOT.match(value) is None)
    ):
        raise ValueError("Use a regular local filesystem path; UNC, device and URI paths are unsupported.")
    if os.name == "nt":
        # Block alternate data streams and DOS device names as well as drive-
        # relative spellings; normal relative files and rooted drives still work.
        tail = value[2:] if _DRIVE_ROOT.match(value) else value
        if ":" in tail or PureWindowsPath(value).is_reserved():
            raise ValueError("Device names and alternate data streams are unsupported.")
        if any(
            component not in {".", ".."} and component.endswith((" ", "."))
            for component in PureWindowsPath(value).parts
        ):
            raise ValueError("Windows local paths must not contain trailing spaces or dots in components.")


def lexical_local_path(path: Path) -> Path:
    """Normalize without stat/resolve/open, rejecting remote spellings first."""
    _local_spelling(os.fspath(path))
    absolute = Path(os.path.abspath(path))
    _local_spelling(os.fspath(absolute))
    return absolute


def checked_local_path(path: Path, *, allow_missing_leaf: bool = False) -> Path:
    """Reject linked/reparse ancestors top-down before metadata can traverse them."""
    absolute = lexical_local_path(path)
    for component in (*reversed(absolute.parents), absolute):
        try:
            info = component.lstat()
        except FileNotFoundError:
            if component == absolute and allow_missing_leaf:
                break
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT:
            raise ValueError("Local paths must not traverse symbolic links, junctions or reparse points.")
    return absolute


def checked_input_root(path: Path) -> Path:
    root = checked_local_path(path)
    if not root.is_dir():
        raise ValueError("MCP input root must be an existing local directory.")
    # Resolution is safe only after every component has passed the no-link check.
    resolved = root.resolve(strict=True)
    _local_spelling(os.fspath(resolved))
    return resolved
