from __future__ import annotations

import json
import os
import stat
import time
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from vulnbatch.client.paths import checked_local_path

MAX_SESSION_BYTES = 16_384


def _uid() -> int:
    # Only called on POSIX; indirect lookup keeps Windows type-checking portable.
    return int(vars(os)["getuid"]())


class SessionData(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: int = Field(default=1, ge=1, le=1)
    api_origin: str
    cookie_name: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")
    cookie_value: SecretStr = Field(min_length=20, max_length=2048)
    csrf_token: SecretStr = Field(min_length=20, max_length=2048)
    expires_at: int = Field(ge=1)

    @field_validator("cookie_value", "csrf_token")
    @classmethod
    def credential_format(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if not raw.isascii() or any(not (character.isalnum() or character in "_-") for character in raw):
            raise ValueError("Invalid session credential format.")
        return value

    def serialized(self) -> bytes:
        return json.dumps(
            {
                **self.model_dump(exclude={"cookie_value", "csrf_token"}),
                "cookie_value": self.cookie_value.get_secret_value(),
                "csrf_token": self.csrf_token.get_secret_value(),
            },
            separators=(",", ":"),
        ).encode("utf-8")


def _safe_path(path: Path) -> Path:
    path = checked_local_path(path, allow_missing_leaf=True)
    if path.exists() and not path.is_file():
        raise ValueError("Session file must be a regular file, not a link or directory.")
    if not path.parent.is_dir():
        raise ValueError("Session file parent directory must already exist.")
    return path


def _windows_security() -> tuple[Any, Any, str]:
    import ctypes
    from ctypes import wintypes

    # These helpers run only on Windows; indirect lookup keeps POSIX type checks portable.
    win_dll = vars(ctypes)["WinDLL"]
    advapi = win_dll("advapi32", use_last_error=True)
    kernel = win_dll("kernel32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise OSError("Cannot inspect Windows session-file permissions.")
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise OSError("Cannot inspect Windows session-file permissions.")
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        value = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(value)):
            raise OSError("Cannot inspect Windows session-file permissions.")
        try:
            sid_string = value.value
        finally:
            kernel.LocalFree(ctypes.cast(value, ctypes.c_void_p))
    finally:
        kernel.CloseHandle(token)
    return advapi, kernel, str(sid_string)


def _windows_validate(path: Path) -> None:
    import ctypes
    from ctypes import wintypes

    advapi, kernel, current_sid = _windows_security()
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    if advapi.GetNamedSecurityInfoW(
        str(path.absolute()),
        1,
        5,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    ):
        raise ValueError("Cannot inspect session-file permissions.")
    try:
        owner_string = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(owner, ctypes.byref(owner_string)):
            raise ValueError("Cannot inspect session-file owner.")
        try:
            if owner_string.value != current_sid:
                raise ValueError("Session file must belong to the current user.")
        finally:
            kernel.LocalFree(ctypes.cast(owner_string, ctypes.c_void_p))
        if not dacl.value:
            raise ValueError("Session file must have a private access-control list.")
        # ACL header: revision byte, reserved byte, size ushort, ACE count ushort.
        count = ctypes.c_ushort.from_address(dacl.value + 4).value
        advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        for index in range(count):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)) or ace.value is None:
                raise ValueError("Cannot inspect session-file access controls.")
            ace_type = ctypes.c_ubyte.from_address(ace.value).value
            if ace_type == 1:  # Access-denied ACE cannot disclose the file.
                continue
            if ace_type != 0:
                raise ValueError("Unsupported session-file access control.")
            trustee = wintypes.LPWSTR()
            if not advapi.ConvertSidToStringSidW(ctypes.c_void_p(ace.value + 8), ctypes.byref(trustee)):
                raise ValueError("Cannot inspect session-file trustee.")
            try:
                if trustee.value not in {current_sid, "S-1-5-18"}:
                    raise ValueError("Session file permits access by another Windows account.")
            finally:
                kernel.LocalFree(ctypes.cast(trustee, ctypes.c_void_p))
    finally:
        kernel.LocalFree(descriptor)


def _private_create(path: Path) -> int:
    if os.name != "nt":
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    import ctypes
    import msvcrt
    from ctypes import wintypes

    advapi, kernel, sid = _windows_security()

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", wintypes.BOOL)]

    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    descriptor = ctypes.c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)", 1, ctypes.byref(descriptor), None
    ):
        raise OSError("Cannot create private Windows session file.")
    try:
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        kernel.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(SecurityAttributes),
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel.CreateFileW.restype = wintypes.HANDLE
        handle = kernel.CreateFileW(
            str(path.absolute()), 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None
        )
        if handle == ctypes.c_void_p(-1).value:
            raise OSError("Cannot create private Windows session file.")
        return int(vars(msvcrt)["open_osfhandle"](handle, os.O_WRONLY | vars(os)["O_BINARY"]))
    finally:
        kernel.LocalFree(descriptor)


def load_session(path: Path, origin: str) -> SessionData:
    path = _safe_path(path)
    if not path.exists():
        raise ValueError("Session file not found. Log in with an explicit --session-file first.")
    if os.name == "nt":
        _windows_validate(path)
    else:
        info = path.stat()
        if info.st_uid != _uid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Session file must be owned by you with permissions 0600.")
    with path.open("rb") as handle:
        content = handle.read(MAX_SESSION_BYTES + 1)
    if len(content) > MAX_SESSION_BYTES:
        raise ValueError("Session file is too large.")
    try:
        data = SessionData.model_validate_json(content)
    except (ValidationError, ValueError) as exc:
        raise ValueError("Session file has an invalid format.") from exc
    if data.api_origin != origin:
        raise ValueError("Session file belongs to a different API origin.")
    if data.expires_at <= time.time():
        raise ValueError("Session has expired. Log in again.")
    return data


def save_session(path: Path, data: SessionData) -> None:
    path = _safe_path(path)
    if path.exists():
        # Validate permissions even when replacing an expired file.
        if os.name == "nt":
            _windows_validate(path)
        elif stat.S_IMODE(path.stat().st_mode) & 0o077 or path.stat().st_uid != _uid():
            raise ValueError("Existing session file is not private.")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with os.fdopen(_private_create(temporary), "wb") as handle:
            handle.write(data.serialized())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def delete_session(path: Path) -> None:
    path = _safe_path(path)
    path.unlink(missing_ok=True)
