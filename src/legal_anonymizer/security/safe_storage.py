"""Safe local storage for private state.

Security patterns selectively ported from juris-calculus compiler_core/storage.py
(safe root, reparse-point refusal, owner-only DACL, atomic write-through
publication) and rewritten for this project's matter semantics. JC artifact
semantics are NOT copied."""

from __future__ import annotations

import ctypes
import os
import stat
import subprocess
from ctypes import wintypes
from pathlib import Path


class StorageError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise StorageError(code, detail)


def is_reparse(info: os.stat_result) -> bool:
    return bool(
        info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
        if hasattr(info, "st_file_attributes")
        else stat.S_ISLNK(info.st_mode)
    )


def current_windows_sid() -> str:
    import ctypes

    advapi32 = ctypes.windll.advapi32

    class TokenUser(ctypes.Structure):
        _fields_ = [("user", ctypes.c_void_p), ("attributes", wintypes.DWORD)]

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        wintypes.HANDLE(-1), wintypes.DWORD(0x0008), ctypes.byref(token)
    ):
        _fail("STORAGE_CAPABILITY_BLOCKED", "cannot open process token")
    try:
        size = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, 1, buffer, size.value, ctypes.byref(size)):
            _fail("STORAGE_CAPABILITY_BLOCKED", "cannot read token user")
        sid = ctypes.cast(buffer, ctypes.POINTER(TokenUser)).contents.user
        text = wintypes.LPWSTR()
        if not sid or not advapi32.ConvertSidToStringSidW(
            ctypes.c_void_p(sid), ctypes.byref(text)
        ):
            _fail("STORAGE_CAPABILITY_BLOCKED", "cannot decode Windows SID")
        return text.value
    finally:
        ctypes.windll.kernel32.CloseHandle(token)


def harden_windows(path: Path) -> None:
    """Owner-only DACL: current user + SYSTEM only; inheritance removed and
    builtin groups (Administrators/Users/Everyone/Authenticated Users/owner
    rights) explicitly stripped."""
    sid = current_windows_sid()
    rights = "(OI)(CI)F" if path.is_dir() else "F"
    commands = (
        ["icacls.exe", str(path), "/setowner", f"*{sid}"],
        [
            "icacls.exe", str(path), "/inheritance:r", "/grant:r",
            f"*{sid}:{rights}", f"*S-1-5-18:{rights}",
        ],
        [
            "icacls.exe", str(path), "/remove:g",
            "*S-1-1-0", "*S-1-5-11", "*S-1-5-32-544", "*S-1-5-32-545",
            "*S-1-3-4",
        ],
    )
    for command in commands:
        completed = subprocess.run(
            command, capture_output=True, check=False, timeout=20,
        )  # bytes output: icacls console encoding varies by locale
        if completed.returncode != 0:
            _fail("STORAGE_CAPABILITY_BLOCKED", "owner-only Windows DACL cannot be set")


def windows_acl_sids(path: Path) -> tuple[str, frozenset[str]]:
    """Inspect owner + DACL via pywin32. Returns (owner_sid, granted_sids)."""
    import win32security

    try:
        sd = win32security.GetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION,
        )
        owner_sid = win32security.ConvertSidToStringSid(
            sd.GetSecurityDescriptorOwner()
        )
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            _fail("STORAGE_CAPABILITY_BLOCKED", "Windows DACL is unavailable")
        allowed: set[str] = set()
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            ace_type = ace[0][0]
            if ace_type == 0:  # ACCESS_ALLOWED_ACE_TYPE
                allowed.add(win32security.ConvertSidToStringSid(ace[2]))
            elif ace_type != 1:
                _fail("STORAGE_CAPABILITY_BLOCKED", "unsupported Windows ACE type")
        return owner_sid, frozenset(allowed)
    except StorageError:
        raise
    except Exception as exc:  # noqa: BLE001
        _fail("STORAGE_CAPABILITY_BLOCKED", f"Windows DACL cannot be inspected: {type(exc).__name__}")


def verify_security(path: Path, *, file: bool = False) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        _fail("STORAGE_IO", f"cannot inspect {path.name}: {exc}")
    if is_reparse(info):
        _fail("STORAGE_REPARSE", f"reparse point is forbidden: {path.name}")
    if (file and not stat.S_ISREG(info.st_mode)) or (
        not file and not stat.S_ISDIR(info.st_mode)
    ):
        _fail("STORAGE_LAYOUT", f"storage node has the wrong type: {path.name}")
    if os.name == "nt":
        current = current_windows_sid()
        owner, allowed = windows_acl_sids(path)
        if owner != current or current not in allowed:
            _fail("STORAGE_DACL", "Windows storage owner/DACL is not owner-only")
        if not allowed <= {current, "S-1-5-18"}:
            _fail("STORAGE_DACL", "Windows storage grants an unapproved principal")
    else:
        expected = 0o600 if file else 0o700
        if stat.S_IMODE(info.st_mode) != expected:
            _fail("STORAGE_PERMISSION", "POSIX storage mode is not private")


def _mkdir_safe(path: Path, harden: bool) -> None:
    path.mkdir(parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or is_reparse(info):
        _fail("STORAGE_LAYOUT", f"storage node has the wrong type: {path.name}")
    if harden and os.name == "nt":
        harden_windows(path)


def safe_root(base: Path, *, matter_id: str | None = None) -> Path:
    """Resolve and harden the safe state root. UNC/device paths are refused and
    every component (including the leaf, before resolution) is checked against
    reparse points — a junction pointing anywhere is refused."""
    root = Path(os.path.abspath(base))
    if os.name == "nt":
        if root.drive.startswith("\\\\") or str(root).startswith("\\\\"):
            _fail("STORAGE_PATH", "UNC paths are forbidden for state roots")
    if root.anchor in ("//", "\\\\"):
        _fail("STORAGE_PATH", "UNC paths are forbidden for state roots")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current = current / part
        if current.exists() or current.is_symlink():
            info = current.lstat()
            if is_reparse(info):
                _fail("STORAGE_REPARSE", "state root traverses a reparse point")
    _mkdir_safe(root, harden=True)
    if matter_id:
        matter_dir = root / matter_id
        if not matter_id.replace("-", "").isalnum():
            _fail("STORAGE_PATH", f"matter id is not a safe directory name: {matter_id!r}")
        _mkdir_safe(matter_dir, harden=True)
        verify_security(matter_dir)
        return matter_dir
    verify_security(root)
    return root


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write temporary -> flush -> write-through replace. Never half-written."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(
        tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600
    )
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    try:
        dirfd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except OSError:
        pass  # directory fsync is best-effort on Windows
