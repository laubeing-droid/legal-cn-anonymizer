"""Portable project export/import (.lapx): Scrypt + AES-256-GCM, random salt
and nonce, associated data binding schema + matter id. Passwords come only
from getpass — never argv. Authentication failures never reveal whether the
password or the file was wrong."""

from __future__ import annotations

import base64
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from ..contracts.canonical import canonical_json
from ..security.safe_storage import StorageError, atomic_write_bytes, safe_root

SCHEMA_VERSION = "1.0"
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class PortableError(RuntimeError):
    error_code = "portable_project_authentication_failed"


def _read_password(confirm: bool) -> str:
    import getpass

    password = getpass.getpass("导出/导入密码: ")
    if not password:
        raise PortableError("empty password")
    if confirm:
        again = getpass.getpass("再次输入密码: ")
        if again != password:
            raise PortableError("passwords do not match")
    return password


def export_portable(state_root: Path, matter_id: str, out_path: Path,
                    *, password: str | None = None) -> dict:
    """Seal the matter's private state into a portable .lapx envelope."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from .state import MatterState, MatterStateError

    try:
        state = MatterState.load(state_root, matter_id)
        private = state.read_private()
    except MatterStateError as exc:
        raise PortableError(f"matter unavailable: {exc}") from exc

    password = password if password is not None else _read_password(confirm=True)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = hashlib_scrypt(password, salt)
    aad = canonical_json({"schema_version": SCHEMA_VERSION, "matter_id": matter_id})
    ciphertext = AESGCM(key).encrypt(nonce, canonical_json(private), aad)
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "matter_id": matter_id,
        "kdf": "scrypt",
        "kdf_params": {"n": _SCRYPT_N, "r": _SCRYPT_R, "p": _SCRYPT_P},
        "cipher": "aes-256-gcm",
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "created_at": _now(),
    }
    atomic_write_bytes(
        Path(out_path),
        json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"),
    )
    return envelope


def hashlib_scrypt(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    kdf = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def import_portable(state_root: Path, in_path: Path, *,
                    password: str | None = None) -> str:
    """Unseal a .lapx into a new matter. Wrong password and tampered file are
    indistinguishable by design. Returns the matter id."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    envelope = json.loads(Path(in_path).read_text(encoding="utf-8"))
    matter_id = envelope["matter_id"]
    password = password if password is not None else _read_password(confirm=False)
    salt = base64.b64decode(envelope["salt_b64"])
    nonce = base64.b64decode(envelope["nonce_b64"])
    key = hashlib_scrypt(password, salt)
    aad = canonical_json({"schema_version": envelope["schema_version"], "matter_id": matter_id})
    try:
        plaintext = AESGCM(key).decrypt(
            nonce, base64.b64decode(envelope["ciphertext_b64"]), aad
        )
    except (InvalidTag, Exception):  # noqa: BLE001 - uniform failure
        raise PortableError("authentication failed") from None
    private = json.loads(plaintext.decode("utf-8"))

    try:
        target_root = safe_root(Path(state_root))
    except StorageError as exc:
        raise PortableError(f"state root unsafe: {exc}") from exc
    target = Path(state_root) / matter_id
    if (target / "private.dpapi").exists() or (target / "project.public.json").exists():
        raise PortableError(f"matter {matter_id} already exists; refusing to overwrite")
    from ..security.dpapi_vault import MatterVault

    safe_root(Path(state_root), matter_id=matter_id)
    vault = MatterVault(target, matter_id)
    vault.create(private)
    public = {
        "schema_version": SCHEMA_VERSION,
        "matter_id": matter_id,
        "profile_id": "cn-ai-safe-v1",
        "documents": [],
        "status": "REVIEW_REQUIRED",
    }
    atomic_write_bytes(
        target / "project.public.json",
        json.dumps(public, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"),
    )
    return matter_id
