"""Receipt signing identity: Ed25519 key pair, private key sealed with DPAPI,
public key exportable. Corruption or unavailability fails closed — callers must
map failures to `CLOSED_BLOCK/mapping_vault_unavailable` and never silently
create a fresh identity over existing receipts."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from ..contracts.signatures import sign_payload, verify_payload
from .dpapi import VaultUnavailableError, protect, unprotect

PRIVATE_FILE = "receipt-signing-private.dpapi"
PUBLIC_FILE = "receipt-signing-public.json"


class ReceiptIdentityError(RuntimeError):
    """Identity unavailable or corrupt. Fail closed."""

    error_code = "mapping_vault_unavailable"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ReceiptIdentity:
    """Loaded signing identity. Private key material never leaves this object."""

    def __init__(self, identity_dir: Path):
        self._dir = Path(identity_dir)
        self._private = None
        self._public = None
        self._meta: dict = {}

    # -- lifecycle ---------------------------------------------------------

    def ensure(self, *, matter_entropy: str | None = None) -> "ReceiptIdentity":
        """Load the identity, creating it on first initialization."""
        priv_path = self._dir / PRIVATE_FILE
        pub_path = self._dir / PUBLIC_FILE
        if priv_path.exists() and pub_path.exists():
            return self._load(priv_path, pub_path)
        if priv_path.exists() or pub_path.exists():
            # half-present identity is corrupt state: fail closed
            raise ReceiptIdentityError("receipt signing identity is incomplete; refusing to recreate")
        return self._create(priv_path, pub_path)

    def _create(self, priv_path: Path, pub_path: Path) -> "ReceiptIdentity":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._private = Ed25519PrivateKey.generate()
        self._public = self._private.public_key()
        priv_raw = self._private.private_bytes_raw()
        sealed = protect(priv_raw, entropy="receipt-signing-identity")
        key_id, fingerprint = self._fingerprint()
        self._meta = {
            "schema_version": "1.0",
            "key_id": key_id,
            "fingerprint": fingerprint,
            "algorithm": "Ed25519",
            "created_at": _now(),
            "rotation": {"generation": 1, "previous_key_ids": []},
        }
        self._dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(priv_path, sealed)
        _atomic_write_bytes(
            pub_path,
            json.dumps(
                {
                    "schema_version": "1.0",
                    "key_id": key_id,
                    "fingerprint": fingerprint,
                    "algorithm": "Ed25519",
                    "created_at": self._meta["created_at"],
                    "public_key_b64": base64.b64encode(self._public.public_bytes_raw()).decode("ascii"),
                    "note": "public trust material; contains no case information",
                },
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            ).encode("utf-8"),
        )
        return self

    def _load(self, priv_path: Path, pub_path: Path) -> "ReceiptIdentity":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        try:
            sealed = priv_path.read_bytes()
            pub_doc = json.loads(pub_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ReceiptIdentityError(f"identity files unreadable: {exc}") from exc
        try:
            priv_raw = unprotect(sealed, entropy="receipt-signing-identity")
        except VaultUnavailableError as exc:
            raise ReceiptIdentityError(str(exc)) from exc
        try:
            self._private = Ed25519PrivateKey.from_private_bytes(priv_raw)
        except Exception as exc:  # noqa: BLE001
            raise ReceiptIdentityError("private key bytes corrupt") from exc
        self._public = self._private.public_key()
        actual_pub_b64 = base64.b64encode(
            self._public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii")
        if pub_doc.get("public_key_b64") != actual_pub_b64:
            raise ReceiptIdentityError("public key file does not match private key; refusing to sign")
        self._meta = pub_doc
        return self

    def _fingerprint(self) -> tuple[str, str]:
        raw = self._public.public_bytes_raw()
        digest = hashlib.sha256(raw).hexdigest()
        return digest[:16], "sha256:" + digest

    # -- accessors ----------------------------------------------------------

    @property
    def key_id(self) -> str:
        return self._meta["key_id"]

    @property
    def metadata(self) -> dict:
        return dict(self._meta)

    def export_public(self) -> dict:
        """Public trust material (no case info)."""
        import base64

        return {
            "schema_version": "1.0",
            "key_id": self._meta["key_id"],
            "fingerprint": self._meta["fingerprint"],
            "algorithm": "Ed25519",
            "created_at": self._meta["created_at"],
            "public_key_b64": base64.b64encode(self._public.public_bytes_raw()).decode("ascii"),
            "rotation": self._meta.get("rotation", {}),
        }

    # -- signing -------------------------------------------------------------

    def sign(self, payload: dict) -> dict:
        if self._private is None:
            raise ReceiptIdentityError("identity not loaded")
        return sign_payload(self._private, payload, self.key_id)

    def verify(self, payload: dict, signature: dict) -> None:
        verify_payload(self._public, payload, signature)


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


_atomic_write_bytes = _atomic_write
