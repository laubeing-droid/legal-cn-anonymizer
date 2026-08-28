"""DPAPI matter vault: the private mapping envelope.

Contents (sealed): entity surfaces/aliases, mapping, matter secret, OCR
corrections, original file-name map, review decisions, rehydrate aliases.
Any unseal failure is fail-closed (`mapping_decryption_failed`) — an empty
mapping is never fabricated to keep going."""

from __future__ import annotations

import json
from pathlib import Path

from .dpapi import protect, unprotect, VaultUnavailableError
from .safe_storage import StorageError, atomic_write_bytes, verify_security

PRIVATE_FILE = "private.dpapi"
CACHE_FILE = "cache.dpapi"
_ENTROPY_PREFIX = "legal-cn-anonymizer/v1"


class VaultError(RuntimeError):
    """Fail-closed vault error. Callers map this to CLOSED_BLOCK."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class MatterVault:
    def __init__(self, matter_dir: Path, matter_id: str):
        self.dir = Path(matter_dir)
        self.matter_id = matter_id
        self.private_path = self.dir / PRIVATE_FILE
        self.cache_path = self.dir / CACHE_FILE
        self._entropy = f"{_ENTROPY_PREFIX}/{matter_id}"

    # -- lifecycle ---------------------------------------------------------

    def create(self, initial: dict) -> None:
        if self.private_path.exists():
            raise VaultError(
                "mapping_collision", f"private vault already exists: {self.private_path.name}"
            )
        self.seal_private(initial)

    # -- private state -------------------------------------------------------

    def seal_private(self, payload: dict) -> None:
        try:
            blob = protect(
                json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8"),
                entropy=self._entropy,
            )
        except VaultUnavailableError as exc:
            raise VaultError("mapping_vault_unavailable", str(exc)) from exc
        try:
            atomic_write_bytes(self.private_path, blob)
            verify_security(self.private_path, file=True)
        except StorageError as exc:
            raise VaultError(exc.code, exc.detail) from exc

    def unseal_private(self) -> dict:
        try:
            verify_security(self.private_path, file=True)
        except StorageError as exc:
            raise VaultError(exc.code, exc.detail) from exc
        try:
            blob = self.private_path.read_bytes()
        except OSError as exc:
            raise VaultError("mapping_vault_unavailable", f"vault unreadable: {exc}") from exc
        try:
            raw = unprotect(blob, entropy=self._entropy)
        except VaultUnavailableError as exc:
            raise VaultError("mapping_decryption_failed", str(exc)) from exc
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise VaultError("mapping_decryption_failed", "vault payload corrupt") from exc

    def cache_seal(self, payload: dict) -> None:
        blob = protect(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8"),
            entropy=self._entropy + "/cache",
        )
        atomic_write_bytes(self.cache_path, blob)
