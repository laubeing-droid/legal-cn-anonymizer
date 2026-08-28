"""Windows DPAPI seal/unseal bound to the current user. Non-Windows or failure
paths fail closed: callers must treat any error as `mapping_vault_unavailable`
and never fall back to plaintext."""

from __future__ import annotations

import sys


class VaultUnavailableError(RuntimeError):
    """Raised when DPAPI is unavailable or the payload cannot be unsealed."""

    error_code = "mapping_vault_unavailable"


_DESCRIPTION = b"legal-cn-anonymizer-v1"


def _entropy_bytes(entropy: str | None) -> bytes:
    if not entropy:
        return _DESCRIPTION
    return _DESCRIPTION + b":" + entropy.encode("utf-8")


def protect(data: bytes, *, entropy: str | None = None) -> bytes:
    """Seal *data* with DPAPI (CryptProtectData), bound to the current user."""
    if sys.platform != "win32":
        raise VaultUnavailableError(
            "DPAPI requires Windows; refusing to store private material unprotected"
        )
    try:
        import win32crypt

        blob = win32crypt.CryptProtectData(
            data,
            "legal-cn-anonymizer",
            _entropy_bytes(entropy),
            None,
            None,
            0,
        )
    except Exception as exc:  # noqa: BLE001 - fail closed on any DPAPI error
        raise VaultUnavailableError(f"DPAPI protect failed: {type(exc).__name__}") from exc
    return blob


def unprotect(blob: bytes, *, entropy: str | None = None) -> bytes:
    """Unseal a DPAPI blob. Any failure raises VaultUnavailableError (fail closed)."""
    if sys.platform != "win32":
        raise VaultUnavailableError("DPAPI requires Windows")
    try:
        import win32crypt

        _desc, data = win32crypt.CryptUnprotectData(
            blob, _entropy_bytes(entropy), None, None, 0
        )
    except Exception as exc:  # noqa: BLE001
        raise VaultUnavailableError(
            f"DPAPI unprotect failed: {type(exc).__name__}"
        ) from exc
    return data
