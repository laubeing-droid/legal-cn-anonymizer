"""Canonical JSON serialization.

Contract (mirrors the Legal Harness canonical profile):

- ``json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
  allow_nan=False).encode("utf-8")``
- floats are forbidden everywhere (money is a canonical decimal string);
- ``Decimal`` becomes a canonical decimal string;
- ``datetime`` must be serialized to an RFC3339 UTC string by the caller, never
  implicitly;
- dict keys must be strings;
- schema_version participates in every hash.
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any, Mapping

import hashlib


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonically serialized."""


def _canonicalize(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        raise CanonicalizationError("float is forbidden in canonical structures")
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise CanonicalizationError("non-finite Decimal is forbidden")
        return format(value, "f")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        raise CanonicalizationError("bytes must be encoded (e.g. base64) before canonicalization")
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"dict key must be str, got {type(key).__name__}")
            out[key] = _canonicalize(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, (type(None),)):
        return None
    raise CanonicalizationError(
        f"type {type(value).__name__} is not canonicalizable; convert it explicitly"
    )


def canonical_json(value: Any) -> bytes:
    """Return the canonical UTF-8 JSON encoding of *value*."""
    return json.dumps(
        _canonicalize(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_hash(value: Any, *, schema_version: str | None = None) -> str:
    """SHA-256 over canonical bytes; schema_version participates when given."""
    payload = canonical_json(value)
    if schema_version is not None:
        payload = canonical_json({"schema_version": schema_version}) + b":" + payload
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def hmac_sha256(key: bytes, value: Any) -> str:
    """HMAC-SHA256 commitment over canonical bytes (hex, not hash-notation)."""
    import hmac as _hmac

    return _hmac.new(key, canonical_json(value), hashlib.sha256).hexdigest()
