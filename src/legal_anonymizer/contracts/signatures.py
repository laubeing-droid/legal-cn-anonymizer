"""Ed25519 receipt signing/verification over canonical JSON bytes."""

from __future__ import annotations

from typing import Any

from .canonical import canonical_json

ALGORITHM = "Ed25519"


class SignatureError(ValueError):
    pass


def sign_payload(private_key, payload: dict[str, Any], key_id: str) -> dict:
    """Return the signature block for *payload* (canonical bytes signed)."""
    from cryptography.exceptions import InternalError

    try:
        raw = private_key.sign(canonical_json(payload))
    except InternalError as exc:
        raise SignatureError("signing failed") from exc
    import base64

    return {
        "algorithm": ALGORITHM,
        "key_id": key_id,
        "signature": base64.b64encode(raw).decode("ascii"),
    }


def verify_payload(public_key, payload: dict[str, Any], signature: dict) -> None:
    """Verify the signature block against *payload*. Raises SignatureError."""
    if not isinstance(signature, dict):
        raise SignatureError("signature block missing")
    if signature.get("algorithm") != ALGORITHM:
        raise SignatureError(f"unsupported signature algorithm: {signature.get('algorithm')}")
    if "signature" not in signature or not signature["signature"]:
        raise SignatureError("signature value missing")
    import base64

    try:
        raw = base64.b64decode(signature["signature"], validate=True)
    except Exception as exc:  # noqa: BLE001
        raise SignatureError("signature is not valid base64") from exc
    from cryptography.exceptions import InvalidSignature

    try:
        public_key.verify(raw, canonical_json(payload))
    except InvalidSignature as exc:
        raise SignatureError("signature verification failed") from exc
