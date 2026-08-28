"""Mock conformance consumer (read-only, minimal, offline).

This consumer exists to prove the protocol closes end-to-end. It represents no
production consumer and performs no Harness/JC integration. It accepts a
handoff bundle directory only when every check passes, and rejects with stable
codes otherwise."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import jsonschema

ACCEPTABLE_FOR_IMPORT = "ACCEPTABLE_FOR_IMPORT"

REJECTED_UNKNOWN_SIGNER = "REJECTED_UNKNOWN_SIGNER"
REJECTED_BAD_SIGNATURE = "REJECTED_BAD_SIGNATURE"
REJECTED_SCHEMA_MISMATCH = "REJECTED_SCHEMA_MISMATCH"
REJECTED_UNKNOWN_SCHEMA_FIELD = "REJECTED_UNKNOWN_SCHEMA_FIELD"
REJECTED_MAPPING_IN_BUNDLE = "REJECTED_MAPPING_IN_BUNDLE"
REJECTED_ARTIFACT_HASH_MISMATCH = "REJECTED_ARTIFACT_HASH_MISMATCH"
REJECTED_STALE_RECEIPT = "REJECTED_STALE_RECEIPT"
REJECTED_MISSING_REVIEW = "REJECTED_MISSING_REVIEW"
REJECTED_STATUS_BLOCKED = "REJECTED_STATUS_BLOCKED"

_FORBIDDEN_KEYS = {"canonical_surface", "surface", "matter_secret", "original_filename_map",
                   "aliases", "ocr_corrections"}


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _signature_ok(public_key_b64: str, payload: dict, signature: dict) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from legal_anonymizer.contracts.canonical import canonical_json

    try:
        if signature.get("algorithm") != "Ed25519" or not signature.get("signature"):
            return False
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature["signature"]),
                   canonical_json(payload))
        return True
    except Exception:  # noqa: BLE001 - any failure is a rejection
        return False


def _canonical_hash(payload: dict) -> str:
    from legal_anonymizer.contracts.canonical import canonical_hash

    return canonical_hash(payload, schema_version="1.0")


def verify_consumer_bundle(bundle_dir: Path, protocol_dir: Path | None = None) -> tuple[str, str | None]:
    """Returns (ACCEPTABLE_FOR_IMPORT, None) or (REJECTED_<CODE>, detail)."""
    bundle_dir = Path(bundle_dir)
    protocol_dir = Path(protocol_dir) if protocol_dir else bundle_dir.parent.parent

    # 1. manifest signature against the shipped public key
    key_path = protocol_dir / "public-keys" / "receipt-signing-public.json"
    manifest_path = protocol_dir / "consumer-contract-manifest.json"
    if not key_path.exists() or not manifest_path.exists():
        return REJECTED_UNKNOWN_SIGNER, "protocol pack incomplete"
    key_doc = _load(key_path)
    manifest = _load(manifest_path)
    if not _signature_ok(key_doc["public_key_b64"],
                         {k: v for k, v in manifest.items() if k != "signature"},
                         manifest.get("signature", {})):
        return REJECTED_BAD_SIGNATURE, "manifest signature invalid"

    # 2. schema copies match the manifest
    schemas_dir = protocol_dir / "schemas"
    for name, meta in manifest["schemas"].items():
        f = schemas_dir / f"{name}.schema.json"
        if not f.exists() or hashlib.sha256(f.read_bytes()).hexdigest() != meta["sha256"]:
            return REJECTED_SCHEMA_MISMATCH, f"{name} does not match manifest"

    # 3. bundle schema validation (unknown fields rejected)
    bundle_path = bundle_dir / "sanitized-bundle.json"
    if not bundle_path.exists():
        return REJECTED_UNKNOWN_SCHEMA_FIELD, "sanitized-bundle.json missing"
    bundle = _load(bundle_path)
    schema = _load(schemas_dir / "sanitized-bundle-v1.schema.json")
    try:
        jsonschema.validate(bundle, schema)
    except jsonschema.ValidationError as exc:
        return REJECTED_UNKNOWN_SCHEMA_FIELD, str(exc.message)

    # 4. private fields must never appear
    for probe in (bundle, *bundle.get("structured_objects", [])):
        for key in probe:
            if key in _FORBIDDEN_KEYS:
                return REJECTED_MAPPING_IN_BUNDLE, f"private field {key!r} in bundle"

    # 5. bundle signature
    body = {k: v for k, v in bundle.items() if k != "signature"}
    if not _signature_ok(key_doc["public_key_b64"], body, bundle.get("signature", {})):
        return REJECTED_BAD_SIGNATURE, "bundle signature invalid"

    # 6. artifact hashes: files on disk must match the signed artifact list
    for artifact in bundle["artifacts"]:
        f = bundle_dir / "sanitized" / artifact["name"]
        if not f.exists():
            return REJECTED_STALE_RECEIPT, f"artifact {artifact['name']} missing"
        if hashlib.sha256(f.read_bytes()).hexdigest() != artifact["sha256"]:
            return REJECTED_STALE_RECEIPT, f"artifact {artifact['name']} changed after signing"

    # 7. receipt binding: signed sanitization receipt must hash-bind to the bundle
    receipt_path = bundle_dir / "sanitization-receipt.json"
    if not receipt_path.exists():
        return REJECTED_BAD_SIGNATURE, "sanitization receipt missing"
    receipt = _load(receipt_path)
    expected = _canonical_hash(receipt)
    if bundle["receipt_hash"] != expected:
        return REJECTED_BAD_SIGNATURE, "receipt hash does not bind the bundle"

    # 8. review status
    status = bundle["status"]
    if status == "CLOSED_BLOCK" or status == "REVIEW_REQUIRED":
        return REJECTED_STATUS_BLOCKED, f"status {status} is not importable"
    if status == "READY_BY_HUMAN":
        hr = bundle_dir / "human-review-receipt.json"
        if not hr.exists():
            return REJECTED_MISSING_REVIEW, "READY_BY_HUMAN without human review receipt"
        hr_doc = _load(hr)
        hr_body = {k: v for k, v in hr_doc.items() if k != "signature"}
        if not _signature_ok(key_doc["public_key_b64"], hr_body, hr_doc.get("signature", {})):
            return REJECTED_BAD_SIGNATURE, "human review receipt signature invalid"
        if hr_body.get("sanitized_bundle_hash") and hr_body["sanitized_bundle_hash"] != _canonical_hash(
            {a["name"]: a["sha256"] for a in bundle["artifacts"]}
        ):
            return REJECTED_MISSING_REVIEW, "human review receipt binds other artifacts"

    return ACCEPTABLE_FOR_IMPORT, None
