"""Consumer contract manifest: binds schemas, provider build, signer key,
profiles, canonical profile, required invariants and fixture hashes. Consumers
never rewrite these schemas; they pin the exact copies shipped here."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from .canonical import canonical_json

MANIFEST_SCHEMA_VERSION = "1.0"
PUBLIC_SCHEMAS = [
    "sanitization-receipt-v1",
    "sanitized-bundle-v1",
    "human-review-receipt-v1",
    "privacy-verification-receipt-v1",
    "privacy-verification-receipt-v2",
    "coverage-statement-v1",
    "scan-bytes-report-v1",
    "consumer-contract-manifest-v1",
]


def schema_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_manifest(
    repo_root: Path,
    signer_public: dict,
    profile_ids: list[str],
    extra_fixture_hashes: dict[str, str] | None = None,
) -> dict:
    schemas_dir = repo_root / "src" / "legal_anonymizer" / "contracts" / "schemas"
    schemas = {}
    for name in PUBLIC_SCHEMAS:
        p = schemas_dir / f"{name}.schema.json"
        if p.exists():
            schemas[name] = {
                "sha256": schema_sha256(p),
                "canonical_copy": True,
            }
    from .. import __version__

    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "source_repository": "legal-cn-anonymizer",
        "source_commit_note": "local construction branch; commit recorded in provenance",
        "package_version": __version__,
        "provider_id": "legal-cn-anonymizer",
        "provider_build_digest": _build_digest(repo_root),
        "signer": {
            "key_id": signer_public.get("key_id"),
            "fingerprint": signer_public.get("fingerprint"),
            "algorithm": signer_public.get("algorithm", "Ed25519"),
        },
        "profile_ids": profile_ids,
        "canonical_serialization_profile": {
            "json_dumps": "ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False",
            "floats": "forbidden",
            "money": "canonical decimal string",
            "time": "RFC3339 UTC",
        },
        "required_invariants": [
            "entity_mapping_injective",
            "money_multiset_preserved",
            "legal_event_date_multiset_preserved",
            "mapping_excluded_from_public_bundle",
        ],
        "schemas": schemas,
        "fixture_hashes": extra_fixture_hashes or {},
    }


def _build_digest(repo_root: Path) -> str:
    schemas_dir = repo_root / "src" / "legal_anonymizer" / "contracts" / "schemas"
    parts = []
    for f in sorted(schemas_dir.glob("*.schema.json")):
        parts.append(f"{f.name}:{schema_sha256(f)}")
    return "sha256:" + hashlib.sha256(canonical_json({"schemas": parts})).hexdigest()


def export_public_key(identity) -> dict:
    exported = identity.export_public()
    return {
        "schema_version": "1.0",
        "key_id": exported["key_id"],
        "fingerprint": exported["fingerprint"],
        "algorithm": exported["algorithm"],
        "public_key_b64": exported["public_key_b64"],
        "note": "public trust material; contains no case information",
    }


def verify_signature_with_public(public_key_b64: str, payload: dict, signature: dict) -> None:
    """Consumer-side signature verification from exported public key bytes."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    from .signatures import canonical_json, SignatureError

    if signature.get("algorithm") != "Ed25519":
        raise SignatureError("unsupported signature algorithm")
    raw = base64.b64decode(signature["signature"])
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
    try:
        pub.verify(raw, canonical_json(payload))
    except InvalidSignature as exc:
        raise SignatureError("signature verification failed") from exc
