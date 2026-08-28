"""S1 contract tests: closed fields, canonical serialization, private/public
separation, schema validation."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import jsonschema
import pytest

from legal_anonymizer.contracts import (
    CanonicalizationError,
    EntityType,
    SanitizationStatus,
    TransformKind,
    canonical_hash,
    canonical_json,
    hmac_sha256,
    public_payload,
)
from legal_anonymizer.contracts.models import SanitizationReceipt
from legal_anonymizer.contracts.private_models import (
    PrivateMapping,
    PrivateMappingEntry,
    PrivateMention,
)

SCHEMA_DIR = Path("src/legal_anonymizer/contracts/schemas")


class TestCanonical:
    def test_hash_is_field_order_independent(self):
        a = {"b": 1, "a": 2}
        b = {"a": 2, "b": 1}
        assert canonical_hash(a) == canonical_hash(b)

    def test_float_rejected(self):
        with pytest.raises(CanonicalizationError):
            canonical_json({"money": 3.14})

    def test_nan_infinity_rejected(self):
        with pytest.raises(CanonicalizationError):
            canonical_json({"x": Decimal("NaN")})
        with pytest.raises(CanonicalizationError):
            canonical_json({"x": Decimal("Infinity")})

    def test_decimal_becomes_canonical_string(self):
        assert canonical_json({"m": Decimal("300.50")}) == b'{"m":"300.50"}'

    def test_non_string_key_rejected(self):
        with pytest.raises(CanonicalizationError):
            canonical_json({1: "a"})

    def test_unicode_stable(self):
        assert canonical_json({"姓名": "张三"}) == '{"姓名":"张三"}'.encode("utf-8")

    def test_schema_version_participates_in_hash(self):
        v = {"x": 1}
        assert canonical_hash(v, schema_version="1.0") != canonical_hash(v, schema_version="1.1")

    def test_hmac_commitment_changes_with_key(self):
        v = {"a": 1}
        assert hmac_sha256(b"k1", v) != hmac_sha256(b"k2", v)


class TestPrivatePublicSeparation:
    def test_private_mention_cannot_serialize_public(self):
        m = PrivateMention(
            mention_id="m1",
            document_id="doc-001",
            locator={"kind": "text_offset", "start": 0, "end": 2},
            surface="张三",
            surface_hmac="0" * 64,
            entity_type=EntityType.PERSON,
            source="regex",
            confidence=0.99,
        )
        with pytest.raises(TypeError, match="private"):
            public_payload(m)

    def test_private_mapping_cannot_serialize_public(self):
        mp = PrivateMapping(
            matter_id="matter-001",
            entries=(
                PrivateMappingEntry(
                    entity_id="ent:person:0001",
                    display_alias="自然人A",
                    canonical_surface="张三",
                ),
            ),
        )
        with pytest.raises(TypeError):
            public_payload(mp)

    def test_public_receipt_serializes_closed(self):
        r = SanitizationReceipt(
            matter_id="matter-001",
            profile_id="cn-ai-safe-v1",
            provider_build_digest="deadbeef",
            created_at="2026-08-29T00:00:00Z",
            status=SanitizationStatus.AUTO_READY,
            sanitized_bundle_hash="sha256:" + "0" * 64,
            artifact_hashes={"doc-001.ai.md": "0" * 64},
            mapping_commitment="0" * 64,
            source_set_commitment="0" * 64,
            invariants={"money_multiset_preserved": True},
        )
        payload = public_payload(r)
        assert "surface" not in json.dumps(payload)
        assert "张三" not in json.dumps(payload)


class TestSchemaValidation:
    def _schema(self, name):
        return json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))

    def test_receipt_validates(self):
        receipt = {
            "schema_version": "1.0",
            "matter_id": "matter-001",
            "profile_id": "cn-ai-safe-v1",
            "provider_id": "legal-cn-anonymizer",
            "provider_build_digest": "deadbeef",
            "created_at": "2026-08-29T00:00:00Z",
            "status": "AUTO_READY",
            "sanitized_bundle_hash": "sha256:" + "0" * 64,
            "artifact_hashes": {"doc-001.ai.md": "0" * 64},
            "mapping_commitment": "0" * 64,
            "source_set_commitment": "0" * 64,
            "invariants": {"money_multiset_preserved": True},
            "signature": {
                "algorithm": "Ed25519",
                "key_id": "0123456789abcdef",
                "signature": "AAAA",
            },
        }
        jsonschema.validate(receipt, self._schema("sanitization-receipt-v1"))

    def test_unknown_field_rejected(self):
        receipt = {
            "schema_version": "1.0",
            "matter_id": "matter-001",
            "profile_id": "cn-ai-safe-v1",
            "provider_id": "x",
            "provider_build_digest": "d",
            "created_at": "2026-08-29T00:00:00Z",
            "status": "AUTO_READY",
            "sanitized_bundle_hash": "sha256:" + "0" * 64,
            "artifact_hashes": {},
            "mapping_commitment": "0" * 64,
            "source_set_commitment": "0" * 64,
            "invariants": {},
            "sneaky_raw_value": "张三",
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(receipt, self._schema("sanitization-receipt-v1"))

    def test_raw_surface_forbidden_in_public_schemas(self):
        for f in SCHEMA_DIR.glob("*.schema.json"):
            if f.name.startswith(("private-", "mapping-envelope")):
                continue
            text = f.read_text(encoding="utf-8")
            assert '"surface"' not in text, f"{f.name} must not carry raw surface field"
            assert "original_path" not in text, f"{f.name} must not carry paths"

    def test_public_models_reject_unknown_fields(self):
        from legal_anonymizer.contracts.models import ProjectManifest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ProjectManifest(
                schema_version="1.0",
                matter_id="matter-001",
                profile_id="cn-ai-safe-v1",
                created_at="2026-08-29T00:00:00Z",
                unexpected_field=True,
            )

    def test_transform_kind_closed(self):
        assert TransformKind.MASK_KEEP_LAST_4.value == "MASK_KEEP_LAST_4"
        assert SanitizationStatus.CLOSED_BLOCK.value == "CLOSED_BLOCK"
