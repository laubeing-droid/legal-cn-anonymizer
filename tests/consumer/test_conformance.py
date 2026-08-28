"""S10 conformance tests: the protocol pack and the mock consumer."""

from __future__ import annotations

from pathlib import Path

import pytest

from legal_anonymizer.application.consumer_protocol import build_consumer_protocol
from tests.consumer.mock_consumer import (
    ACCEPTABLE_FOR_IMPORT,
    REJECTED_ARTIFACT_HASH_MISMATCH,
    REJECTED_BAD_SIGNATURE,
    REJECTED_MAPPING_IN_BUNDLE,
    REJECTED_MISSING_REVIEW,
    REJECTED_STATUS_BLOCKED,
    REJECTED_STALE_RECEIPT,
    REJECTED_UNKNOWN_SCHEMA_FIELD,
    verify_consumer_bundle,
)


@pytest.fixture(scope="module")
def protocol_pack(tmp_path_factory):
    base = tmp_path_factory.mktemp("s10")
    state_root = base / "state"
    pack = base / "consumer-protocol"
    result = build_consumer_protocol(state_root, pack)
    return base, Path(result["protocol_dir"])


class TestProtocolPack:
    def test_positive_examples_accepted(self, protocol_pack):
        _base, pack = protocol_pack
        for example in ("auto-ready", "ready-by-human"):
            ok, reason = verify_consumer_bundle(pack / "examples" / example, pack)
            assert ok == ACCEPTABLE_FOR_IMPORT, (example, reason)

    def test_blocked_example_rejected(self, protocol_pack):
        _base, pack = protocol_pack
        ok, reason = verify_consumer_bundle(pack / "examples" / "blocked", pack)
        assert ok == REJECTED_STATUS_BLOCKED

    def test_negative_fixtures_rejected(self, protocol_pack):
        _base, pack = protocol_pack
        expectations = {
            "bad-signature": REJECTED_BAD_SIGNATURE,
            "stale-receipt": REJECTED_STALE_RECEIPT,
            "mapping-in-bundle": REJECTED_MAPPING_IN_BUNDLE,
            "missing-review": REJECTED_MISSING_REVIEW,
            "artifact-hash-mismatch": REJECTED_BAD_SIGNATURE,  # tampered field breaks signature first
            "unknown-schema-field": REJECTED_UNKNOWN_SCHEMA_FIELD,
        }
        for name, expected in expectations.items():
            ok, reason = verify_consumer_bundle(pack / "negative-fixtures" / name, pack)
            assert ok == expected, (name, reason)

    def test_pack_completeness(self, protocol_pack):
        _base, pack = protocol_pack
        for required in (
            "consumer-contract-manifest.json",
            "SHA256SUMS",
            "README.md",
            "public-keys/receipt-signing-public.json",
            "schemas/sanitization-receipt-v1.schema.json",
            "schemas/sanitized-bundle-v1.schema.json",
            "schemas/human-review-receipt-v1.schema.json",
            "schemas/privacy-verification-receipt-v1.schema.json",
            "schemas/consumer-contract-manifest-v1.schema.json",
        ):
            assert (pack / required).exists(), required

    def test_public_key_contains_no_case_data(self, protocol_pack):
        _base, pack = protocol_pack
        text = (pack / "public-keys" / "receipt-signing-public.json").read_text(
            encoding="utf-8"
        )
        for marker in ("秦岭", "暮云", "matter", "proto-demo"):
            assert marker not in text, marker

    def test_sha256sums_covers_pack(self, protocol_pack):
        import hashlib

        _base, pack = protocol_pack
        entries = {}
        for line in (pack / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            digest, rel = line.split("  ", 1)
            entries[rel] = digest
        assert "consumer-contract-manifest.json" in entries
        assert "README.md" in entries
        for rel, digest in entries.items():
            actual = hashlib.sha256((pack / rel).read_bytes()).hexdigest()
            assert actual == digest, rel
