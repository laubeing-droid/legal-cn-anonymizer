"""S1 receipt identity tests: creation, signing, tamper detection, fail-closed
behavior on corruption."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from legal_anonymizer.security.receipt_identity import (
    PRIVATE_FILE,
    PUBLIC_FILE,
    ReceiptIdentity,
    ReceiptIdentityError,
)


@pytest.fixture()
def identity_dir(tmp_path):
    return tmp_path / "identity"


def _payload():
    return {
        "schema_version": "1.0",
        "matter_id": "matter-001",
        "status": "AUTO_READY",
    }


class TestReceiptIdentity:
    def test_create_and_load(self, identity_dir):
        ident = ReceiptIdentity(identity_dir).ensure()
        first_key_id = ident.key_id
        assert (identity_dir / PRIVATE_FILE).exists()
        assert (identity_dir / PUBLIC_FILE).exists()
        again = ReceiptIdentity(identity_dir).ensure()
        assert again.key_id == first_key_id

    def test_sign_and_verify(self, identity_dir):
        ident = ReceiptIdentity(identity_dir).ensure()
        sig = ident.sign(_payload())
        assert sig["algorithm"] == "Ed25519"
        ReceiptIdentity(identity_dir).ensure().verify(_payload(), sig)

    def test_single_byte_change_fails(self, identity_dir):
        ident = ReceiptIdentity(identity_dir).ensure()
        sig = ident.sign(_payload())
        tampered = dict(_payload())
        tampered["status"] = "CLOSED_BLOCK"
        with pytest.raises(Exception):
            ReceiptIdentity(identity_dir).ensure().verify(tampered, sig)

    def test_public_key_export_has_no_case_info(self, identity_dir):
        ident = ReceiptIdentity(identity_dir).ensure()
        exported = json.dumps(ident.export_public())
        assert "张三" not in exported
        assert "matter" not in exported
        assert set(json.loads(exported)) <= {
            "schema_version", "key_id", "fingerprint", "algorithm",
            "created_at", "public_key_b64", "rotation",
        }

    def test_corrupt_private_blob_fails_closed(self, identity_dir):
        ReceiptIdentity(identity_dir).ensure()
        (identity_dir / PRIVATE_FILE).write_bytes(b"corrupted blob")
        with pytest.raises(ReceiptIdentityError):
            ReceiptIdentity(identity_dir).ensure()

    def test_incomplete_identity_fails_closed(self, identity_dir):
        ReceiptIdentity(identity_dir).ensure()
        (identity_dir / PUBLIC_FILE).unlink()
        with pytest.raises(ReceiptIdentityError):
            ReceiptIdentity(identity_dir).ensure()

    def test_public_key_mismatch_fails_closed(self, identity_dir, tmp_path):
        ident = ReceiptIdentity(identity_dir).ensure()
        doc = json.loads((identity_dir / PUBLIC_FILE).read_text(encoding="utf-8"))
        doc["public_key_b64"] = ident.export_public()["public_key_b64"][:-4] + "AAAA"
        (identity_dir / PUBLIC_FILE).write_text(json.dumps(doc), encoding="utf-8")
        with pytest.raises(ReceiptIdentityError):
            ReceiptIdentity(identity_dir).ensure()

    def test_schema_hash_stable(self, identity_dir):
        ident = ReceiptIdentity(identity_dir).ensure()
        payload = _payload()
        sig1 = ident.sign(payload)
        sig2 = ident.sign(payload)
        assert sig1["signature"] == sig2["signature"]  # Ed25519 is deterministic
