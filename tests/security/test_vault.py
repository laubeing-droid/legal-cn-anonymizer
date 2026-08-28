"""S8 vault tests: DPAPI sealing, DACL hardening and drift, reparse refusal,
portable roundtrip, tamper and wrong-password uniform failure."""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path

import pytest

from legal_anonymizer.application.portable_service import (
    PortableError,
    export_portable,
    import_portable,
)
from legal_anonymizer.application.state import MatterState, MatterStateError
from legal_anonymizer.security.safe_storage import (
    StorageError,
    current_windows_sid,
    safe_root,
    verify_security,
)


@pytest.fixture()
def state(tmp_path):
    root = tmp_path / "state"
    MatterState(root, "matter-001").init("cn-ai-safe-v1")
    return root


class TestDpapiVault:
    def test_private_state_is_sealed(self, state):
        blob = (state / "matter-001" / "private.dpapi").read_bytes()
        # DPAPI blob magic, definitely not plaintext JSON
        assert blob[:4] == b"\x01\x00\x00\x00"
        assert b"matter_secret" not in blob
        assert b"entities" not in blob

    def test_roundtrip(self, state):
        s = MatterState.load(state, "matter-001")
        private = s.read_private()
        private["entities"].append({"entity_id": "ent:person:0001", "canonical_surface": "张三"})
        s.write_private(private)
        again = MatterState.load(state, "matter-001").read_private()
        assert again["entities"][0]["entity_id"] == "ent:person:0001"

    def test_tampered_vault_fails_closed(self, state):
        s = MatterState.load(state, "matter-001")
        blob_path = state / "matter-001" / "private.dpapi"
        blob = bytearray(blob_path.read_bytes())
        blob[-20] ^= 0xFF  # flip bits inside the ciphertext
        blob_path.write_bytes(bytes(blob))
        with pytest.raises(MatterStateError, match="mapping_decryption_failed|STORAGE"):
            s.read_private()

    def test_matter_secret_stable(self, state):
        s1 = MatterState.load(state, "matter-001")
        s2 = MatterState.load(state, "matter-001")
        assert s1.matter_secret == s2.matter_secret


class TestDacl:
    def test_state_root_hardened(self, tmp_path):
        root = safe_root(tmp_path / "state", matter_id="matter-001")
        sid = current_windows_sid()
        owner, allowed = __import__(
            "legal_anonymizer.security.safe_storage", fromlist=["windows_acl_sids"]
        ).windows_acl_sids(root)
        assert owner == sid
        assert allowed <= {sid, "S-1-5-18"}
        verify_security(root)

    def test_dacl_drift_detected(self, tmp_path):
        root = safe_root(tmp_path / "state", matter_id="matter-001")
        probe = root / "probe.txt"
        probe.write_bytes(b"x")
        # grant Everyone on the probe -> drift must be detected
        subprocess.run(
            ["icacls.exe", str(probe), "/grant", "*S-1-1-0:R"],
            capture_output=True, check=True, timeout=20,
        )
        with pytest.raises(StorageError, match="STORAGE_DACL"):
            verify_security(probe, file=True)

    def test_reparse_point_refused(self, tmp_path):
        target = tmp_path / "real"
        target.mkdir()
        link = tmp_path / "state"
        try:
            subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True, check=True, timeout=20,
            )
        except subprocess.CalledProcessError:
            pytest.skip("junction creation unavailable")
        with pytest.raises(StorageError, match="STORAGE_REPARSE"):
            safe_root(link)


class TestPortable:
    def test_roundtrip(self, tmp_path, state):
        s = MatterState.load(state, "matter-001")
        private = s.read_private()
        private["entities"].append(
            {"entity_id": "ent:person:0001", "canonical_surface": "张三",
             "display_alias": "自然人A", "aliases": [], "roles": []}
        )
        s.write_private(private)

        lapx = tmp_path / "matter-001.lapx"
        export_portable(state, "matter-001", lapx, password="强密码123")
        new_root = tmp_path / "restored"
        matter = import_portable(new_root, lapx, password="强密码123")
        assert matter == "matter-001"
        restored = MatterState.load(new_root, "matter-001").read_private()
        assert restored["entities"][0]["canonical_surface"] == "张三"
        # restored vault is DPAPI-sealed again
        blob = (new_root / "matter-001" / "private.dpapi").read_bytes()
        assert "张三".encode("utf-8") not in blob

    def test_wrong_password_uniform_failure(self, tmp_path, state):
        lapx = tmp_path / "matter-001.lapx"
        export_portable(state, "matter-001", lapx, password="correct-password")
        with pytest.raises(PortableError) as exc:
            import_portable(tmp_path / "r2", lapx, password="wrong-password")
        assert "authentication failed" in str(exc.value)

    def test_tampered_file_same_failure(self, tmp_path, state):
        lapx = tmp_path / "matter-001.lapx"
        export_portable(state, "matter-001", lapx, password="correct-password")
        doc = json.loads(lapx.read_text(encoding="utf-8"))
        raw = bytearray(base64.b64decode(doc["ciphertext_b64"]))
        raw[0] ^= 0xFF
        doc["ciphertext_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
        lapx.write_text(json.dumps(doc), encoding="utf-8")
        with pytest.raises(PortableError) as wrong_pw:
            import_portable(tmp_path / "r3", lapx, password="wrong-password")
        with pytest.raises(PortableError) as right_pw:
            import_portable(tmp_path / "r4", lapx, password="correct-password")
        # uniform error: tamper and wrong password are indistinguishable
        assert str(wrong_pw.value) == str(right_pw.value)

    def test_import_refuses_existing_matter(self, tmp_path, state):
        lapx = tmp_path / "matter-001.lapx"
        export_portable(state, "matter-001", lapx, password="pw123456789")
        with pytest.raises(PortableError, match="already exists"):
            import_portable(state, lapx, password="pw123456789")
