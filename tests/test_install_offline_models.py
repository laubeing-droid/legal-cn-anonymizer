"""Offline model install script tests (V42-R2 item 6).

Synthetic packs only: tiny files standing in for weights, locked by a
generated manifest. Covers: verify-only PASS, verify-only named failures,
zip and directory installs, the standing-lock anchor (a pack cannot silently
re-pin its own hashes), zip-slip refusal, and the total-absence failure.
The real script is loaded from scripts/ by file path (scripts/ is not a
package).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install_offline_models.py"
_SPEC = importlib.util.spec_from_file_location("install_offline_models", _SCRIPT)
install_models = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(install_models)


def _asset_files(tmp_path: Path, asset: str, files: dict[str, bytes]) -> dict:
    asset_dir = tmp_path / "ner" / asset
    asset_dir.mkdir(parents=True)
    locked = {}
    for name, content in files.items():
        (asset_dir / name).write_bytes(content)
        locked[name] = {"sha256": hashlib.sha256(content).hexdigest(),
                        "bytes": len(content)}
    return locked


def _make_pack(tmp_path: Path, name: str = "pack",
               weights_content: bytes = b"W" * 128) -> Path:
    root = tmp_path / name
    root.mkdir()
    manifest = {
        "manifest_version": "1.0",
        "ner": {"release_models": [
            {"asset_id": "tiny-a", "model_id": "org/tiny-a", "revision": "r" * 40,
             "local_dir": "models/ner/tiny-a",
             "files": _asset_files(root, "tiny-a",
                                   {"config.json": b'{"x":1}',
                                    "weights.bin": weights_content})},
        ]},
    }
    (root / "manifest.json").write_text(json.dumps(manifest), "utf-8")
    return root


@pytest.fixture()
def fake_repo(tmp_path, monkeypatch):
    """Point the script module at a synthetic repo root."""
    monkeypatch.setattr(install_models, "ROOT", tmp_path)
    monkeypatch.setattr(install_models, "MODELS_DIR", tmp_path / "models")
    return tmp_path


def test_verify_fails_named_when_nothing_installed(fake_repo):
    rc = install_models.main([])
    assert rc == 1
    assert "missing" in str(install_models._verify()[0])


def test_install_from_directory_and_verify_pass(fake_repo, capsys):
    pack = _make_pack(fake_repo)
    rc = install_models.main(["--source", str(pack)])
    assert rc == 0, capsys.readouterr().err
    assert (fake_repo / "models" / "ner" / "tiny-a" / "weights.bin").read_bytes() == b"W" * 128
    out = capsys.readouterr().out
    assert "PASS" in out and "tiny-a" in out


def test_install_from_zip_and_verify_pass(fake_repo):
    pack = _make_pack(fake_repo)
    zip_path = fake_repo / "pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for p in sorted(pack.rglob("*")):
            zf.write(p, p.relative_to(pack).as_posix())
    rc = install_models.main(["--source", str(zip_path)])
    assert rc == 0


def test_standing_lock_anchors_verification(fake_repo):
    """A pack whose own manifest re-pins different hashes cannot silently
    replace the standing lock — installed files must match the REPO lock."""
    pack = _make_pack(fake_repo)
    assert install_models.main(["--source", str(pack)]) == 0  # lock established
    # self-consistent but different pack: re-pins its own hashes
    tampered = _make_pack(fake_repo, name="pack2", weights_content=b"E" * 128)
    rc = install_models.main(["--source", str(tampered)])
    assert rc == 1                 # standing lock refuses the different payload
    problems = " ".join(install_models._verify())
    assert "hash_mismatch" in problems


def test_accept_manifest_repins_explicitly(fake_repo):
    _make_pack(fake_repo)
    repacked = _make_pack(fake_repo, name="pack2", weights_content=b"V2" * 64)
    rc = install_models.main(["--source", str(repacked), "--accept-manifest"])
    assert rc == 0  # explicit re-pin is honest; verification runs against it


def test_hash_mismatch_named_in_verify(fake_repo):
    pack = _make_pack(fake_repo)
    (pack / "ner" / "tiny-a" / "weights.bin").write_bytes(b"X" * 128)  # same size, other bytes
    install_models.main(["--source", str(pack)])
    problems = install_models._verify()
    assert any("hash_mismatch" in p and "tiny-a" in p for p in problems)


def test_zip_slip_refused(fake_repo, tmp_path):
    evil = fake_repo / "evil.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../escaped.json", "{}")
    rc = install_models.main(["--source", str(evil)])
    assert rc == 2
    assert not (fake_repo / "escaped.json").exists()


def test_missing_source_is_bad_invocation(fake_repo):
    assert install_models.main(["--source", str(fake_repo / "nope.zip")]) == 2
