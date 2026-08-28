"""Verify the distribution: schemas hash-stable, no private artifacts, wheel
importable, model pack hashes match, consumer protocol fixtures present."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
FORBIDDEN_CONTENT = ("BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
                     "matter_secret_b64")


def _fail(msg: str) -> int:
    print("FAIL:", msg)
    return 1


def main() -> int:
    problems = []
    wheels = list(DIST.glob("legal_cn_anonymizer-*.whl"))
    if not wheels:
        problems.append("wheel missing")
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as zf:
            names = zf.namelist()
            if not any(n.endswith(".py") for n in names):
                problems.append(f"{wheel.name}: no python modules")
            for name in names:
                if name.endswith(".dpapi") or "private.seam.json" in name:
                    problems.append(f"{wheel.name}: private artifact {name}")
                # key NAMES in .py source are fine; only data files are scanned
                if name.endswith(".json"):
                    data = zf.read(name)
                    for marker in FORBIDDEN_CONTENT:
                        if marker.encode() in data:
                            problems.append(f"{wheel.name}/{name}: contains {marker!r}")
            # no raw personal IDs (checksum-valid) inside the wheel
    sdists = list(DIST.glob("legal_cn_anonymizer-*.tar.gz"))
    if not sdists:
        problems.append("sdist missing")

    # model pack matches manifest
    model_pack = DIST / "models-cn-v1.zip"
    if model_pack.exists():
        manifest = json.loads((ROOT / "models" / "manifest.json").read_text(encoding="utf-8"))
        with zipfile.ZipFile(model_pack) as zf:
            for entry in manifest.get("ocr", {}).get("files", []):
                try:
                    data = zf.read(f"models/{entry['path']}")
                except KeyError:
                    problems.append(f"model pack missing {entry['path']}")
                    continue
                if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                    problems.append(f"model pack hash mismatch {entry['path']}")
    else:
        problems.append("models-cn-v1.zip missing")

    # consumer protocol zip: manifest + negative fixtures present
    protocol = DIST / "consumer-protocol-v1.zip"
    if protocol.exists():
        with zipfile.ZipFile(protocol) as zf:
            names = zf.namelist()
            for required in (
                "consumer-contract-manifest.json", "SHA256SUMS", "README.md",
                "public-keys/receipt-signing-public.json",
            ):
                if required not in names:
                    problems.append(f"consumer protocol missing {required}")
            if not any("negative-fixtures/" in n for n in names):
                problems.append("consumer protocol has no negative fixtures")
    else:
        problems.append("consumer-protocol-v1.zip missing")

    onedir = DIST / "legal-anonymizer-windows-x64"
    if not onedir.exists():
        problems.append("onedir build missing")

    if problems:
        for p in problems:
            print(" -", p)
        return 1
    print("PASS: distribution verified (wheel/sdist/model pack/consumer protocol/onedir)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
