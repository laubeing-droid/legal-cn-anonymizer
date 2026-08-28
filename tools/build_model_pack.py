"""Build the offline model pack (models-cn-v1.zip) with hash-verified contents."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    manifest_path = ROOT / "models" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    target = dist / "models-cn-v1.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(manifest_path, "models/manifest.json")
        for entry in manifest.get("ocr", {}).get("files", []):
            f = ROOT / "models" / entry.get("repo_path", entry["path"])
            if not f.exists():
                print(f"FAIL: model file missing: {entry['path']}")
                return 1
            digest = hashlib.sha256(f.read_bytes()).hexdigest()
            if digest != entry["sha256"]:
                print(f"FAIL: model hash mismatch: {entry['path']}")
                return 1
            zf.write(f, f"models/{entry['path']}")
    print(f"PASS: {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
