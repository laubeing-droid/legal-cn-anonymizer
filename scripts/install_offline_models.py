"""Offline model installation for consumer machines (V42-R2 item 6).

The ONLY supported way to bring NER weights onto a machine. There is no
network path: weights arrive as an offline pack (directory or zip with the
same layout as ``models/`` — ``manifest.json`` plus ``ner/<asset>/`` files)
and are verified against the hash lock in ``models/manifest.json →
ner.release_models`` (per-file sha256 + size). Packaging boundary (S12,
unchanged): wheels/sdists/onedir never contain weights; this script is the
pre-install channel.

Usage (cwd = repo root or anywhere):
    python scripts/install_offline_models.py                 # verify only
    python scripts/install_offline_models.py --source pack.zip
    python scripts/install_offline_models.py --source ./model-pack/

Exit codes: 0 verified/installed+verified; 1 named failure (every gap is
listed: asset, file, missing / hash_mismatch / size_mismatch); 2 bad
invocation. Never downloads; never prints file contents — paths and digests
only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = ROOT / "models"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_zip(source: Path) -> Path:
    """Extract a zip model pack into a temp dir (zip-slip guarded) and return
    the pack root (the directory that contains manifest.json)."""
    tmp = Path(tempfile.mkdtemp(prefix="anon-models-"))
    with zipfile.ZipFile(source) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                raise ValueError(f"unsafe zip entry: {info.filename}")
            target = (tmp / name).resolve()
            if not target.is_relative_to(tmp.resolve()):
                raise ValueError(f"zip entry escapes pack root: {info.filename}")
        zf.extractall(tmp)
    if (tmp / "manifest.json").exists():
        return tmp
    inner = [p for p in tmp.iterdir() if p.is_dir() and (p / "manifest.json").exists()]
    if len(inner) == 1:
        return inner[0]
    raise ValueError("model pack has no manifest.json at its root")


def _install(source: Path, accept_manifest: bool) -> None:
    """Copy the pack (manifest.json + ner/) into <repo>/models/. Existing
    files are overwritten by the pack; nothing else is touched. The hash lock
    is anchored on the REPO's manifest: overwriting an existing lock requires
    an explicit --accept-manifest (a pack cannot silently re-pin its own
    hashes); files that mismatch the standing lock fail verification."""
    manifest = source / "manifest.json"
    if not manifest.is_file():
        raise ValueError(f"model pack has no manifest.json: {source}")
    json.loads(manifest.read_text(encoding="utf-8"))  # must parse before install
    standing = MODELS_DIR / "manifest.json"
    if standing.is_file() and not accept_manifest:
        # keep the installed lock as the trust anchor; incoming files must
        # match it or verification names the gap
        print("keeping existing models/manifest.json as the hash lock "
              "(pass --accept-manifest to re-pin from the pack)")
    else:
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(manifest, standing)
    src_ner = source / "ner"
    if src_ner.is_dir():
        dst_ner = MODELS_DIR / "ner"
        dst_ner.mkdir(parents=True, exist_ok=True)
        for asset_dir in sorted(src_ner.iterdir()):
            if asset_dir.is_dir():
                shutil.copytree(asset_dir, dst_ner / asset_dir.name,
                                dirs_exist_ok=True)


def _verify() -> list[str]:
    """Full (non-short-circuit) hash-lock verification. Returns a list of
    named problems; empty list means every locked file matches."""
    manifest_file = MODELS_DIR / "manifest.json"
    if not manifest_file.is_file():
        return ["models/manifest.json missing — no hash lock to verify against"]
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return [f"models/manifest.json unreadable: {type(exc).__name__}"]
    entries = manifest.get("ner", {}).get("release_models", [])
    if not entries:
        return ["models/manifest.json has no ner.release_models entries"]
    problems: list[str] = []
    for entry in entries:
        asset_id = entry.get("asset_id", "?")
        base = ROOT / entry.get("local_dir", f"models/ner/{asset_id}")
        files = entry.get("files", {})
        if not files:
            problems.append(f"[{asset_id}] no locked files recorded")
            continue
        for name, locked in sorted(files.items()):
            path = base / name
            if not path.is_file():
                problems.append(
                    f"[{asset_id}] {name}: missing "
                    f"(expected sha256 {str(locked.get('sha256', ''))[:12]}…)")
                continue
            actual_size = path.stat().st_size
            want_size = locked.get("bytes")
            if want_size is not None and actual_size != want_size:
                problems.append(
                    f"[{asset_id}] {name}: size_mismatch "
                    f"(expected {want_size}, found {actual_size})")
                continue
            digest = _sha256(path)
            want = str(locked.get("sha256", ""))
            if want and digest != want:
                problems.append(
                    f"[{asset_id}] {name}: hash_mismatch "
                    f"(expected {want[:12]}…, found {digest[:12]}…)")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install and hash-verify offline NER model packs "
                    "(no network; wheels never carry weights).")
    parser.add_argument("--source", help="offline pack directory or .zip "
                                         "(layout: manifest.json + ner/)")
    parser.add_argument("--accept-manifest", action="store_true",
                        help="re-pin the hash lock from the pack's manifest.json "
                             "(required only when models/manifest.json already exists)")
    args = parser.parse_args(argv)

    try:
        if args.source:
            source = Path(args.source)
            if not source.exists():
                print(f"FAIL: source not found: {source}", file=sys.stderr)
                return 2
            if source.suffix.lower() == ".zip":
                pack_root = _extract_zip(source)
            else:
                pack_root = source
            _install(pack_root, args.accept_manifest)
            print(f"installed pack from {source} -> {MODELS_DIR}")
    except (ValueError, OSError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    problems = _verify()
    if problems:
        print("FAIL: model hash-lock verification failed:")
        for problem in problems:
            print(f"  - {problem}")
        print("offline install is REQUIRED before NER-dependent release runs; "
              "the product fails closed (CLOSED_BLOCK/model_unavailable) until then.")
        return 1
    manifest = json.loads((MODELS_DIR / "manifest.json").read_text(encoding="utf-8"))
    total = 0
    print("PASS: model hash-lock verified:")
    for entry in manifest.get("ner", {}).get("release_models", []):
        size = sum(int(f.get("bytes", 0)) for f in entry.get("files", {}).values())
        total += size
        print(f"  - {entry['asset_id']} ({entry['model_id']} @ "
              f"{entry['revision'][:12]}): {len(entry.get('files', {}))} files, "
              f"{size / 1e6:.1f} MB")
    print(f"total {total / 1e9:.2f} GB — models available offline; "
          f"runtime stays zero-network.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
