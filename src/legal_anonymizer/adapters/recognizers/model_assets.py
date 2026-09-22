"""Hash-locked local NER model assets (S-v42).

Models are NEVER downloaded at runtime. An asset is available only when every
locked file exists locally and matches its pinned sha256. Any gap reports
(unavailable, named reason) so callers degrade to REVIEW_REQUIRED instead of
silently pretending the rules-only path is release-qualified.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

_VERIFIED: dict[str, tuple[str, str]] = {}  # rel path -> (repo_root marker, "ok")


@dataclass(frozen=True)
class NerAsset:
    asset_id: str
    model_id: str
    revision: str
    local_dir: str
    files: dict[str, dict[str, int | str]] = field(default_factory=dict)

    def check(self, repo_root: Path) -> tuple[bool, str]:
        base = repo_root / self.local_dir
        for name, locked in sorted(self.files.items()):
            path = base / name
            key = str(path.resolve())
            marker = str(repo_root)
            if _VERIFIED.get(key) == (marker, "ok"):
                continue
            if not path.is_file():
                return False, f"model asset file missing: {self.local_dir}/{name}"
            want = str(locked.get("sha256", ""))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if want and digest != want:
                return False, (
                    f"model asset digest mismatch: {self.local_dir}/{name}"
                )
            _VERIFIED[key] = (marker, "ok")
        return True, "ok"


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "models" / "manifest.json").exists():
            return parent
    return Path.cwd()


def manifest_path() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "models" / "manifest.json"
        if candidate.exists():
            return candidate
    return None


def load_ner_assets() -> list[NerAsset]:
    path = manifest_path()
    if path is None:
        return []
    manifest = json.loads(path.read_text(encoding="utf-8"))
    assets = []
    for entry in manifest.get("ner", {}).get("release_models", []):
        assets.append(
            NerAsset(
                asset_id=entry["asset_id"],
                model_id=entry["model_id"],
                revision=entry["revision"],
                local_dir=entry["local_dir"],
                files=entry.get("files", {}),
            )
        )
    return assets


def find_asset(asset_id: str) -> NerAsset | None:
    for asset in load_ner_assets():
        if asset.asset_id == asset_id:
            return asset
    return None


def check_asset(asset_id: str) -> tuple[bool, str]:
    asset = find_asset(asset_id)
    if asset is None:
        return False, f"no locked asset {asset_id!r} in models/manifest.json"
    ok, reason = asset.check(repo_root())
    return ok, reason


def import_ok(module: str) -> bool:
    import importlib.util

    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def spacy_model_installed(model_name: str) -> bool:
    try:
        from spacy.util import get_installed_models

        return model_name in get_installed_models()
    except Exception:  # noqa: BLE001 - any spacy failure is "not installed"
        return False
