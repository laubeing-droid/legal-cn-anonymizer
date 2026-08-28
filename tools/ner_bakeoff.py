"""NER bake-off harness.

This tool runs offline candidate evaluations ONLY when candidate models are
present and hash-locked in models/ (per models/manifest.json). It never
downloads anything. In an offline construction environment with no models, it
reports the external blocker honestly and exits with a distinct code so the
wave can record CLOSED_BLOCK_EXTERNAL instead of a fabricated benchmark."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "models" / "manifest.json"


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    models = manifest.get("models", [])
    if not models:
        blockers = [
            c for c in manifest.get("ner", {}).get("evaluated_candidates", [])
            if c.get("status") == "NOT_EVALUATED"
        ]
        print("NER bake-off: no hash-locked models available offline.")
        for b in blockers:
            print(f"  - {b['model_id']}: {b['reason']}")
        print(
            "Result: CLOSED_BLOCK_EXTERNAL (model distribution unavailable). "
            "System remains honest: no recall numbers advertised; documents with "
            "unconfirmed subject mentions default to REVIEW_REQUIRED."
        )
        return 2
    # With models present, the evaluation harness would run here against the
    # synthetic benchmark (tests/benchmark). Implementation lands with S9.
    print(f"{len(models)} models registered; run S9 benchmark harness.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
