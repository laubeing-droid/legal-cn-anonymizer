"""Build the consumer protocol pack zip into dist/consumer-protocol-v1.zip."""

from __future__ import annotations

import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    import tempfile

    dist = ROOT / "dist"
    from legal_anonymizer.application.consumer_protocol import build_consumer_protocol

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "consumer-protocol"
        state_root = Path(tmp) / "state"
        result = build_consumer_protocol(state_root, work)
        target = dist / "consumer-protocol-v1.zip"
        if target.exists():
            target.unlink()
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(work.rglob("*")):
                if f.is_file():
                    zf.write(f, f.relative_to(work))
    print(f"PASS: {target} ({result['examples']} examples, {result['negative_fixtures']} negatives)")
    return 0
    target = dist / "consumer-protocol-v1.zip"
    if target.exists():
        target.unlink()
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(work.rglob("*")):
            if f.is_file():
                zf.write(f, f.relative_to(work))



if __name__ == "__main__":
    sys.exit(main())
