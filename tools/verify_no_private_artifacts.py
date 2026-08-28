"""Verify that no private artifacts (keys, user state, seam files) exist in
dist/ or inside distribution zips."""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

FORBIDDEN_NAMES = ("*.dpapi", "private.seam.json", "private.dpapi",
                   "*.lapx", "identity", "*.key")
FORBIDDEN_MARKERS = (b"BEGIN PRIVATE KEY", b"matter_secret_b64")


def main() -> int:
    problems = []
    if not DIST.exists():
        print("PASS: no dist directory (nothing built)")
        return 0
    for f in DIST.rglob("*"):
        for pattern in FORBIDDEN_NAMES:
            if f.match(pattern):
                problems.append(f"forbidden path: {f.relative_to(DIST)}")
        # .py source legitimately contains key NAMES; only data files can
        # contain key VALUES
        if f.is_file() and f.suffix in (".json", ".md", ".txt"):
            try:
                data = f.read_bytes()
            except OSError:
                continue
            for marker in FORBIDDEN_MARKERS:
                if marker in data:
                    problems.append(f"{f.relative_to(DIST)} contains {marker!r}")
        if f.is_file() and f.suffix in (".zip", ".whl"):
            with zipfile.ZipFile(f) as zf:
                for name in zf.namelist():
                    for pattern in FORBIDDEN_NAMES:
                        if Path(name).match(pattern):
                            problems.append(f"{f.name}: forbidden entry {name}")
                    if name.endswith(".json") and not name.endswith(".py"):
                        data = zf.read(name)
                        for marker in FORBIDDEN_MARKERS:
                            if marker in data:
                                problems.append(f"{f.name}/{name}: contains {marker!r}")
    if problems:
        print("FAIL")
        for p in problems:
            print(" -", p)
        return 1
    print("PASS: no private artifacts in dist/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
