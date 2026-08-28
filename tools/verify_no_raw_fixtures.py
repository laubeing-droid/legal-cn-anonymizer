"""Verify that no tracked file contains a checksum-valid 18-digit Chinese resident
ID, which would indicate real case data leaked into the repository. Synthetic
fixtures must use invalid-checksum numbers."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = ["src", "tests", "examples", "tools", "profiles", "models"]
ID18 = re.compile(
    r"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]"
)
WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
CODES = "10X98765432"


def checksum_ok(value: str) -> bool:
    total = sum(int(d) * w for d, w in zip(value[:17], WEIGHTS))
    return CODES[total % 11] == value[17].upper()


def main() -> int:
    problems: list[str] = []
    for scan_dir in SCAN_DIRS:
        base = ROOT / scan_dir
        if not base.exists():
            continue
        for f in base.rglob("*"):
            if f.suffix.lower() not in {
                ".py", ".md", ".txt", ".yaml", ".yml", ".json", ".toml",
            } or not f.is_file():
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
            for m in ID18.finditer(text):
                if checksum_ok(m.group(0)):
                    problems.append(
                        f"{f.relative_to(ROOT)}: checksum-valid 18-digit ID looks like real data"
                    )
    if problems:
        print("FAIL")
        for p in problems:
            print(" -", p)
        return 1
    print("PASS: no checksum-valid raw personal IDs in tracked data files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
