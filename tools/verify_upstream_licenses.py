"""Verify that every upstream in upstream.lock.json has license/usage entries and
that no excluded dependency (e.g. AGPL PyMuPDF) is declared in pyproject.toml."""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ("pymupdf", "fitz")


def main() -> int:
    lock = json.loads((ROOT / "upstream.lock.json").read_text(encoding="utf-8"))
    problems: list[str] = []
    for entry in lock["upstreams"]:
        for field in ("repository", "commit", "license", "usage"):
            if not entry.get(field):
                problems.append(f"upstream {entry.get('repository')}: missing {field}")
    if not lock["upstreams"]:
        problems.append("upstream.lock.json has no entries")
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = list(pyproject["project"].get("dependencies", []))
    for extra in pyproject["project"].get("optional-dependencies", {}).values():
        deps.extend(extra)
    for dep in deps:
        low = dep.lower()
        for bad in FORBIDDEN:
            if bad in low:
                problems.append(f"forbidden dependency in pyproject.toml: {dep}")
    if problems:
        print("FAIL")
        for p in problems:
            print(" -", p)
        return 1
    print(f"PASS: {len(lock['upstreams'])} upstreams registered, no forbidden dependencies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
