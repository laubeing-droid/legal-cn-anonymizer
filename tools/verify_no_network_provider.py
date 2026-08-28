"""Static tripwire: the package must not contain network provider imports, runtime
model-download calls, or telemetry hooks. A line containing
`# network-guard-allowlist` exempts a file (used only for the sanctioned offline
network guard test itself)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = ["src"]
IMPORTS = re.compile(
    r"^\s*(?:import|from)\s+(requests|httpx|aiohttp|urllib\.request|urllib3|"
    r"socket|ftplib|telnetlib|smtplib|huggingface_hub)\b",
    re.MULTILINE,
)
CALLS = re.compile(
    r"(?:urlopen\s*\(|requests\.(?:get|post)\s*\(|socket\.connect\s*\(|"
    r"snapshot_download\s*\()"
)
ALLOW = re.compile(r"#\s*network-guard-allowlist")


def main() -> int:
    problems: list[str] = []
    for scan_dir in SCAN_DIRS:
        for f in (ROOT / scan_dir).rglob("*.py"):
            text = f.read_text(encoding="utf-8", errors="ignore")
            if ALLOW.search(text):
                continue
            for m in IMPORTS.finditer(text):
                problems.append(f"{f.relative_to(ROOT)}: network import '{m.group(1)}'")
            for m in CALLS.finditer(text):
                problems.append(f"{f.relative_to(ROOT)}: network call pattern '{m.group(0).strip()}'")
    if problems:
        print("FAIL")
        for p in problems:
            print(" -", p)
        return 1
    print("PASS: no network provider imports or download calls in src/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
