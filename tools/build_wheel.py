"""Build the wheel + sdist into dist/."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    completed = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--sdist",
         "--outdir", str(dist), str(ROOT)],
        check=False,
    )
    if completed.returncode != 0:
        print("FAIL: python -m build returned", completed.returncode)
        return 1
    wheels = list(dist.glob("legal_cn_anonymizer-*.whl"))
    sdists = list(dist.glob("legal_cn_anonymizer-*.tar.gz"))
    print(f"PASS: {wheels} {sdists}")
    return 0 if wheels and sdists else 1


if __name__ == "__main__":
    sys.exit(main())
