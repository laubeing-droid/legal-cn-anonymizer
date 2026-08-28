"""Build provenance.json: source commit, build environment, artifact digests."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=False, cwd=ROOT
    )
    return completed.stdout.strip()


def _version() -> str:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    attr = pyproject["tool"]["setuptools"]["dynamic"]["version"]["attr"]
    if ":" in attr:
        package, attr_name = attr.split(":", 1)
    else:
        package, attr_name = attr.rsplit(".", 1)
    src = ROOT / "src"
    sys.path.insert(0, str(src))
    try:
        module = __import__(package, fromlist=[attr_name])
        return getattr(module, attr_name)
    finally:
        sys.path.remove(str(src))


def main() -> int:
    artifacts = {}
    for f in sorted(DIST.rglob("*")):
        if f.is_file() and f.name not in ("provenance.json",):
            rel = f.relative_to(DIST).as_posix()
            artifacts[rel] = {
                "sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
                "bytes": f.stat().st_size,
            }
    provenance = {
        "schema_version": "1.0",
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "package": "legal-cn-anonymizer",
        "package_version": _version(),
        "source": {
            "repository": "legal-cn-anonymizer (fork of fishonbike/vault-engine)",
            "git_commit": _git("rev-parse", "HEAD"),
            "git_tree": _git("rev-parse", "HEAD^{tree}"),
            "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
            "upstream_lock": json.loads(
                (ROOT / "upstream.lock.json").read_text(encoding="utf-8")
            ),
        },
        "build_environment": {
            "python": platform.python_version(),
            "os": platform.platform(),
            "machine": platform.machine(),
        },
        "artifacts": artifacts,
        "source_date_epoch": "0",
    }
    out = DIST / "provenance.json"
    out.write_text(json.dumps(provenance, ensure_ascii=False, indent=2) + "\n",
                   encoding="utf-8")
    print(f"PASS: {out} ({len(artifacts)} artifacts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
