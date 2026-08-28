"""Build the Windows onedir portable bundle with PyInstaller.

Includes: package code, schemas, profiles, model manifest, consumer protocol
fixtures reference. Excludes: dev/test private fixtures, private keys, user
matter state, cloud extras. The onedir layout (never one-file) avoids runtime
self-extraction into temp directories."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def main() -> int:
    entry = ROOT / "tools" / "anonymizer_entry.py"
    if not entry.exists():
        entry.write_text(
            "from legal_anonymizer.cli import main\n\n"
            "if __name__ == '__main__':\n"
            "    raise SystemExit(main())\n",
            encoding="utf-8",
        )
    work = ROOT / "build" / "pyinstaller"
    name = "legal-anonymizer-windows-x64"
    target = DIST / name
    if target.exists():
        shutil.rmtree(target)
    command = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onedir", "--name", name,
        "--workpath", str(work), "--distpath", str(DIST),
        "--specpath", str(work),
        "--hidden-import", "legal_anonymizer.cli",
        "--hidden-import", "legal_anonymizer.adapters.documents.markdown",
        "--hidden-import", "legal_anonymizer.adapters.documents.docx.parser",
        "--hidden-import", "legal_anonymizer.adapters.documents.pdf.pdfium_parser",
        "--hidden-import", "legal_anonymizer.adapters.ocr.rapidocr",
        "--hidden-import", "rapidocr",
        "--collect-all", "rapidocr",
        "--collect-data", "legal_anonymizer",
        str(entry),
    ]
    completed = subprocess.run(command, check=False, cwd=ROOT)
    if completed.returncode != 0:
        print("FAIL: PyInstaller returned", completed.returncode)
        return 1
    marker = target / "PORTABLE.md"
    marker.write_text(
        "# legal-cn-anonymizer portable (onedir)\n\n"
        "Offline local tool. No network. No private keys and no user matter\n"
        "state are shipped in this bundle; matter state is created per user\n"
        "under %LOCALAPPDATA%\\\\LegalAnonymizer and sealed with DPAPI.\n",
        encoding="utf-8",
    )
    print(f"PASS: {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
