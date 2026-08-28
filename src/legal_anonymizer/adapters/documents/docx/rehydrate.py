"""DOCX rehydrate: restore display aliases inside a sanitized DOCX package."""

from __future__ import annotations

import zipfile
from pathlib import Path

from lxml import etree

from .parser import W_NS
from .sanitizer import write_docx


def rehydrate_docx(src: Path, dst: Path, pairs: list[tuple[str, str]]) -> int:
    """Replace alias -> real surface inside every text part of the package.
    Aliases were written into a single run by the sanitizer, so node-level
    replacement is sufficient. Returns the number of replacements."""
    ordered = sorted(pairs, key=lambda p: -len(p[0]))
    total = 0
    modified: dict[str, bytes] = {}
    with zipfile.ZipFile(src) as zin:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename.startswith("word/") and info.filename.endswith(".xml"):
                try:
                    tree = etree.fromstring(data)
                except etree.XMLSyntaxError:
                    continue
                count = 0
                for t in tree.iter(f"{{{W_NS}}}t"):
                    text = t.text or ""
                    if not text:
                        continue
                    for alias, surface in ordered:
                        if alias in text:
                            count += text.count(alias)
                            text = text.replace(alias, surface)
                    t.text = text
                if count:
                    total += count
                    modified[info.filename] = etree.tostring(
                        tree, xml_declaration=True, encoding="UTF-8", standalone=True
                    )
        write_docx(src, dst, modified, set())
    return total
