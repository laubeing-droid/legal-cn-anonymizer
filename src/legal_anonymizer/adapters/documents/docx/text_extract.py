"""Extract user-visible text from an OOXML part for independent scanning:
element text (w:t, w:delText, comments...) plus privacy-relevant attributes
(alt text, author names, part names). Markup and namespace URIs are excluded."""

from __future__ import annotations

from lxml import etree

INTERESTING_ATTRIBUTES = (
    "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}author",
    "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}descr",
    "{http://schemas.openxmlformats.org/drawingml/2006/main}descr",
    "{http://schemas.openxmlformats.org/drawingml/2006/main}name",
)


def extract_part_text(xml_bytes: bytes) -> str:
    try:
        tree = etree.fromstring(xml_bytes)
    except etree.XMLSyntaxError:
        return ""
    pieces = list(tree.itertext())
    for el in tree.iter():
        for attr in INTERESTING_ATTRIBUTES:
            value = el.get(attr)
            if value:
                pieces.append(value)
    return "\n".join(p for p in pieces if p)
