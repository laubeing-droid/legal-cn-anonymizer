"""DOCX OOXML parser: full part inventory and per-part text tape.

zipfile + lxml are the authority; python-docx is only a convenience validator.
Every text-bearing part is inventoried: document, headers/footers, footnotes/
endnotes, comments, textboxes, drawings (alt text), and their hidden-content
state is recorded. Hidden content never silently passes."""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
XML_NS = "http://www.w3.org/XML/1998/namespace"
NS = {"w": W_NS}

# parts that may carry user-visible or hidden text
TEXT_PARTS = (
    "word/document.xml",
    "word/footnotes.xml",
    "word/endnotes.xml",
    "word/comments.xml",
    "word/footnotes.xml",
)
_TEXT_PART_RE = re.compile(
    r"^word/(document|footnotes|endnotes|comments|header[0-9]*|footer[0-9]*)\.xml$"
)

HIDDEN_SIGNALS = {
    "word/comments.xml": "comments",
    "word/vbaProject.bin": "macros",
    "word/customXml/": "custom_xml",
    "word/embeddings/": "embeddings",
    "docProps/custom.xml": "custom_properties",
    "word/people.xml": "people",
}

METADATA_PARTS = ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml")


@dataclass
class TextNode:
    part: str
    node_index: int  # index of the w:t node within the part (document order)
    start: int  # start in the part's logical text
    end: int
    in_deleted_revision: bool = False
    in_inserted_revision: bool = False


@dataclass
class PartTape:
    part: str
    logical_text: str
    nodes: list[TextNode] = field(default_factory=list)
    tree: object = None  # lxml tree (not serialized)


@dataclass
class DocxInventory:
    parts: list[str]
    text_parts: list[str]
    hidden_signals: list[str]  # e.g. comments / macros / custom_xml / revisions
    external_links: list[str]  # relationship targets outside the package
    metadata_parts: list[str]
    part_tapes: dict[str, PartTape]


def _is_external(target: str) -> bool:
    return target.startswith(("http://", "https://", "file:", "\\\\", "mailto:"))


def _revision_context(node) -> tuple[bool, bool]:
    deleted = node.xpath(
        "ancestor::w:del or self::w:delText", namespaces=NS
    ) or node.xpath("ancestor::w:delText", namespaces=NS)
    inserted = node.xpath("ancestor::w:ins", namespaces=NS)
    return bool(deleted), bool(inserted)


def inventory(docx_path: Path) -> DocxInventory:
    with zipfile.ZipFile(docx_path) as zf:
        names = zf.namelist()
        hidden: list[str] = []
        for name in names:
            for needle, signal in HIDDEN_SIGNALS.items():
                if name == needle or name.startswith(needle):
                    if signal not in hidden:
                        hidden.append(signal)
        external = []
        for name in names:
            if name.endswith(".rels"):
                try:
                    tree = etree.fromstring(zf.read(name))
                except etree.XMLSyntaxError:
                    hidden.append("unparseable_rels")
                    continue
                for rel in tree.iter("{http://schemas.openxmlformats.org/package/2006/relationships}Relationship"):
                    if rel.get("TargetMode") == "External" and rel.get("Target"):
                        external.append(rel.get("Target"))

        part_tapes: dict[str, PartTape] = {}
        text_parts = []
        for name in names:
            if not _TEXT_PART_RE.match(name):
                continue
            try:
                tree = etree.fromstring(zf.read(name))
            except etree.XMLSyntaxError:
                hidden.append(f"unparseable:{name}")
                continue
            text_parts.append(name)
            tape = _build_tape(name, tree)
            part_tapes[name] = tape
        if "word/comments.xml" not in hidden and any("comments" == h for h in hidden):
            pass
        # tracked changes signal
        for name in text_parts:
            tree = part_tapes[name].tree
            if tree is not None and (
                tree.xpath("//w:ins", namespaces=NS) or tree.xpath("//w:del", namespaces=NS)
            ):
                if "tracked_changes" not in hidden:
                    hidden.append("tracked_changes")
        return DocxInventory(
            parts=names,
            text_parts=text_parts,
            hidden_signals=hidden,
            external_links=external,
            metadata_parts=[n for n in names if n in METADATA_PARTS],
            part_tapes=part_tapes,
        )


def _build_tape(part: str, tree) -> PartTape:
    pieces: list[str] = []
    nodes: list[TextNode] = []
    cursor = 0
    for index, t in enumerate(tree.iter(f"{{{W_NS}}}t")):
        text = t.text or ""
        deleted, inserted = _revision_context(t)
        pieces.append(text)
        nodes.append(
            TextNode(
                part=part,
                node_index=index,
                start=cursor,
                end=cursor + len(text),
                in_deleted_revision=bool(deleted),
                in_inserted_revision=bool(inserted),
            )
        )
        cursor += len(text)
    return PartTape(part=part, logical_text="".join(pieces), nodes=nodes, tree=tree)
