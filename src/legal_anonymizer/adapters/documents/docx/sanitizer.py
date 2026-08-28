"""DOCX tree policy application, cross-run replacement and package writer."""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

from lxml import etree

from .parser import NS, W_NS, XML_NS, PartTape, _build_tape

_HIDDEN_POLICY_ACTIONS = {
    "KEEP_AND_SANITIZE",
    "FLATTEN_CURRENT_VIEW",
    "DROP_WITH_RECEIPT",
    "BLOCK",
}


class DocxPolicyError(ValueError):
    error_code = "hidden_content_unresolved"


def apply_hidden_policy(tape: PartTape, action: str) -> None:
    """Apply the user's hidden-content decision to one part tree."""
    W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    if action == "KEEP_AND_SANITIZE":
        # authors inside kept hidden content are personal data: blank them
        for el in tape.tree.iter():
            if el.get(f"{W}author") is not None:
                el.set(f"{W}author", "")
        return
    if action == "FLATTEN_CURRENT_VIEW":
        tree = tape.tree
        for del_el in tree.xpath("//w:del", namespaces=NS):
            del_el.getparent().remove(del_el)
        for del_text in tree.xpath("//w:delText", namespaces=NS):
            parent = del_text.getparent()
            parent.remove(del_text)
        for ins_el in tree.xpath("//w:ins", namespaces=NS):
            parent = ins_el.getparent()
            for child in list(ins_el):
                parent.append(child)
            parent.remove(ins_el)
        for tag in ("commentRangeStart", "commentRangeEnd", "commentReference"):
            for el in tree.xpath(f"//w:{tag}", namespaces=NS):
                el.getparent().remove(el)
        return
    if action == "BLOCK":
        raise DocxPolicyError("hidden content policy BLOCK")
    raise DocxPolicyError(f"unknown hidden content action: {action}")


def replace_in_tree(tape: PartTape, start: int, end: int, replacement: str) -> None:
    """Cross-run span replacement on the part's logical text. The first overlapped
    node keeps the prefix and carries the replacement, middle nodes are cleared,
    the last node keeps the suffix. xml:space=preserve is set when required."""
    overlapped = [
        n for n in tape.nodes
        if n.start < end and start < n.end and (n.end > n.start or replacement)
    ]
    if not overlapped:
        return
    first = overlapped[0]
    last = overlapped[-1]
    tree_nodes = list(tape.tree.iter(f"{{{W_NS}}}t"))
    for node in overlapped:
        element = tree_nodes[node.node_index]
        text = element.text or ""
        if node is first and node is last:
            new_text = text[: start - node.start] + replacement + text[end - node.start :]
        elif node is first:
            new_text = text[: start - node.start] + replacement
        elif node is last:
            new_text = text[end - node.start :]
        else:
            new_text = ""
        element.text = new_text
        if new_text != new_text.strip():
            element.set(f"{{{XML_NS}}}space", "preserve")


def clear_metadata(core_xml: bytes) -> bytes:
    """Blank identifying metadata in docProps/core.xml."""
    if not core_xml:
        return core_xml
    tree = etree.fromstring(core_xml)
    DC = "http://purl.org/dc/elements/1.1/"
    CP = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    for tag in (f"{{{DC}}}creator", f"{{{DC}}}lastModifiedBy", f"{{{CP}}}lastModifiedBy"):
        for el in tree.iter(tag):
            el.text = ""
    for el in tree.iter(f"{{{CP}}}revision"):
        el.text = "1"
    return etree.tostring(tree, xml_declaration=True, encoding="UTF-8", standalone=True)


def write_docx(src: Path, dst: Path, modified_parts: dict[str, bytes],
               dropped_parts: set[str]) -> None:
    """Rebuild the package: unmodified entries byte-identical, modified parts
    replaced, dropped parts removed (drop must be recorded in the receipt)."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(
        dst, "w", zipfile.ZIP_DEFLATED
    ) as zout:
        for info in zin.infolist():
            if info.filename in dropped_parts:
                continue
            data = modified_parts.get(info.filename, zin.read(info.filename))
            zout.writestr(info, data)


def refresh_tape(tape: PartTape) -> PartTape:
    """Rebuild the tape after tree mutation (policy or replacement)."""
    return _build_tape(tape.part, tape.tree)
