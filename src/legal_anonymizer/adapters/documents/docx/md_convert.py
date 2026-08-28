"""DOCX -> AI Markdown converter (post-sanitization structure walk)."""

from __future__ import annotations

from lxml import etree

from .parser import NS, W_NS


def _para_text(p) -> str:
    return "".join(t.text or "" for t in p.iter(f"{{{W_NS}}}t"))


def _para_style(p) -> str:
    styles = p.xpath("./w:pPr/w:pStyle/@w:val", namespaces=NS)
    return styles[0] if styles else ""


def docx_tree_to_markdown(tree) -> str:
    lines: list[str] = []
    body = tree.find(f"{{{W_NS}}}body")
    if body is None:
        body = tree

    def walk(parent):
        for child in parent:
            tag = child.tag
            if tag == f"{{{W_NS}}}p":
                text = _para_text(child)
                style = _para_style(child)
                if style.startswith("Heading1") or style == "1":
                    lines.append(f"# {text}")
                elif style.startswith("Heading2") or style == "2":
                    lines.append(f"## {text}")
                elif style.startswith("Heading3") or style == "3":
                    lines.append(f"### {text}")
                elif text.strip():
                    lines.append(text)
                else:
                    lines.append("")
            elif tag == f"{{{W_NS}}}tbl":
                for tr in child.iter(f"{{{W_NS}}}tr"):
                    cells = [_para_text(tc) for tc in tr.findall(f"{{{W_NS}}}tc")]
                    lines.append("| " + " | ".join(cells) + " |")
                lines.append("")
            elif tag in (f"{{{W_NS}}}sdt", f"{{{W_NS}}}sdtContent"):
                walk(child)

    walk(body)
    return "\n".join(lines) + "\n"
