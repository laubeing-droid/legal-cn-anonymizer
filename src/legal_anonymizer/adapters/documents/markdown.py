"""Markdown/Text TextTape. Every case-content element is data — instruction-like
content is flagged (AI_INSTRUCTION_LIKE_CONTENT), never dropped. Structure is
recorded so sanitization can preserve headings, tables, fences and links."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s")
_TABLE_RE = re.compile(r"^\s*\|.+\|\s*$")
_QUOTE_RE = re.compile(r"^\s{0,3}>\s")
_LIST_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")
_HTML_RE = re.compile(r"<[a-zA-Z!/][^>]*>")
_LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)\s]+)\)")
_URL_RE = re.compile(r"https?://[^\s)>\]]+")

_INJECTION_RE = re.compile(
    r"(?:ignore\s+(?:all\s+)?previous\s+instructions|system\s*prompt|"
    r"你(?:现在是|的角色)|忽略(?:之前|上面)(?:的)?(?:所有)?指令|"
    r"system\s*:|assistant\s*:|<\|?(?:im_start|system|endoftext)\|?>)",
    re.IGNORECASE,
)


@dataclass
class TapeSegment:
    kind: str  # heading | table_row | quote | list | fence | paragraph | html | blank
    line_no: int  # 1-based
    start: int
    end: int
    flags: tuple[str, ...] = ()


@dataclass
class TextTape:
    text: str
    segments: list[TapeSegment] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)

    def instruction_like_segments(self) -> list[TapeSegment]:
        return [s for s in self.segments if "AI_INSTRUCTION_LIKE_CONTENT" in s.flags]


def parse_markdown(text: str) -> TextTape:
    tape = TextTape(text=text)
    offset = 0
    in_fence = False
    for line_no, line in enumerate(text.splitlines(keepends=True), start=1):
        start = offset
        end = offset + len(line)
        offset = end
        stripped = line.rstrip("\r\n")
        flags: list[str] = []
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            kind = "fence"
        elif in_fence:
            kind = "fence"
        elif _HEADING_RE.match(line):
            kind = "heading"
        elif _TABLE_RE.match(line):
            kind = "table_row"
        elif _QUOTE_RE.match(line):
            kind = "quote"
        elif _LIST_RE.match(line):
            kind = "list"
        elif _HTML_RE.search(line):
            kind = "html"
        elif not stripped.strip():
            kind = "blank"
        else:
            kind = "paragraph"
        if _INJECTION_RE.search(line):
            flags.append("AI_INSTRUCTION_LIKE_CONTENT")
            tape.flags.add("AI_INSTRUCTION_LIKE_CONTENT")
        if _LINK_RE.search(line) or _URL_RE.search(line):
            flags.append("contains_link")
        tape.segments.append(TapeSegment(kind, line_no, start, end, tuple(flags)))
    return tape
