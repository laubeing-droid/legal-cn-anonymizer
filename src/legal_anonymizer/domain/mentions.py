"""Mention: a concrete occurrence of a protected surface in one document.

The raw surface is private state — it never enters public payloads; public
structures carry ``surface_hmac`` (HMAC keyed by the matter secret) instead."""

from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Locator:
    """Where a mention occurs. Only the fields relevant to the format are set."""

    kind: str  # text_offset | pdf_box | ocr_box | docx_xml
    page: int = 1
    start: int = -1
    end: int = -1
    part: str = ""
    node_path: str = ""
    box: tuple[float, float, float, float] | None = None

    def sort_key(self) -> tuple:
        return (self.page, self.start if self.start >= 0 else 0, self.end if self.end >= 0 else 0)


@dataclass
class Mention:
    surface: str  # RAW - private
    entity_type: str  # EntityType value
    document_id: str
    locator: Locator
    source: str = "regex"  # regex | ner | dictionary | structure | manual | vision
    confidence: float = 1.0
    evidence_codes: tuple[str, ...] = field(default_factory=tuple)
    surface_hmac: str = ""

    def hmac_for(self, matter_secret: bytes) -> str:
        if not self.surface_hmac:
            digest = hmac.new(matter_secret, self.surface.encode("utf-8"), hashlib.sha256)
            self.surface_hmac = digest.hexdigest()
        return self.surface_hmac

    def sort_key(self) -> tuple:
        return (self.document_id,) + self.locator.sort_key()


@dataclass(frozen=True)
class Span:
    """A text range to replace, end-to-start applied."""

    start: int
    end: int
    replacement: str
    entity_id: str | None = None

    def __post_init__(self):
        if self.end < self.start:
            raise ValueError(f"span end {self.end} < start {self.start}")


def apply_spans(text: str, spans: list[Span]) -> str:
    """Apply replacement spans end-to-start; overlapping spans are rejected."""
    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    for a, b in zip(ordered, ordered[1:]):
        if b.start < a.end:
            raise ValueError(f"overlapping spans: [{a.start},{a.end}) and [{b.start},{b.end})")
    result = text
    for span in sorted(spans, key=lambda s: s.start, reverse=True):
        result = result[: span.start] + span.replacement + result[span.end :]
    return result
