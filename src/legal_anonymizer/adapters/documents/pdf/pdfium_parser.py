"""PDFium parser: input checks, per-page text + char boxes, page metadata.
pypdfium2 is the default PDF engine (PyMuPDF/AGPL is excluded)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pypdfium2 as pdfium


class PdfInputError(ValueError):
    error_code = "parser_failed"


@dataclass
class PageText:
    page_index: int  # 0-based
    width: float  # points
    height: float
    text: str  # extraction-order text
    char_boxes: list[tuple[float, float, float, float]] = field(default_factory=list)
    # each entry: (left, bottom, right, top) in PDF points for char i


@dataclass
class PdfInfo:
    path: Path
    page_count: int
    encrypted: bool
    has_text_layer: bool
    metadata: dict
    pages: list[PageText]


def load_pdf(path: Path) -> PdfInfo:
    path = Path(path)
    header = path.read_bytes()[:8]
    if not header.startswith(b"%PDF"):
        raise PdfInputError("not a PDF file (fail closed)")
    try:
        pdf = pdfium.PdfDocument(str(path))
    except Exception as exc:  # noqa: BLE001 - malformed PDFs must fail closed
        raise PdfInputError(f"pdfium failed to open: {type(exc).__name__}") from exc
    encrypted = bool(getattr(pdf, "is_encrypted", False))
    if encrypted:
        raise PdfInputError("encrypted PDF not supported (fail closed)")
    page_count = len(pdf)
    metadata = {}
    for key in ("Title", "Author", "Subject", "Keywords", "Creator", "Producer"):
        try:
            metadata[key] = pdf.get_metadata_value(key) or ""
        except Exception:  # noqa: BLE001
            metadata[key] = ""
    pages: list[PageText] = []
    has_text = False
    for i in range(page_count):
        page = pdf[i]
        width, height = page.get_size()
        textpage = page.get_textpage()
        n_chars = textpage.count_chars()
        text = textpage.get_text_range(0, n_chars) if n_chars else ""
        boxes = [textpage.get_charbox(j) for j in range(n_chars)]
        if text.strip():
            has_text = True
        pages.append(PageText(page_index=i, width=width, height=height,
                              text=text, char_boxes=boxes))
        textpage.close()
        page.close()
    pdf.close()
    return PdfInfo(path=path, page_count=page_count, encrypted=encrypted,
                   has_text_layer=has_text, metadata=metadata, pages=pages)


def render_page(path: Path, page_index: int, dpi: int = 200):
    """Render one page to a PIL image at the given DPI."""
    pdf = pdfium.PdfDocument(str(path))
    try:
        page = pdf[page_index]
        bitmap = page.render(scale=dpi / 72.0)
        image = bitmap.to_pil()
        page.close()
    finally:
        pdf.close()
    return image


def charboxes_to_pixels(boxes: list[tuple], page_height: float, dpi: int,
                        image_width: int, image_height: int) -> tuple[int, int, int, int]:
    """Union of char boxes -> pixel (x0, y0, x1, y1) top-left origin."""
    scale = dpi / 72.0
    left = min(b[0] for b in boxes) * scale
    right = max(b[2] for b in boxes) * scale
    bottom = min(b[1] for b in boxes) * scale
    top = max(b[3] for b in boxes) * scale
    x0 = max(0, int(left) - 1)
    x1 = min(image_width, int(right) + 1)
    y0 = max(0, int(page_height * scale - top) - 1)
    y1 = min(image_height, int(page_height * scale - bottom) + 1)
    return x0, y0, x1, y1
