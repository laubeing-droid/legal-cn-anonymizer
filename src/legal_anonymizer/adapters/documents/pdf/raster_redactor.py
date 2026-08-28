"""Raster review PDF builder: render -> pixel erase/alias -> rebuild image-only
PDF with invariant metadata. The original text layer, attachments, scripts,
forms and annotations are never copied."""

from __future__ import annotations

import io
import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from .pdfium_parser import render_page

_FONT_CANDIDATES = [
    "C:/Windows/Fonts/msyh.ttc",
    "C:/Windows/Fonts/msyhbd.ttc",
    "C:/Windows/Fonts/simhei.ttf",
    "C:/Windows/Fonts/simsun.ttc",
]


def _load_font(px: int):
    for candidate in _FONT_CANDIDATES:
        if Path(candidate).exists():
            try:
                return ImageFont.truetype(candidate, px), True
            except OSError:
                continue
    return ImageFont.load_default(), False


def erase_and_draw(image: Image.Image, box: tuple[int, int, int, int],
                   replacement: str | None) -> None:
    """Physically erase the region (white box) and draw the display alias if one
    is provided. With no alias the area is fully redacted."""
    draw = ImageDraw.Draw(image)
    draw.rectangle([box[0], box[1], box[2] - 1, box[3] - 1], fill="white")
    if not replacement:
        return
    height = max(8, box[3] - box[1] - 2)
    font, cjk_ok = _load_font(height)
    if not cjk_ok and any("\u4e00" <= ch <= "\u9fff" for ch in replacement):
        # no CJK font available: cannot draw the alias without leaking shape
        draw.rectangle([box[0], box[1], box[2] - 1, box[3] - 1], fill="black")
        return
    draw.text((box[0] + 1, box[1]), replacement, fill="black", font=font)


def build_review_pdf(src: Path, page_boxes: dict[int, list[tuple]],
                     out_path: Path, dpi: int = 200) -> dict:
    """page_boxes: page_index -> list of (pixel_box, replacement_text_or_None).
    Returns page geometry for the report."""
    import pypdfium2 as pdfium

    pdf = pdfium.PdfDocument(str(src))
    page_sizes = [pdf[i].get_size() for i in range(len(pdf))]
    pdf.close()

    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas as rl_canvas

    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=page_sizes[0] if page_sizes else (595, 842))
    c.setTitle("")
    c.setAuthor("")
    c.setSubject("")
    c.setCreator("legal-cn-anonymizer review-pdf v1")
    c.setProducer("legal-cn-anonymizer")

    rendered: list[Image.Image] = []
    for i, (w, h) in enumerate(page_sizes):
        image = render_page(src, i, dpi=dpi)
        for box, replacement in page_boxes.get(i, []):
            erase_and_draw(image, box, replacement)
        rendered.append(image)

    for i, (w, h) in enumerate(page_sizes):
        c.setPageSize((w, h))
        img_buf = io.BytesIO()
        rendered[i].save(img_buf, format="JPEG", quality=88)
        img_buf.seek(0)
        c.drawImage(ImageReader(img_buf), 0, 0, width=w, height=h)
        c.showPage()
    c.save()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(buf.getvalue())
    return {"page_sizes": [list(map(float, s)) for s in page_sizes], "dpi": dpi}
