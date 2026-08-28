"""S7 scan-pipeline tests: rendered (image-only) PDF through RapidOCR,
per-page states, manual boxes, QR signals, forced human review.

These tests run real CPU OCR and are therefore slow but honest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from legal_anonymizer.application.scan_pipeline import ScanPipeline
from legal_anonymizer.application.state import MatterState
from legal_anonymizer.adapters.recognizers.project_dictionary import (
    ProjectDictionaryProvider,
)
from tests.recognizers.test_cn_rules import SYNTHETIC_ID

DICTIONARY = ProjectDictionaryProvider(
    blacklist=[
        {"value": "张三", "type": "PERSON"},
        {"value": "丹霞青云置业有限公司", "type": "LEGAL_PERSON"},
    ]
)


def make_image_only_pdf(path: Path, text: str) -> None:
    """Render text into pixels, then rebuild an image-only PDF (no text layer)."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.pdfgen import canvas as rl_canvas

    import io

    from PIL import Image

    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    c.setFont("STSong-Light", 16)
    c.drawString(60, h - 120, text)
    c.showPage()
    c.save()
    buf.seek(0)

    import pypdfium2 as pdfium

    pdf = pdfium.PdfDocument(buf)
    page = pdf[0]
    image = page.render(scale=2.0).to_pil()
    page.close()
    pdf.close()

    from reportlab.lib.utils import ImageReader

    out = io.BytesIO()
    c2 = rl_canvas.Canvas(str(path), pagesize=A4)
    img_buf = io.BytesIO()
    image.save(img_buf, format="PNG")
    img_buf.seek(0)
    c2.drawImage(ImageReader(img_buf), 0, 0, width=w, height=h)
    c2.showPage()
    c2.save()


@pytest.fixture(scope="module")
def scanned_pdf(tmp_path_factory):
    base = tmp_path_factory.mktemp("scan")
    src = base / "scan.pdf"
    make_image_only_pdf(
        src,
        f"项目负责人张三 身份证{SYNTHETIC_ID} 电话13812345678 工程款3,000,000.00元 2023年5月1日开工",
    )
    return base, src


@pytest.fixture()
def workspace(tmp_path):
    state_root = tmp_path / "state"
    out_dir = tmp_path / "out"
    MatterState(state_root, "matter-001").init("cn-ai-safe-v1")
    return state_root, out_dir


class TestScanPipeline:
    def test_scan_requires_human_review(self, scanned_pdf, workspace):
        base, src = scanned_pdf
        state_root, out_dir = workspace
        result = ScanPipeline(state_root).sanitize_scan(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY
        )
        assert result["status"] == "REVIEW_REQUIRED"
        assert "OCR_DOCUMENT" in result["review_reasons"]
        report = result["report"]
        assert report["page_states"]["0"] == "TRANSFORMED"
        assert report["ocr_states"]["0"] in ("OCR_COMPLETE", "OCR_LOW_CONFIDENCE")
        # the OCR must have actually read the surfaces (hash-locked model works)
        review_pdf = out_dir / "sanitized" / "doc-001.review.pdf"
        assert review_pdf.exists()
        from legal_anonymizer.adapters.documents.pdf.pdfium_parser import load_pdf

        out_info = load_pdf(review_pdf)
        joined = "\n".join(p.text for p in out_info.pages)
        assert SYNTHETIC_ID not in joined
        assert "13812345678" not in joined

    def test_rehydrate_after_scan(self, scanned_pdf, workspace):
        base, src = scanned_pdf
        state_root, out_dir = workspace
        ScanPipeline(state_root).sanitize_scan(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY
        )
        from legal_anonymizer.application.rehydrate_service import RehydrateService

        md = (out_dir / "sanitized" / "doc-001.ai.md").read_text(encoding="utf-8")
        restored = RehydrateService(state_root).rehydrate_text("matter-001", md)
        assert "张三" in restored.output_text

    def test_manual_box_redaction(self, scanned_pdf, workspace):
        base, src = scanned_pdf
        state_root, out_dir = workspace
        result = ScanPipeline(state_root).sanitize_scan(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY,
            decisions={"manual_boxes": [
                {"document_id": "doc-001", "page": 1, "box": [40, 40, 500, 90],
                 "entity_type": "SIGNATURE", "action": "REDACT"},
            ]},
        )
        # manual box added a redaction region
        assert result["report"]["redaction_boxes"]["0"] >= 2

    def test_ocr_model_mismatch_fails_closed(self, scanned_pdf, workspace, tmp_path, monkeypatch):
        base, src = scanned_pdf
        state_root, out_dir = workspace
        # corrupt the manifest hash -> engine must refuse
        manifest_path = Path(
            __import__("legal_anonymizer.adapters.ocr.rapidocr", fromlist=["_REPO_MODELS"]).__dict__["_REPO_MODELS"]
        )
        original = manifest_path.read_text(encoding="utf-8")
        tampered = original.replace(
            "e47acedf663230f8863ff1ab0e64dd2d82b838fceb5957146dab185a89d6215c",
            "0" * 64,
        )
        manifest_path.write_text(tampered, encoding="utf-8")
        try:
            result = ScanPipeline(state_root).sanitize_scan(
                "matter-001", src, out_dir, "doc-001"
            )
            assert result["status"] == "CLOSED_BLOCK"
            assert any("ocr_unavailable" in r for r in result["review_reasons"])
        finally:
            manifest_path.write_text(original, encoding="utf-8")
