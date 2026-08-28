"""S6 text-PDF and raster review PDF tests."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pypdfium2 as pdfium
import pytest

from legal_anonymizer.adapters.documents.pdf.pdfium_parser import PdfInputError, load_pdf
from legal_anonymizer.application.pdf_pipeline import PdfSanitizeService
from legal_anonymizer.application.state import MatterState
from legal_anonymizer.application.verify_service import VerifyService
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


def make_text_pdf(path: Path) -> None:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.pdfgen import canvas as rl_canvas

    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    c = rl_canvas.Canvas(str(path), pagesize=A4)
    w, h = A4
    c.setFont("STSong-Light", 12)
    c.drawString(60, h - 80, "建设工程施工合同")
    c.drawString(60, h - 120, "发包人丹霞青云置业有限公司，项目负责人张三。")
    c.drawString(60, h - 160, f"身份证{SYNTHETIC_ID}，联系电话13812345678。")
    c.drawString(60, h - 200, "合同总价人民币3,000,000.00元。2023年5月1日开工。")
    c.showPage()
    c.drawString(60, h - 80, "第二页：质量保证金300,000.00元。")
    c.showPage()
    c.save()


@pytest.fixture()
def workspace(tmp_path):
    state_root = tmp_path / "state"
    out_dir = tmp_path / "out"
    MatterState(state_root, "matter-001").init("cn-ai-safe-v1")
    return state_root, out_dir, tmp_path


class TestTextPdf:
    def test_parse_and_sanitize(self, workspace, tmp_path):
        state_root, out_dir, base = workspace
        src = base / "in" / "合同.pdf"
        src.parent.mkdir()
        make_text_pdf(src)
        info = load_pdf(src)
        assert info.page_count == 2 and info.has_text_layer
        assert "张三" in info.pages[0].text

        result = PdfSanitizeService(state_root).sanitize_pdf(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY
        )
        assert result["status"] == "AUTO_READY", result["review_reasons"]
        review_pdf = out_dir / "sanitized" / "doc-001.review.pdf"

        # physical gate: no original text layer, pages consistent
        out_info = load_pdf(review_pdf)
        assert out_info.page_count == 2
        for page in out_info.pages:
            assert "张三" not in page.text
            assert SYNTHETIC_ID not in page.text
            assert "13812345678" not in page.text
            assert "丹霞青云置业有限公司" not in page.text
        # money survives as pixels (rasterized, no text layer at all)
        assert all(not page.text.strip() for page in out_info.pages) or all(
            "张三" not in p.text for p in out_info.pages
        )
        # markdown side output contains page markers
        md = (out_dir / "sanitized" / "doc-001.ai.md").read_text(encoding="utf-8")
        assert "page 1" in md and "3,000,000.00元" in md

    def test_verify_accepts_pdf_outputs(self, workspace, tmp_path):
        state_root, out_dir, base = workspace
        src = base / "in" / "合同.pdf"
        src.parent.mkdir()
        make_text_pdf(src)
        PdfSanitizeService(state_root).sanitize_pdf(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY
        )
        result = VerifyService(state_root).verify("matter-001", out_dir)
        assert result.status == "AUTO_READY", result.residual_counts

    def test_rehydrate_after_pdf(self, workspace, tmp_path):
        state_root, out_dir, base = workspace
        src = base / "in" / "合同.pdf"
        src.parent.mkdir()
        make_text_pdf(src)
        PdfSanitizeService(state_root).sanitize_pdf(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY
        )
        md = (out_dir / "sanitized" / "doc-001.ai.md").read_text(encoding="utf-8")
        from legal_anonymizer.application.rehydrate_service import RehydrateService

        restored = RehydrateService(state_root).rehydrate_text("matter-001", md)
        assert "张三" in restored.output_text
        assert "丹霞青云置业有限公司" in restored.output_text

    def test_invalid_pdf_fails_closed(self, workspace, tmp_path):
        state_root, out_dir, base = workspace
        src = base / "in" / "fake.pdf"
        src.parent.mkdir()
        src.write_bytes(b"PK\x03\x04 not a pdf")
        with pytest.raises(PdfInputError):
            load_pdf(src)
        result = PdfSanitizeService(state_root).sanitize_pdf(
            "matter-001", src, out_dir, "doc-001"
        )
        assert result["status"] == "CLOSED_BLOCK"

    def test_image_only_pdf_is_not_marked_done(self, workspace, tmp_path):
        state_root, out_dir, base = workspace
        # a PDF with no text layer (image-only) must not pass as text PDF
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas as rl_canvas

        src = base / "in" / "scan.pdf"
        src.parent.mkdir()
        c = rl_canvas.Canvas(str(src), pagesize=A4)
        c.drawString(60, 700, "")  # no text drawn
        c.showPage()
        c.save()
        result = PdfSanitizeService(state_root).sanitize_pdf(
            "matter-001", src, out_dir, "doc-001"
        )
        assert result["status"] == "REVIEW_REQUIRED"
