"""S5 DOCX OOXML tests: inventory, cross-run replacement, hidden content
policy, metadata cleanup, independent rescan."""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

import docx as python_docx
import pytest
from lxml import etree

from legal_anonymizer.adapters.documents.docx.parser import inventory
from legal_anonymizer.application.docx_pipeline import DocxSanitizeService
from legal_anonymizer.application.sanitize_service import SanitizeService
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
        {"value": "丹霞青云", "type": "LEGAL_PERSON"},
    ],
    aliases=[
        {"canonical": "丹霞青云置业有限公司", "values": ["丹霞青云置业有限公司", "丹霞青云"],
         "type": "LEGAL_PERSON"},
    ],
)


def make_docx(path: Path, with_comments=False, with_revision=False) -> None:
    doc = python_docx.Document()
    doc.add_heading("施工合同", level=1)
    doc.add_paragraph("发包人丹霞青云置业有限公司。")
    doc.add_paragraph(f"项目负责人张三，身份证{SYNTHETIC_ID}，电话13812345678。")
    table = doc.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text = "工程款3,000,000.00元"
    table.rows[0].cells[1].text = "2023年5月1日开工"
    doc.core_properties.author = "真实作者"
    doc.save(str(path))
    if with_comments or with_revision:
        _inject_hidden_parts(path, with_comments, with_revision)


def _inject_hidden_parts(path: Path, with_comments: bool, with_revision: bool) -> None:
    """Manually add comments and a tracked change (python-docx doesn't)."""
    import shutil
    tmp = path.with_suffix(".tmp.docx")
    with zipfile.ZipFile(path) as zin, zipfile.ZipFile(tmp, "w") as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if with_comments and info.filename == "[Content_Types].xml":
                data = data.replace(
                    b"</Types>",
                    b'<Override PartName="/word/comments.xml" '
                    b'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/></Types>',
                )
            if with_comments and info.filename == "word/_rels/document.xml.rels":
                data = data.replace(
                    b"</Relationships>",
                    b'<Relationship Id="rIdC1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/></Relationships>',
                )
            if with_revision and info.filename == "word/document.xml":
                data = data.replace(
                    "张三".encode("utf-8"),
                    '<w:ins w:id="1" w:author="人名"><w:r><w:t>张三</w:t></w:r></w:ins>'.encode("utf-8"),
                )
            zout.writestr(info, data)
        if with_comments:
            zout.writestr(
                "word/comments.xml",
                ('<?xml version="1.0"?><w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                 '<w:comment w:id="1" w:author="李四"><w:p><w:r><w:t>请核对张三身份</w:t></w:r></w:p></w:comment></w:comments>').encode("utf-8"),
            )
    shutil.move(str(tmp), str(path))


@pytest.fixture()
def workspace(tmp_path):
    state_root = tmp_path / "state"
    out_dir = tmp_path / "out"
    MatterState(state_root, "matter-001").init("cn-ai-safe-v1")
    return state_root, out_dir


class TestDocxPipeline:
    def test_inventory_and_sanitize(self, workspace, tmp_path):
        state_root, out_dir = workspace
        src = tmp_path / "in" / "合同.docx"
        src.parent.mkdir()
        make_docx(src)
        result = DocxSanitizeService(state_root).sanitize_docx(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY
        )
        # no dictionary-confirmed failure: all subjects in dictionary
        assert result.status == "AUTO_READY", result.review_reasons
        out_docx = out_dir / "sanitized" / "doc-001.sanitized.docx"
        assert out_docx.exists()
        # opens without repair (python-docx roundtrip)
        doc = python_docx.Document(str(out_docx))
        texts = [p.text for p in doc.paragraphs]
        assert any("法人A" in t for t in texts)
        assert any("自然人A" in t for t in texts)
        full = "\n".join(texts)
        assert "张三" not in full and SYNTHETIC_ID not in full
        assert "13812345678" not in full
        # table values preserved
        table_text = "\n".join(
            c.text for row in doc.tables[0].rows for c in row.cells
        )
        assert "3,000,000.00元" in table_text and "2023年5月1日开工" in table_text
        # markdown side output
        md = (out_dir / "sanitized" / "doc-001.ai.md").read_text(encoding="utf-8")
        assert "# 施工合同" in md and "法人A" in md

    def test_part_inventory_accounted(self, workspace, tmp_path):
        state_root, out_dir = workspace
        src = tmp_path / "in" / "合同.docx"
        src.parent.mkdir()
        make_docx(src)
        result = DocxSanitizeService(state_root).sanitize_docx(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY
        )
        report = json.loads(
            (out_dir / "reports" / "doc-001.report.json").read_text(encoding="utf-8")
        )
        inv = report["part_inventory"]
        assert inv["total_parts"] == len(inv["text_parts"]) + len(inv["dropped"]) + len(inv["modified"]) + len(inv["unmodified"]) - len(
            set(inv["modified"]) & set(inv["text_parts"])
        ) - len(set(inv["dropped"]) & set(inv["modified"]))
        # simpler invariant: modified + unmodified + dropped >= text parts
        assert set(inv["text_parts"]) <= set(inv["modified"]) | set(inv["dropped"])

    def test_metadata_cleaned(self, workspace, tmp_path):
        state_root, out_dir = workspace
        src = tmp_path / "in" / "合同.docx"
        src.parent.mkdir()
        make_docx(src)
        DocxSanitizeService(state_root).sanitize_docx(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY
        )
        with zipfile.ZipFile(out_dir / "sanitized" / "doc-001.sanitized.docx") as zf:
            core = zf.read("docProps/core.xml").decode("utf-8")
        assert "真实作者" not in core

    def test_hidden_content_requires_decision(self, workspace, tmp_path):
        state_root, out_dir = workspace
        src = tmp_path / "in" / "合同.docx"
        src.parent.mkdir()
        make_docx(src, with_comments=True, with_revision=True)
        result = DocxSanitizeService(state_root).sanitize_docx(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY
        )
        assert result.status == "REVIEW_REQUIRED"
        assert "HIDDEN_CONTENT" in result.review_reasons

    def test_flatten_drops_comments_and_deletions(self, workspace, tmp_path):
        state_root, out_dir = workspace
        src = tmp_path / "in" / "合同.docx"
        src.parent.mkdir()
        make_docx(src, with_comments=True, with_revision=True)
        result = DocxSanitizeService(state_root).sanitize_docx(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY,
            decisions={"comments": "FLATTEN_CURRENT_VIEW", "tracked_changes": "FLATTEN_CURRENT_VIEW"},
        )
        out_docx = out_dir / "sanitized" / "doc-001.sanitized.docx"
        with zipfile.ZipFile(out_docx) as zf:
            names = zf.namelist()
            assert "word/comments.xml" not in names
            doc_xml = zf.read("word/document.xml").decode("utf-8")
        assert "张三" not in doc_xml  # deleted-revision text is physically gone
        assert "<w:ins" not in doc_xml and "<w:del" not in doc_xml

    def test_block_policy_closes(self, workspace, tmp_path):
        state_root, out_dir = workspace
        src = tmp_path / "in" / "合同.docx"
        src.parent.mkdir()
        make_docx(src, with_comments=True)
        result = DocxSanitizeService(state_root).sanitize_docx(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY,
            decisions={"comments": "BLOCK"},
        )
        assert result.status == "CLOSED_BLOCK"

    def test_independent_verify_scans_docx_parts(self, workspace, tmp_path):
        state_root, out_dir = workspace
        src = tmp_path / "in" / "合同.docx"
        src.parent.mkdir()
        make_docx(src)
        DocxSanitizeService(state_root).sanitize_docx(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY
        )
        result = VerifyService(state_root).verify("matter-001", out_dir)
        assert result.status == "AUTO_READY", result.residual_counts
        assert result.gates["privacy"] == "PASS"

    def test_docx_rehydrate_roundtrip(self, workspace, tmp_path):
        state_root, out_dir = workspace
        src = tmp_path / "in" / "合同.docx"
        src.parent.mkdir()
        make_docx(src)
        DocxSanitizeService(state_root).sanitize_docx(
            "matter-001", src, out_dir, "doc-001", dictionary=DICTIONARY
        )
        from legal_anonymizer.application.rehydrate_service import RehydrateService

        out_docx = out_dir / "sanitized" / "doc-001.sanitized.docx"
        restored_path = out_dir / "restored.docx"
        result = RehydrateService(state_root).rehydrate_docx(
            "matter-001", out_docx, restored_path
        )
        assert result.replacements > 0
        doc = python_docx.Document(str(restored_path))
        full = "\n".join(p.text for p in doc.paragraphs)
        assert "张三" in full
        assert "丹霞青云置业有限公司" in full
        # money untouched
        table_text = "\n".join(
            c.text for row in doc.tables[0].rows for c in row.cells
        )
        assert "3,000,000.00元" in table_text

    def test_cli_docx_dispatch(self, workspace, tmp_path, capsys):
        from legal_anonymizer.cli import main

        state_root, out_dir = workspace
        input_dir = tmp_path / "in"
        input_dir.mkdir()
        make_docx(input_dir / "合同.docx")
        (input_dir / "备注.md").write_text(
            "青云绿洲项目款100万元，2023年5月1日开工。", encoding="utf-8"
        )
        dict_file = tmp_path / "dict.json"
        dict_file.write_text(
            json.dumps(
                {
                    "blacklist": [
                        {"value": "青云绿洲项目", "type": "PROJECT"},
                        {"value": "张三", "type": "PERSON"},
                        {"value": "丹霞青云置业有限公司", "type": "LEGAL_PERSON"},
                        {"value": "丹霞青云", "type": "LEGAL_PERSON"},
                    ]
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        code = main(["sanitize", str(input_dir), "--matter", "matter-001",
                     "--out", str(out_dir), "--state-dir", str(state_root),
                     "--dictionary", str(dict_file)])
        # md has dictionary-confirmed project but docx subjects confirmed too;
        # md has no unconfirmed subjects, docx none unconfirmed
        assert code == 0
        assert (out_dir / "sanitized" / "doc-002.sanitized.docx").exists()
        caps = capsys.readouterr()
