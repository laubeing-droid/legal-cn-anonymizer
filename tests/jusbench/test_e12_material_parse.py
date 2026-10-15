"""W2a-U02 / E12 全量材料解析公开面测试：5000 页级清单、未读失败低置信
分母（信号闭集分别计数）、跨页表阅读序、页号 bbox 版本、人改不覆、局部恢复
（每页原子提交，重跑不重不漏）。

语料清单只取身份字段——金标字段（expected_signal 等）即使出现在清单里也
被结构性忽略（test_batch_json_never_carries_gold_fields）。所有材料合成
（AGENTS.md rule 1）；页字节与登记不符=fail-closed 拒解析（原件只读）。
OCR 分类用真实本地引擎（slow but honest），引擎未装配时该组 skip 并注明，
不伪造通过。
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from legal_anonymizer.application import material_parse_service as mp
from legal_anonymizer.application.material_parse_service import (
    MaterialParseError,
    batch_report,
    human_edit,
    pending_pages,
    process_pages,
    read_page,
    reparse_page,
    register_batch,
    table_rows,
)

CORPUS_SCHEMA = "juscite-e12-corpus/1"


def _png_bytes(img) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _sha(b: bytes) -> str:
    import hashlib

    return hashlib.sha256(b).hexdigest()


def _white_png(w: int = 992, h: int = 1403) -> bytes:
    from PIL import Image

    return _png_bytes(Image.new("L", (w, h), 255))


def _inky_noise_png(w: int = 992, h: int = 1403) -> bytes:
    """非空白但无可读文本（淡墨点阵）：OCR 低置信或零行，绝不 READ_OK。"""
    from PIL import Image, ImageDraw

    img = Image.new("L", (w, h), 255)
    d = ImageDraw.Draw(img)
    for x in range(120, 880, 40):
        for y in range(200, 1300, 40):
            d.rectangle([x, y, x + 6, y + 6], fill=180)
    return _png_bytes(img)


def _rendered_text_png(lines: list[tuple[int, int, str]], w=992, h=1403) -> bytes:
    """reportlab STSong（无字体文件依赖）→ PDF → pypdfium2 栅格化 PNG。

    lines 坐标为目标图像像素系（x, y_from_top）；内部换算 PDF 点位。
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.pdfgen import canvas as rl_canvas

    import pypdfium2 as pdfium

    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    scale = w / A4[0]
    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=A4)
    c.setFont("STSong-Light", 16)
    for x, y, text in lines:
        c.drawString(x / scale, A4[1] - y / scale, text)
    c.showPage()
    c.save()
    buf.seek(0)
    pdf = pdfium.PdfDocument(buf)
    image = pdf[0].render(scale=scale).to_pil().convert("L")
    pdf.close()
    return _png_bytes(image)


def _write_corpus(root: Path, docs: list[dict[str, list[bytes]]], *,
                  with_gold_fields: bool = True) -> Path:
    """按语料身份 schema 写合成语料（金标字段写进去以证明被忽略）。"""
    corpus = root / "corpus"
    (corpus / "pages").mkdir(parents=True)
    documents = []
    for di, (meta, pages) in enumerate(docs):
        doc_id = meta.get("doc_id", f"doc_{di + 1:04d}")
        page_files = []
        for pi, png in enumerate(pages):
            rel = f"pages/{doc_id}/p{pi + 1:04d}.png"
            target = corpus / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(png, Path):
                png = png.read_bytes()
            target.write_bytes(png)
            entry = {"page": pi + 1, "kind": "TEXT", "png": rel,
                     "sha256": _sha(png), "bytes": len(png)}
            if with_gold_fields:
                entry["expected_signal"] = "read_ok"      # 金标——必须被忽略
                entry["page_no_gold"] = {"text": "- 1 -", "bbox_px": [0, 0, 1, 1]}
            page_files.append(entry)
        documents.append({
            "doc_id": doc_id, "doc_code": f"SJ-{di + 1:04d}",
            "title": "合成测试卷", "case_no": "（2026）京01民初1号",
            "page_count": len(pages), "pdf": f"docs/{doc_id}.pdf",
            "pdf_bytes": 1234, "pdf_sha256": "0" * 64,
            "tables": [],                                # 金标——必须被忽略
            "page_files": page_files,
        })
    manifest = {"schema": CORPUS_SCHEMA, "seed": 1, "pages": sum(len(d) for _, d in docs),
                "documents": documents}
    (corpus / "corpus_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    return corpus


@pytest.fixture()
def blank_corpus(tmp_path):
    # 纯白页＋（非空白噪声页＋其字节级复刻）：空白/重复两分类都不需要 OCR
    noise = _inky_noise_png()
    corpus = _write_corpus(tmp_path, [
        ({"doc_id": "doc_0001"}, [_white_png(), noise, noise]),
    ])
    return tmp_path, corpus


class TestRegister:
    def test_register_idempotent_and_counts(self, blank_corpus):
        tmp_path, corpus = blank_corpus
        first = register_batch(tmp_path, corpus)
        again = register_batch(tmp_path, corpus)
        assert first["batch_id"] == again["batch_id"]
        assert first["registered_pages"] == 3
        assert first["documents"] == 1
        assert first["batch_id"].startswith("mp-")

    def test_batch_json_never_carries_gold_fields(self, blank_corpus):
        tmp_path, corpus = blank_corpus
        reg = register_batch(tmp_path, corpus)
        raw = (tmp_path / "material-parse" / reg["batch_id"]
               / "batch.json").read_text(encoding="utf-8")
        assert "expected_signal" not in raw
        assert "page_no_gold" not in raw
        assert '"tables"' not in raw          # 表格金标不进登记清单
        assert '"kind"' not in raw            # 页型（解析答案）不进登记清单

    def test_missing_manifest_fails_closed(self, tmp_path):
        with pytest.raises(MaterialParseError, match="parse_corpus_manifest_missing"):
            register_batch(tmp_path, tmp_path)

    def test_unregistered_batch_operations_fail(self, blank_corpus):
        tmp_path, _ = blank_corpus
        with pytest.raises(MaterialParseError, match="parse_batch_not_registered"):
            batch_report(tmp_path, "mp-doesnotexist")


class TestSignalsWithoutOcr:
    """空白/重复/字节变动三条分类路径不需要 OCR 引擎（纯确定性）。"""

    def test_blank_and_duplicate_signals(self, blank_corpus):
        tmp_path, corpus = blank_corpus
        reg = register_batch(tmp_path, corpus)
        out = process_pages(tmp_path, reg["batch_id"], None)
        assert out["signals"]["BLANK"] == 1
        assert out["signals"]["DUPLICATE"] == 1
        rec1 = read_page(tmp_path, reg["batch_id"], "doc_0001", 1)
        assert rec1["signal"] == "BLANK"
        assert rec1["page_no"]["versions"] == []
        rec3 = read_page(tmp_path, reg["batch_id"], "doc_0001", 3)
        assert rec3["signal"] == "DUPLICATE"
        assert rec3["duplicate_of"] == {"doc_id": "doc_0001", "page": 2}

    def test_identical_blank_pages_stay_blank_not_duplicate(self, tmp_path):
        # 纯白页彼此字节恒同（无帧无内容）：语义仍是空白页，不是内容页复刻
        white = _white_png()
        corpus = _write_corpus(tmp_path, [
            ({"doc_id": "doc_0001"}, [white, white])])
        reg = register_batch(tmp_path, corpus)
        out = process_pages(tmp_path, reg["batch_id"], None)
        assert out["signals"]["BLANK"] == 2
        assert out["signals"].get("DUPLICATE", 0) == 0

    def test_mutated_page_fails_closed_unread(self, tmp_path):
        # 语料页在登记后被改写：sha 不符 → UNREAD_FAILED，绝不解析被改原件
        white = _white_png()
        corpus = _write_corpus(tmp_path, [({"doc_id": "doc_0001"}, [white])])
        png_path = next((corpus / "pages").glob("*/*.png"))
        png_path.write_bytes(_white_png(800, 600))     # 同为空白但字节不同
        reg = register_batch(tmp_path, corpus)
        out = process_pages(tmp_path, reg["batch_id"], None)
        assert out["signals"]["UNREAD_FAILED"] == 1
        rec = read_page(tmp_path, reg["batch_id"], "doc_0001", 1)
        assert rec["signal_detail"] == "page_bytes_mismatch"

    def test_resume_is_idempotent_no_dup_no_miss(self, blank_corpus):
        tmp_path, corpus = blank_corpus
        reg = register_batch(tmp_path, corpus)
        bid = reg["batch_id"]
        first = process_pages(tmp_path, bid,
                              [{"doc_id": "doc_0001", "page": 1}])
        assert first["processed"] == 1
        second = process_pages(tmp_path, bid, None)     # 恢复：全量待处理
        assert second["processed"] == 2
        assert second["skipped_existing"] == 1
        report = batch_report(tmp_path, bid)
        assert report["completed"] == 3 and report["pending"] == 0
        assert report["corrupt_records"] == 0

    def test_pending_and_report_closed_denominator(self, blank_corpus):
        tmp_path, corpus = blank_corpus
        reg = register_batch(tmp_path, corpus)
        bid = reg["batch_id"]
        assert pending_pages(tmp_path, bid) == [
            {"doc_id": "doc_0001", "page": 1},
            {"doc_id": "doc_0001", "page": 2},
            {"doc_id": "doc_0001", "page": 3}]
        process_pages(tmp_path, bid, [{"doc_id": "doc_0001", "page": 3}])
        report = batch_report(tmp_path, bid)
        assert report["registered_pages"] == 3
        assert report["completed"] == 1 and report["pending"] == 2
        assert set(report["signals"]) == set(mp.SIGNALS)
        # 登记外的野记录：corrupt 计数，不并入完成（不凭文件存在已读）
        rogue = tmp_path / "material-parse" / bid / "pages" / "doc_9999" / "p0001.json"
        rogue.parent.mkdir(parents=True, exist_ok=True)
        rogue.write_text('{"doc_id": "doc_9999", "page": 1, "signal": "READ_OK"}',
                         encoding="utf-8")
        report2 = batch_report(tmp_path, bid)
        assert report2["corrupt_records"] == 1
        assert report2["completed"] == 1

    def test_pages_argument_validation(self, blank_corpus):
        tmp_path, corpus = blank_corpus
        reg = register_batch(tmp_path, corpus)
        with pytest.raises(MaterialParseError, match="parse_page_not_in_batch"):
            process_pages(tmp_path, reg["batch_id"],
                          [{"doc_id": "doc_0001", "page": 99}])
        with pytest.raises(MaterialParseError, match="parse_pages_arg_invalid"):
            process_pages(tmp_path, reg["batch_id"], ["doc_0001:1"])


class TestHumanEditAndReparse:
    def _blank_state(self, tmp_path):
        corpus = _write_corpus(tmp_path, [
            ({"doc_id": "doc_0001"}, [_white_png(), _white_png(992, 1400)])])
        reg = register_batch(tmp_path, corpus)
        process_pages(tmp_path, reg["batch_id"], None)
        return reg["batch_id"]

    def test_human_edit_appends_version_and_becomes_current(self, tmp_path):
        bid = self._blank_state(tmp_path)
        edit = human_edit(tmp_path, bid, "doc_0001", 1, "- 1 -")
        assert edit["source"] == "human" and edit["version"] == 1
        rec = read_page(tmp_path, bid, "doc_0001", 1)
        assert rec["page_no"]["current_version"] == 1
        assert rec["page_no"]["versions"][0]["source"] == "human"

    def test_reparse_never_overwrites_human_version(self, tmp_path):
        # 人改不覆：重抽追加引擎版本，human 版本原样保留且仍是当前版本
        bid = self._blank_state(tmp_path)
        human_edit(tmp_path, bid, "doc_0001", 1, "- 1 -")
        out = reparse_page(tmp_path, bid, "doc_0001", 1)
        assert out["human_versions_kept"] == 1
        assert out["page_no_current_version"] == 1        # 指向 human 版本
        rec = read_page(tmp_path, bid, "doc_0001", 1)
        sources = [v["source"] for v in rec["page_no"]["versions"]]
        assert sources == ["human"]
        assert rec["parse_count"] == 2

    def test_human_edit_rejects_empty_text(self, tmp_path):
        bid = self._blank_state(tmp_path)
        with pytest.raises(MaterialParseError,
                            match="parse_human_edit_text_invalid"):
            human_edit(tmp_path, bid, "doc_0001", 1, "  ")

    def test_edit_or_reparse_unprocessed_page_fails(self, tmp_path):
        corpus = _write_corpus(tmp_path, [({"doc_id": "doc_0001"}, [_white_png()])])
        reg = register_batch(tmp_path, corpus)
        with pytest.raises(MaterialParseError, match="parse_page_not_processed"):
            human_edit(tmp_path, reg["batch_id"], "doc_0001", 1, "- 1 -")


class TestTableAssembly:
    """跨页表阅读序组装（纯几何，无 OCR）：行序=(页,页内行)；缺格=空位。"""

    @staticmethod
    def _cell(text, x, y):
        return {"text": text, "bbox": [x, y, x + 100, y + 40], "conf": 0.99}

    def _state_with_tables(self, tmp_path):
        corpus = _write_corpus(tmp_path, [
            ({"doc_id": "doc_0001"}, [_white_png()] * 3)])
        reg = register_batch(tmp_path, corpus)
        bdir = tmp_path / "material-parse" / reg["batch_id"]
        pages = {
            # 页1：3 行（行1 跨到页2 续）；页2 隔开（断组）；页3：续表
            1: [
                {"page_row_index": 0, "cells": [
                    self._cell("1", 86, 220), self._cell("2026-02-05", 184, 220),
                    self._cell("100.00", 364, 220), self._cell("20.00", 544, 220),
                    self._cell("120.00", 724, 220)]},
                {"page_row_index": 1, "cells": [
                    self._cell("2", 86, 284), self._cell("2026-03-05", 184, 284),
                    self._cell("100.00", 364, 284), self._cell("18.00", 544, 284),
                    self._cell("118.00", 724, 284)]},
            ],
            3: [
                {"page_row_index": 0, "cells": [
                    self._cell("3", 86, 220), self._cell("2026-04-05", 184, 220),
                    self._cell("100.00", 364, 220), self._cell("16.00", 544, 220),
                    self._cell("116.00", 724, 220)]},
                {"page_row_index": 1, "cells": [
                    # 合计行：期次列放「合计」，日期列缺格
                    self._cell("合计", 86, 284), self._cell("300.00", 364, 284),
                    self._cell("54.00", 544, 284), self._cell("354.00", 724, 284)]},
            ],
        }
        for page, rows in pages.items():
            rec = {"schema": mp.SCHEMA, "batch_id": reg["batch_id"],
                   "doc_id": "doc_0001", "page": page, "signal": "READ_OK",
                   "table_rows": rows}
            path = bdir / "pages" / "doc_0001" / f"p{page:04d}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            from legal_anonymizer.security.safe_storage import atomic_write_bytes

            atomic_write_bytes(
                path, json.dumps(rec, ensure_ascii=False,
                                 sort_keys=True).encode("utf-8"))
        return reg["batch_id"]

    def test_reading_order_across_pages_and_gap_breaks_group(self, tmp_path):
        bid = self._state_with_tables(tmp_path)
        out = table_rows(tmp_path, bid, "doc_0001")
        assert len(out["groups"]) == 2          # 页2 无表 → 断组
        g1, g2 = out["groups"]
        assert g1["pages"] == [1, 1] and g2["pages"] == [3, 3]
        assert g1["columns"] == 5 and g2["columns"] == 5
        assert [(r["page"], r["page_row_index"]) for r in g1["rows"]] == \
            [(1, 0), (1, 1)]
        texts = [[c["text"] if c else None for c in r["cells"]] for r in g1["rows"]]
        assert texts[0] == ["1", "2026-02-05", "100.00", "20.00", "120.00"]
        g2_texts = [[c["text"] if c else None for c in r["cells"]]
                    for r in g2["rows"]]
        assert g2_texts[0] == ["3", "2026-04-05", "100.00", "16.00", "116.00"]
        assert g2_texts[1] == ["合计", None, "300.00", "54.00", "354.00"]  # 缺格=空位

    def test_unknown_doc_fails(self, tmp_path):
        bid = self._state_with_tables(tmp_path)
        with pytest.raises(MaterialParseError, match="parse_doc_not_in_batch"):
            table_rows(tmp_path, bid, "doc_7777")


def _ocr_available() -> bool:
    try:
        mp._get_engine()
    except Exception:  # noqa: BLE001 - 引擎未装配=CLOSED_BLOCK，skip 如实
        return False
    return True


@pytest.mark.skipif(not _ocr_available(), reason="rapidocr 引擎未装配（fail-closed skip）")
class TestOcrClassification:
    """真实本地 OCR：READ_OK 分类＋页号 bbox 提取＋非文本页空识别。"""

    def test_read_ok_page_with_page_no_bbox(self, tmp_path):
        body = [(86, 130 + 30 * i,
                 "合成测试卷第%d行甲乙双方确认本协议系测试材料" % (i + 1))
                for i in range(10)]
        png = _rendered_text_png(body + [(466, 1345, "- 1 -")])
        corpus = _write_corpus(tmp_path, [({"doc_id": "doc_0001"}, [png])])
        reg = register_batch(tmp_path, corpus)
        out = process_pages(tmp_path, reg["batch_id"], None)
        assert out["signals"].get("READ_OK") == 1
        rec = read_page(tmp_path, reg["batch_id"], "doc_0001", 1)
        assert rec["signal"] == "READ_OK"
        assert rec["engine"]["lines"] >= 8
        version = rec["page_no"]["versions"][0]
        assert version["source"] == "engine" and version["version"] == 1
        assert version["bbox"][1] > 1200          # 页脚带内
        assert rec["page_no"]["current_version"] == 1

    def test_nonblank_notext_page_is_empty_recognition(self, tmp_path):
        png = _inky_noise_png()
        corpus = _write_corpus(tmp_path, [({"doc_id": "doc_0001"}, [png])])
        reg = register_batch(tmp_path, corpus)
        out = process_pages(tmp_path, reg["batch_id"], None)
        # 淡墨点阵：诚实分族＝空识别或低置信，绝不 READ_OK（fail-closed）
        assert out["signals"].get("EMPTY_RECOGNITION", 0) + \
            out["signals"].get("LOW_CONFIDENCE", 0) == 1
        assert out["signals"].get("READ_OK", 0) == 0
        rec = read_page(tmp_path, reg["batch_id"], "doc_0001", 1)
        assert rec["signal"] in ("EMPTY_RECOGNITION", "LOW_CONFIDENCE")
        assert rec["page_no"]["versions"] == []
