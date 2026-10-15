"""E12 全量材料解析公开面（W2a-U02）：5000 页级清单、未读失败低置信分母，
跨页表阅读序、页号 bbox 版本、人改不覆、局部恢复。

义务 07:E12（05:123 细则）：材料登记来源/只读 ref/大小/页数/解析状态；扫描件
本地 OCR，保存页块 bbox/置信/引擎与人改版本，保跨页表。失败、空识别、未读、
低置信**分别计数，不凭文件存在已读**；可暂停局部重跑（每页记录原子提交，
重跑=处理无记录页，不重不漏）；人改不覆（人工修订版本永不被重扫覆盖，
当前版本=最新人改版本，否则最新引擎版本）。

确定性纪律（红线）：
- 语料清单只取身份字段（doc_id/页数/png ref/sha256/bytes/pdf ref 白名单），
  金标字段（expected_signal/page_no_gold/reading_order_rows 等）结构性不读
  ——解析结果只能来自栅格本身；
- 页字节先复验 sha256（变了=fail-closed UNREAD_FAILED，绝不解析被改写的原件）；
- 信号闭集 SIGNALS；分类 fail-closed：非空白页 OCR 零行=EMPTY_RECOGNITION，
  异常=UNREAD_FAILED，永不静默跳页；
- 服务永不 print/log 材料内容；错误码只带类别与计数（typed error）。

存储布局（页记录=解析产物，正文行文本不入账，仅 bbox/置信；页号与表格
单元格文本是解析产物本身）::

    <state_root>/material-parse/<batch_id>/batch.json
    <state_root>/material-parse/<batch_id>/pages/<doc_id>/p<NNNN>.json

All test data synthetic (AGENTS.md rule 1); originals are read-only.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

from ..security.safe_storage import atomic_write_bytes

SCHEMA = "juscite-e12-material-parse/1"
SIGNALS = frozenset({
    "READ_OK", "LOW_CONFIDENCE", "EMPTY_RECOGNITION",
    "UNREAD_FAILED", "BLANK", "DUPLICATE",
})
LOW_CONFIDENCE_THRESHOLD = 0.85   # 与 S7 scan_pipeline 同阈
BLANK_MIN_LUMA = 250              # 全白判定（PNG 无损，空白页=255）
_ROW_Y_TOL_FRAC = 0.025           # 行聚类的 y 容差（按页高比例）
_TABLE_MIN_CELLS = 4              # 表格行最少模式格数
_TABLE_MIN_AMOUNTS = 2            # 表格行最少金额格数

# 语料清单身份字段白名单——金标字段结构性不读（见模块 docstring）
_DOC_FIELDS = frozenset({"doc_id", "doc_code", "page_count",
                         "pdf", "pdf_bytes", "pdf_sha256"})
_PAGE_FIELDS = frozenset({"page", "png", "sha256", "bytes"})

_DATE_RE = re.compile(r"^20\d{2}-\d{2}-\d{2}$")
_AMT_RE = re.compile(r"^[\d,]+\.\d{2}$")
_INT_RE = re.compile(r"^\d{1,2}$")
_PAGENO_RE = re.compile(r"^-\d{1,4}-$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class MaterialParseError(ValueError):
    """Typed parse-face failure; str() is a code, never material content."""

    error_code = "material_parse_invalid"


def _fail(code: str) -> "MaterialParseError":
    return MaterialParseError(code)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _norm_text(s: str) -> str:
    return re.sub(r"\s+", "", unicodedata.normalize("NFKC", s))


# ---------------------------------------------------------------- engine pin
_ENGINE = None
_ENGINE_PIN: dict | None = None

# 引擎线程钉定：固定值（非环境可变）保证单/多 worker 批跑与重抽结果一致；
# 批量吞吐靠多进程并行，不靠每进程线程堆叠（12 核机 6 worker×2 线程满载）。
OCR_INTRA_OP_THREADS = 2


def _get_engine():
    global _ENGINE
    if _ENGINE is None:
        from ..adapters.ocr.rapidocr import RapidOcrEngine

        _ENGINE = RapidOcrEngine(num_threads=OCR_INTRA_OP_THREADS)
    return _ENGINE


def engine_pin() -> dict:
    """引擎与模型钉定（离线、hash-locked；F40 四端口未到，本面单端口如实）。"""
    global _ENGINE_PIN
    if _ENGINE_PIN is None:
        import rapidocr

        files = []
        manifest = Path(__file__).resolve().parents[4] / "models" / "manifest.json"
        if manifest.exists():
            lock = json.loads(manifest.read_text(encoding="utf-8"))
            files = [{"path": f["path"], "sha256": f["sha256"]}
                     for f in lock.get("ocr", {}).get("files", [])]
        _ENGINE_PIN = {
            "engine": "rapidocr-onnx",
            "rapidocr_version": getattr(rapidocr, "__version__", "unknown"),
            "intra_op_threads": OCR_INTRA_OP_THREADS,
            "models": files,
        }
    return dict(_ENGINE_PIN)


# ------------------------------------------------------------ batch registry
def _batch_dir(state_root: Path, batch_id: str) -> Path:
    if not isinstance(batch_id, str) or not _SAFE_ID_RE.fullmatch(batch_id):
        raise _fail("parse_batch_id_invalid")
    return Path(state_root) / "material-parse" / batch_id


def _doc_key(doc_id: Any) -> str:
    if not isinstance(doc_id, str) or not _SAFE_ID_RE.fullmatch(doc_id):
        raise _fail("parse_doc_id_invalid")
    return doc_id


def register_batch(state_root: Path, corpus_root: Path) -> dict:
    """登记批次：读语料清单的**身份字段**建页任务清单（5000 页级分母）。

    同一语料（corpus_manifest.json 字节相同）重复登记=幂等返回；不同语料
    生成不同 batch_id。金标字段不在白名单内，本函数与解析全程都不读。
    """
    corpus_root = Path(corpus_root)
    manifest_path = corpus_root / "corpus_manifest.json"
    if not manifest_path.is_file():
        raise _fail("parse_corpus_manifest_missing")
    raw = manifest_path.read_bytes()
    corpus_sha = _sha256_bytes(raw)
    try:
        corpus = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _fail("parse_corpus_manifest_invalid") from None
    batch_id = "mp-" + corpus_sha[:12]
    bdir = _batch_dir(state_root, batch_id)
    batch_path = bdir / "batch.json"
    if batch_path.exists():
        existing = json.loads(batch_path.read_text(encoding="utf-8"))
        if existing.get("corpus_sha256") == corpus_sha:
            return _batch_summary(existing, bdir)
        raise _fail("parse_batch_id_collision")   # sha256 前 12 位撞车=fail-closed

    documents, page_index = [], {}
    for doc in corpus.get("documents", []):
        if not isinstance(doc, dict) or "doc_id" not in doc:
            raise _fail("parse_corpus_doc_invalid")
        doc_rec = {k: doc[k] for k in _DOC_FIELDS if k in doc}
        pages = []
        for pf in doc.get("page_files", []):
            if not isinstance(pf, dict) or "page" not in pf or "png" not in pf:
                raise _fail("parse_corpus_page_invalid")
            task = {k: pf[k] for k in _PAGE_FIELDS if k in pf}
            pages.append(task)
            page_index[(doc["doc_id"], int(pf["page"]))] = task
        doc_rec["pages"] = pages
        documents.append(doc_rec)
    if not documents:
        raise _fail("parse_corpus_empty")

    batch = {
        "schema": SCHEMA,
        "batch_id": batch_id,
        "corpus_root": str(corpus_root.resolve()),
        "corpus_sha256": corpus_sha,
        "registered_pages": len(page_index),
        "documents": documents,
        "engine_pin": engine_pin(),
    }
    bdir.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(
        bdir / "batch.json",
        json.dumps(batch, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8"))
    return _batch_summary(batch, bdir)


def _load_batch(state_root: Path, batch_id: str) -> tuple[dict, Path]:
    bdir = _batch_dir(state_root, batch_id)
    path = bdir / "batch.json"
    if not path.is_file():
        raise _fail("parse_batch_not_registered")
    batch = json.loads(path.read_text(encoding="utf-8"))
    if batch.get("schema") != SCHEMA:
        raise _fail("parse_batch_schema_unsupported")
    return batch, bdir


def _batch_summary(batch: dict, bdir: Path) -> dict:
    return {
        "batch_id": batch["batch_id"],
        "corpus_sha256": batch["corpus_sha256"],
        "registered_pages": batch["registered_pages"],
        "documents": len(batch["documents"]),
        "engine": batch["engine_pin"]["engine"],
    }


def _page_tasks(batch: dict) -> list[dict]:
    tasks = []
    for doc in batch["documents"]:
        for task in doc["pages"]:
            tasks.append({"doc_id": doc["doc_id"], **task})
    tasks.sort(key=lambda t: (t["doc_id"], int(t["page"])))
    return tasks


def _page_path(bdir: Path, doc_id: str, page: int) -> Path:
    return bdir / "pages" / _doc_key(doc_id) / f"p{page:04d}.json"


def pending_pages(state_root: Path, batch_id: str) -> list[dict]:
    """无完成记录的页（局部恢复的驱动面；不凭 PNG 存在=已读）。"""
    batch, bdir = _load_batch(state_root, batch_id)
    pending = []
    for task in _page_tasks(batch):
        if not _page_path(bdir, task["doc_id"], int(task["page"])).is_file():
            pending.append({"doc_id": task["doc_id"], "page": int(task["page"])})
    return pending


# ------------------------------------------------------------------- parsing
def _classify_cells(lines: list[dict]) -> list[dict]:
    """模式格→行聚类（阅读序=页内自上而下）。确定性几何，无模型猜测。"""
    cells = []
    page_h = max((l["bbox"][3] for l in lines), default=0)
    for line in lines:
        text = _norm_text(line["text"])
        if (_DATE_RE.fullmatch(text) or _AMT_RE.fullmatch(text)
                or _INT_RE.fullmatch(text) or text == "合计"):
            cells.append({"text": text, "bbox": line["bbox"], "conf": line["conf"]})
    if not cells:
        return []
    tol = max(12.0, page_h * _ROW_Y_TOL_FRAC)
    cells.sort(key=lambda c: ((c["bbox"][1] + c["bbox"][3]) / 2, c["bbox"][0]))
    rows: list[dict] = []
    for cell in cells:
        yc = (cell["bbox"][1] + cell["bbox"][3]) / 2
        if rows and abs(yc - rows[-1]["yc"]) <= tol:
            rows[-1]["cells"].append(cell)
            n = len(rows[-1]["cells"])
            rows[-1]["yc"] = rows[-1]["yc"] * (n - 1) / n + yc / n
        else:
            rows.append({"yc": yc, "cells": [cell]})
    table_rows = []
    for row in rows:
        row["cells"].sort(key=lambda c: c["bbox"][0])
        amounts = sum(1 for c in row["cells"] if _AMT_RE.fullmatch(c["text"]))
        if len(row["cells"]) >= _TABLE_MIN_CELLS and amounts >= _TABLE_MIN_AMOUNTS:
            table_rows.append({
                "page_row_index": len(table_rows),
                "cells": row["cells"],
            })
    return table_rows


def _parse_one(batch: dict, bdir: Path, doc_id: str, page_no: int,
               task: dict, dup_index: dict) -> dict:
    """解析单页并返回页记录（不落盘；落盘由调用方原子提交）。"""
    from PIL import Image

    record: dict[str, Any] = {
        "schema": SCHEMA,
        "batch_id": batch["batch_id"],
        "doc_id": doc_id,
        "page": page_no,
        "png_ref": task.get("png"),
        "png_sha256": None,
        "bytes": task.get("bytes"),
        "geom": None,
        "signal": None,
        "signal_detail": None,
        "parse_count": 1,
        "engine": None,
        "ink": None,
        "duplicate_of": None,
        "page_no": {"versions": [], "current_version": None},
        "table_rows": [],
    }
    png_path = Path(batch["corpus_root"]) / task["png"]
    try:
        payload = png_path.read_bytes()
    except OSError:
        record["signal"], record["signal_detail"] = "UNREAD_FAILED", "png_unreadable"
        return record
    sha = _sha256_bytes(payload)
    record["png_sha256"] = sha
    if task.get("sha256") and sha != task["sha256"]:
        # 原件只读红线：字节与登记时不符=拒解析（fail-closed，不是复刻旧值）
        record["signal"], record["signal_detail"] = "UNREAD_FAILED", "page_bytes_mismatch"
        return record

    try:
        img = Image.open(png_path)
        img.load()
        luma_min = img.convert("L").getextrema()[0]
        w, h = img.size
    except Exception as exc:  # noqa: BLE001 - 分类面，异常类别入账
        record["signal"] = "UNREAD_FAILED"
        record["signal_detail"] = f"decode:{type(exc).__name__}"
        return record
    record["geom"] = {"w": w, "h": h}
    if luma_min >= BLANK_MIN_LUMA:
        # 空白判定先于重复判定：纯白页彼此字节恒同（无帧无内容），
        # 语义上仍是空白页，不是「某内容页的复刻」。
        record["signal"] = "BLANK"
        return record

    src = dup_index.get(sha)
    if src is not None and src != (doc_id, page_no):
        record["signal"] = "DUPLICATE"
        record["duplicate_of"] = {"doc_id": src[0], "page": src[1]}
        return record

    try:
        ocr_lines, _ok = _get_engine().run(img)
    except Exception as exc:  # noqa: BLE001
        record["signal"] = "UNREAD_FAILED"
        record["signal_detail"] = f"engine:{type(exc).__name__}"
        return record

    lines = [{"text": l.text, "bbox": list(l.box), "conf": round(l.confidence, 4)}
             for l in ocr_lines]
    record["engine"] = {
        **engine_pin(),
        "lines": len(lines),
        "avg_conf": None if not lines else round(
            sum(l["conf"] for l in lines) / len(lines), 4),
        "min_conf": None if not lines else min(l["conf"] for l in lines),
        "low_conf_lines": sum(1 for l in lines
                              if l["conf"] < LOW_CONFIDENCE_THRESHOLD),
    }
    record["ink"] = {
        "lines_top_half": sum(1 for l in lines
                              if (l["bbox"][1] + l["bbox"][3]) / 2 < h / 2),
        "lines_bottom_half": sum(1 for l in lines
                                 if (l["bbox"][1] + l["bbox"][3]) / 2 >= h / 2),
    }
    if not lines:
        # 非空白页 OCR 零行=空识别（单独计数，不是读成功也不是失败）
        record["signal"] = "EMPTY_RECOGNITION"
        return record
    if record["engine"]["avg_conf"] < LOW_CONFIDENCE_THRESHOLD:
        record["signal"] = "LOW_CONFIDENCE"
    else:
        record["signal"] = "READ_OK"

    # 页号提取：页脚 "- N -"（结构性事实，带 bbox 入版本链）
    page_no_hits = [l for l in lines if _PAGENO_RE.fullmatch(_norm_text(l["text"]))]
    if page_no_hits:
        hit = max(page_no_hits, key=lambda l: l["conf"])
        record["page_no"] = {
            "versions": [{"version": 1, "source": "engine",
                          "text": hit["text"], "bbox": hit["bbox"],
                          "confidence": hit["conf"]}],
            "current_version": 1,
        }
    record["table_rows"] = _classify_cells(lines)
    return record


def process_pages(state_root: Path, batch_id: str,
                  pages: list[dict] | None = None) -> dict:
    """处理页（幂等：已有完成记录=跳过；原子提交，中断=无记录即未处理）。

    pages=None → 全部待处理页（局部恢复：不重不漏）；否则只处理指定页。
    返回处理计数与信号分布（错误码不携材料内容）。
    """
    batch, bdir = _load_batch(state_root, batch_id)
    corpus_root = Path(batch["corpus_root"])
    if not (corpus_root / "corpus_manifest.json").is_file():
        raise _fail("parse_corpus_root_missing")

    # 同卷更早同字节页索引（重复页检测：与处理顺序无关，来自登记清单）
    seen: dict[str, tuple[str, int]] = {}
    dup_index: dict[str, tuple[str, int]] = {}
    for doc in batch["documents"]:
        for task in doc["pages"]:
            sha = task.get("sha256")
            page = int(task["page"])
            if sha and sha in seen and seen[sha][0] == doc["doc_id"]:
                dup_index[sha] = seen[sha]
            if sha and sha not in seen:
                seen[sha] = (doc["doc_id"], page)

    task_map = {(t["doc_id"], int(t["page"])): t for t in _page_tasks(batch)}
    if pages is None:
        todo = [dict(t, page=int(t["page"])) for t in task_map.values()]
    else:
        todo = []
        for item in pages or []:
            if not isinstance(item, dict):
                raise _fail("parse_pages_arg_invalid")
            key = (_doc_key(item.get("doc_id")), item.get("page"))
            if (isinstance(key[1], bool) or not isinstance(key[1], int)
                    or key not in task_map):
                raise _fail("parse_page_not_in_batch")
            todo.append({**task_map[key], "doc_id": key[0], "page": key[1]})

    processed = skipped = 0
    signals: dict[str, int] = {}
    for task in todo:
        doc_id, page_no = task["doc_id"], int(task["page"])
        ppath = _page_path(bdir, doc_id, page_no)
        if ppath.is_file():
            skipped += 1
            continue
        record = _parse_one(batch, bdir, doc_id, page_no, task, dup_index)
        if record["signal"] not in SIGNALS:
            raise _fail("parse_signal_out_of_closed_set")   # 闭集外=编程错误
        ppath.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(
            ppath, json.dumps(record, ensure_ascii=False, indent=1,
                              sort_keys=True).encode("utf-8"))
        processed += 1
        signals[record["signal"]] = signals.get(record["signal"], 0) + 1
    return {"batch_id": batch_id, "processed": processed,
            "skipped_existing": skipped, "signals": dict(sorted(signals.items()))}


# ------------------------------------------------------------------ readback
def _load_page(state_root: Path, batch_id: str, doc_id: str, page: int) -> tuple[dict, Path]:
    if isinstance(page, bool) or not isinstance(page, int) or page < 1:
        raise _fail("parse_page_invalid")
    batch, bdir = _load_batch(state_root, batch_id)
    if (doc_id, page) not in {(t["doc_id"], int(t["page"]))
                              for t in _page_tasks(batch)}:
        raise _fail("parse_page_not_in_batch")
    ppath = _page_path(bdir, _doc_key(doc_id), page)
    if not ppath.is_file():
        raise _fail("parse_page_not_processed")
    record = json.loads(ppath.read_text(encoding="utf-8"))
    if record.get("signal") not in SIGNALS:
        raise _fail("parse_record_corrupt")
    return record, ppath


def read_page(state_root: Path, batch_id: str, doc_id: str, page: int) -> dict:
    """回读页记录（含页号版本链与当前版本）。"""
    record, _ppath = _load_page(state_root, batch_id, doc_id, page)
    return dict(record)


def human_edit(state_root: Path, batch_id: str, doc_id: str, page: int,
               page_no_text: Any) -> dict:
    """人改不覆·入账：人工修订页号文本 → 追加 human 版本并成为当前版本。

    只追加，不改不删既有版本；后续重扫（reparse_page）永不触碰 human 版本。
    """
    record, ppath = _load_page(state_root, batch_id, doc_id, page)
    if not isinstance(page_no_text, str) or not page_no_text.strip():
        raise _fail("parse_human_edit_text_invalid")
    versions = record["page_no"]["versions"]
    new_version = max((v["version"] for v in versions), default=0) + 1
    versions.append({"version": new_version, "source": "human",
                     "text": page_no_text.strip(), "bbox": None,
                     "confidence": None})
    record["page_no"]["current_version"] = new_version
    atomic_write_bytes(
        ppath, json.dumps(record, ensure_ascii=False, indent=1,
                          sort_keys=True).encode("utf-8"))
    return {"doc_id": doc_id, "page": page, "version": new_version,
            "source": "human",
            "current_version": new_version,
            "versions_total": len(versions)}


def reparse_page(state_root: Path, batch_id: str, doc_id: str, page: int) -> dict:
    """单页重抽（F41 语义：重抽版本不删；人改版本永不被覆盖）。

    重跑引擎解析覆盖信号/引擎统计/表格行，页号提取追加新 engine 版本；
    human 版本原样保留，当前版本仍指向最新 human 版本（人改不覆）。
    """
    old, ppath = _load_page(state_root, batch_id, doc_id, page)
    batch, bdir = _load_batch(state_root, batch_id)
    task = next(t for t in _page_tasks(batch)
                if t["doc_id"] == doc_id and int(t["page"]) == page)
    seen: dict[str, tuple[str, int]] = {}
    dup_index: dict[str, tuple[str, int]] = {}
    for doc in batch["documents"]:
        for t in doc["pages"]:
            sha, p = t.get("sha256"), int(t["page"])
            if sha and sha in seen and seen[sha][0] == doc["doc_id"]:
                dup_index[sha] = seen[sha]
            if sha and sha not in seen:
                seen[sha] = (doc["doc_id"], p)
    fresh = _parse_one(batch, bdir, doc_id, page, task, dup_index)
    fresh["parse_count"] = int(old.get("parse_count", 1)) + 1

    old_versions = old["page_no"]["versions"]
    human_versions = [v for v in old_versions if v["source"] == "human"]
    new_versions = list(old_versions)
    if fresh["page_no"]["versions"]:
        hit = fresh["page_no"]["versions"][0]
        new_versions.append({"version": max((v["version"] for v in old_versions),
                                            default=0) + 1,
                             "source": "engine", "text": hit["text"],
                             "bbox": hit["bbox"], "confidence": hit["confidence"]})
    fresh["page_no"] = {
        "versions": new_versions,
        "current_version": (human_versions[-1]["version"] if human_versions
                            else new_versions[-1]["version"] if new_versions
                            else None),
    }
    if fresh["signal"] not in SIGNALS:
        raise _fail("parse_signal_out_of_closed_set")
    atomic_write_bytes(
        ppath, json.dumps(fresh, ensure_ascii=False, indent=1,
                          sort_keys=True).encode("utf-8"))
    return {"doc_id": doc_id, "page": page, "signal": fresh["signal"],
            "parse_count": fresh["parse_count"],
            "page_no_current_version": fresh["page_no"]["current_version"],
            "human_versions_kept": len(human_versions)}


def _column_medians(group_rows: list[list[dict]]) -> list[float]:
    """列心定位：取满列行的各槽位 x 心中位数（确定性，无模型猜测）。

    满列行 = 格数等于组内最大格数的行；列数=最大格数。缺列的行（如合计行）
    由调用方按最近列心归位——列心来自多数满列行，不受缺格行影响。
    """
    if not group_rows:
        return []
    ncols = min(max(len(r) for r in group_rows), 12)
    full_rows = [r for r in group_rows if len(r) == ncols]
    if not full_rows:
        return []
    medians = []
    for slot in range(ncols):
        xs = sorted(((c["bbox"][0] + c["bbox"][2]) / 2)
                    for c in (r[slot] for r in full_rows))
        medians.append(xs[len(xs) // 2])
    return medians


def table_rows(state_root: Path, batch_id: str, doc_id: str) -> dict:
    """跨页表阅读序组装：同卷连续表页 → 一组，行序=(页,页内行)。

    列位由满列行各槽位 x 心中位数定位（缺格=空位，不编造文本）；金额保持
    字符串原样（整分纪律在语料侧，本面不改写数值）。
    """
    batch, bdir = _load_batch(state_root, batch_id)
    doc = next((d for d in batch["documents"] if d["doc_id"] == doc_id), None)
    if doc is None:
        raise _fail("parse_doc_not_in_batch")
    pages_data = []
    for task in sorted(doc["pages"], key=lambda t: int(t["page"])):
        page = int(task["page"])
        ppath = _page_path(bdir, doc_id, page)
        if not ppath.is_file():
            continue
        record = json.loads(ppath.read_text(encoding="utf-8"))
        if record.get("table_rows"):
            pages_data.append((page, record["table_rows"]))
    groups, current = [], None
    for page, rows in pages_data:
        if current is not None and page == current["pages"][-1] + 1:
            current["pages"].append(page)
            current["rows"].extend((page, r) for r in rows)
        else:
            current = {"pages": [page], "rows": [(page, r) for r in rows]}
            groups.append(current)
    out_groups = []
    for gi, group in enumerate(groups):
        row_cells = [sorted(r["cells"], key=lambda c: c["bbox"][0])
                     for _, r in group["rows"]]
        medians = _column_medians(row_cells)
        out_rows = []
        for (page, row), cells in zip(group["rows"], row_cells):
            slots: list[dict | None] = [None] * len(medians)
            for cell in cells:
                xc = (cell["bbox"][0] + cell["bbox"][2]) / 2
                slot = min(range(len(medians)),
                           key=lambda i: (abs(xc - medians[i]), i))
                if slots[slot] is None or (
                        abs(xc - medians[slot])
                        < abs((slots[slot]["bbox"][0] + slots[slot]["bbox"][2]) / 2
                              - medians[slot])):
                    slots[slot] = {"text": cell["text"], "bbox": cell["bbox"],
                                   "confidence": cell["conf"]}
            out_rows.append({
                "page": page,
                "page_row_index": row["page_row_index"],
                "cells": slots,
            })
        out_groups.append({
            "group_index": gi,
            "pages": [group["pages"][0], group["pages"][-1]],
            "columns": len(medians),
            "rows": out_rows,
        })
    return {"batch_id": batch_id, "doc_id": doc_id, "groups": out_groups}


def batch_report(state_root: Path, batch_id: str) -> dict:
    """分母报告：登记/完成/待处理＋信号闭集分别计数（不凭文件存在已读）。

    完成记录数与信号计数来自**解析记录文件**（PNG 存在不计入完成）；闭集外
    信号或登记外记录=corrupt 计数（fail-closed 标志，绝不并入通过计数）。
    """
    batch, bdir = _load_batch(state_root, batch_id)
    registered = set()
    for t in _page_tasks(batch):
        registered.add((t["doc_id"], int(t["page"])))
    signals: dict[str, int] = {s: 0 for s in sorted(SIGNALS)}
    completed, corrupt = 0, []
    for ppath in bdir.glob("pages/*/*.json"):
        try:
            record = json.loads(ppath.read_text(encoding="utf-8"))
            key = (record["doc_id"], int(record["page"]))
            signal = record.get("signal")
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            corrupt.append("record_undecodable")
            continue
        if key not in registered:
            corrupt.append("record_outside_batch")
            continue
        if signal not in SIGNALS:
            corrupt.append("signal_out_of_closed_set")
            continue
        signals[signal] += 1
        completed += 1
    return {
        "batch_id": batch_id,
        "registered_pages": len(registered),
        "completed": completed,
        "pending": len(registered) - completed,
        "signals": signals,
        "corrupt_records": len(corrupt),
        "existence_is_not_read": True,
    }
