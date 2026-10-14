"""F09 overlay revisions: 原文件夹绝对只读 + user_overrides_json 覆盖层（W2a-U05）。

义务 06:10/17:10：原件字节不变；校对/修改覆盖层（user_overrides_json）
形成新 revision 并可回读旧件。与「原件不出域」边界天然兼容：本服务只在
**脱敏视图**（revision 1＝pipeline 首版 sanitized 文本）上叠加人工覆盖层，
原件文件只读（每次修订先复验 sha256，变了＝fail-closed），Vault/身份映射
从不进入本服务的输入输出与错误。

确定性纪律（红线）：覆盖层闭集两操作（redact_span / replace_text），逐条
按文档序应用；应用失败（越界/找不到目标/无实效）＝typed error，不静默
no-op 假成功；最终字节经确定性检测器复扫——覆盖层把正则可捕获 PII 带回
＝拒绝（错误只带类别与计数，永不携带表面值）。

存储布局（全合成/脱敏内容，egress-safe）::

    <state_root>/<matter_id>/overlay/<document_id>/revisions.json
    <state_root>/<matter_id>/overlay/<document_id>/rev-0001.txt ...

All test data synthetic; originals are read-only snapshots (AGENTS.md rule 4).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..contracts.canonical import canonical_hash
from ..detectors import detect as _detect

OVERLAY_OPS = frozenset({"redact_span", "replace_text"})
_LOCALE = "zh"


class OverlayError(ValueError):
    """Typed overlay failure; str carries a code, never a surface value."""

    error_code = "overlay_invalid"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fail(code: str) -> "OverlayError":
    return OverlayError(code)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _doc_dir(state_root: Path, matter_id: str, document_id: str) -> Path:
    if not matter_id or not document_id:
        raise _fail("overlay_document_invalid")
    base = Path(state_root) / matter_id / "overlay" / document_id
    for part in (matter_id, document_id):
        if part in {".", ".."} or "/" in part or "\\" in part or ":" in part:
            raise _fail("overlay_document_invalid")
    return base


def _load_ledger(doc_dir: Path) -> list[dict]:
    path = doc_dir / "revisions.json"
    if not path.exists():
        raise _fail("overlay_document_not_registered")
    ledger = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(ledger, list) or not ledger:
        raise _fail("overlay_ledger_corrupt")
    return ledger


def _write_ledger(doc_dir: Path, ledger: list[dict]) -> None:
    from ..security.safe_storage import atomic_write_bytes

    atomic_write_bytes(
        doc_dir / "revisions.json",
        json.dumps(ledger, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"),
    )


def _write_revision_text(doc_dir: Path, revision: int, text: str) -> None:
    from ..security.safe_storage import atomic_write_bytes

    atomic_write_bytes(
        doc_dir / f"rev-{revision:04d}.txt", text.encode("utf-8"))


def _read_revision_text(doc_dir: Path, revision: int) -> str:
    path = doc_dir / f"rev-{revision:04d}.txt"
    if not path.exists():
        raise _fail("overlay_revision_missing")
    return path.read_text(encoding="utf-8")


def _verify_original(original_path: Path, expected_sha256: str) -> None:
    """原件只读红线：每次修订复验原件字节未变；缺文件/被改写都 fail-closed。"""
    if not original_path.is_file():
        raise _fail("overlay_original_missing")
    if _sha256_bytes(original_path.read_bytes()) != expected_sha256:
        raise _fail("overlay_original_mutated")


def _rescan_refuses_catchable_pii(text: str) -> None:
    """最终字节复扫（确定性层）：正则可捕获 PII 残留＝拒绝（不假成功）。

    错误只携带类别与计数，永不携带表面值（AGENTS.md 规则 2）。
    """
    spans = _detect(text, _LOCALE)
    if spans:
        categories: dict[str, int] = {}
        for span in spans:
            categories[span.category] = categories.get(span.category, 0) + 1
        detail = ",".join(f"{k}x{v}" for k, v in sorted(categories.items()))
        raise _fail(f"overlay_introduces_catchable_pii:{len(spans)}:{detail}")


def _apply_ops(text: str, user_overrides: Any) -> tuple[str, int]:
    """闭集两操作逐条按文档序应用；任何失败＝typed error（不静默 no-op）。"""
    if not isinstance(user_overrides, list) or not user_overrides:
        raise _fail("overlay_overrides_invalid")
    applied = 0
    for index, op in enumerate(user_overrides):
        if not isinstance(op, dict) or op.get("op") not in OVERLAY_OPS:
            raise _fail(f"overlay_op_invalid:{index}")
        if op["op"] == "redact_span":
            if set(op) != {"op", "start", "end", "replacement"}:
                raise _fail(f"overlay_op_fields_not_closed:{index}")
            start, end, replacement = op["start"], op["end"], op["replacement"]
            if (isinstance(start, bool) or isinstance(end, bool)
                    or not isinstance(start, int) or not isinstance(end, int)
                    or not 0 <= start < end <= len(text)):
                raise _fail(f"overlay_span_out_of_bounds:{index}")
            if not isinstance(replacement, str) or not replacement:
                raise _fail(f"overlay_replacement_invalid:{index}")
            text = text[:start] + replacement + text[end:]
        else:  # replace_text
            if set(op) != {"op", "find", "replace"}:
                raise _fail(f"overlay_op_fields_not_closed:{index}")
            find, replace = op["find"], op["replace"]
            if (not isinstance(find, str) or not find
                    or not isinstance(replace, str) or find == replace):
                raise _fail(f"overlay_replace_invalid:{index}")
            if find not in text:
                # 目标不存在＝人工校对意图无法落地：拒绝，绝不静默跳过。
                raise _fail(f"overlay_target_missing:{index}")
            text = text.replace(find, replace)
        applied += 1
    return text, applied


def register_document(state_root: Path, matter_id: str, document_id: str,
                      original_path: Path, sanitized_text: str) -> dict:
    """F09 revision 1：绑定只读原件（sha256 入账，永不改写）＋首版脱敏视图。

    sanitized_text 必须已经过 P10 deidentify：正则可捕获 PII 残留＝拒绝
    （base_not_sanitized）；person 等 NER 层残留不在本面强拦——那是人审
    （REVIEW_REQUIRED，E11）的诚实缺口，不是本服务的假成功。
    """
    if not isinstance(sanitized_text, str) or not sanitized_text:
        raise _fail("overlay_base_text_invalid")
    original_path = Path(original_path)
    if not original_path.is_file():
        raise _fail("overlay_original_missing")
    original_sha = _sha256_bytes(original_path.read_bytes())
    try:
        _rescan_refuses_catchable_pii(sanitized_text)
    except OverlayError:
        raise _fail("overlay_base_not_sanitized") from None
    doc_dir = _doc_dir(state_root, matter_id, document_id)
    if (doc_dir / "revisions.json").exists():
        raise _fail("overlay_document_already_registered")
    doc_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "schema_version": "1.0",
        "matterId": matter_id,
        "documentId": document_id,
        "revision": 1,
        "origin": "pipeline",
        "originalPath": str(original_path),
        "originalSha256": original_sha,
        "textSha256": _sha256_bytes(sanitized_text.encode("utf-8")),
        "overridesDigest": None,
        "appliedOps": 0,
        "recordedAt": _now(),
    }
    _write_revision_text(doc_dir, 1, sanitized_text)
    _write_ledger(doc_dir, [record])
    return dict(record)


def apply_overlay(state_root: Path, matter_id: str, document_id: str,
                  user_overrides: Any) -> dict:
    """F09 校对/修改覆盖层：当前头 revision ＋ user_overrides → 新 revision。

    原件字节不变（复验 sha256）；旧 revision 文件原样保留可回读；最终字节
    复扫拒绝可捕获 PII 回带；无实效（新文本与旧文本相同）＝拒绝。
    """
    doc_dir = _doc_dir(state_root, matter_id, document_id)
    ledger = _load_ledger(doc_dir)
    head = ledger[-1]
    _verify_original(Path(head["originalPath"]), head["originalSha256"])
    base_text = _read_revision_text(doc_dir, int(head["revision"]))
    new_text, applied = _apply_ops(base_text, user_overrides)
    if new_text == base_text:
        raise _fail("overlay_no_effect")
    _rescan_refuses_catchable_pii(new_text)
    new_revision = int(head["revision"]) + 1
    record = {
        "schema_version": "1.0",
        "matterId": matter_id,
        "documentId": document_id,
        "revision": new_revision,
        "origin": "user_overrides",
        "originalPath": head["originalPath"],
        "originalSha256": head["originalSha256"],
        "textSha256": _sha256_bytes(new_text.encode("utf-8")),
        "overridesDigest": canonical_hash({"ops": user_overrides},
                                          schema_version="1.0"),
        "appliedOps": applied,
        "baseRevision": int(head["revision"]),
        "recordedAt": _now(),
    }
    _write_revision_text(doc_dir, new_revision, new_text)
    ledger.append(record)
    _write_ledger(doc_dir, ledger)
    return dict(record)


def read_revision(state_root: Path, matter_id: str, document_id: str,
                  revision: int) -> dict:
    """回读任一旧 revision（record＋脱敏文本）——F09「可回读旧件」。"""
    doc_dir = _doc_dir(state_root, matter_id, document_id)
    ledger = _load_ledger(doc_dir)
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise _fail("overlay_revision_invalid")
    for record in ledger:
        if int(record["revision"]) == revision:
            return {"record": dict(record),
                    "text": _read_revision_text(doc_dir, revision)}
    raise _fail("overlay_revision_missing")


def list_revisions(state_root: Path, matter_id: str,
                   document_id: str) -> dict:
    """全 revision 清点（record 列表；不携带文本正文）。"""
    doc_dir = _doc_dir(state_root, matter_id, document_id)
    ledger = _load_ledger(doc_dir)
    return {"matterId": matter_id, "documentId": document_id,
            "revisions": [dict(record) for record in ledger],
            "currentRevision": int(ledger[-1]["revision"])}
