"""Surface normalization functions. Each format has its own normalization;
none of them merge different people by surname, and none apply aggressive
pinyin folding to natural-person names."""

from __future__ import annotations

import re
import unicodedata

# Company / organization suffixes stripped when normalizing org surfaces.
ORG_SUFFIXES = (
    "股份有限公司", "有限责任公司", "有限公司", "集团公司", "总公司", "分公司",
    "公司", "事务所", "中心", "研究院", "研究所", "项目部", "指挥部", "分公司",
)

_FULLWIDTH = str.maketrans(
    "０１２３４５６７８９ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ：；，．（）",
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz:;,.()",
)

_PUNCT_RE = re.compile(r"[\s\u3000]+")
_CN_PUNCT_RE = re.compile(r"[，、。；：！？（）【】《》“”‘’·]")


def _nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def _base_normalize(text: str) -> str:
    return _PUNCT_RE.sub("", _nfkc(text).translate(_FULLWIDTH)).strip()


def normalize_person_surface(text: str) -> str:
    """Conservative person normalization: no pinyin folding, no surname-only folding."""
    return _base_normalize(text)


def normalize_org_surface(text: str) -> str:
    """Org normalization: full/half width, whitespace/punct removal, bracket short
    forms and '以下简称' expansions handled by callers; suffix stripping here."""
    base = _base_normalize(text)
    base = _CN_PUNCT_RE.sub("", base)
    lowered = base.lower()
    for suffix in ORG_SUFFIXES:
        tail = suffix.translate(_FULLWIDTH)
        if lowered.endswith(tail.lower()):
            base = base[: len(base) - len(tail)]
            break
    return base


def normalize_phone(text: str) -> str:
    digits = re.sub(r"[^0-9+]", "", _nfkc(text))
    if digits.startswith("+86"):
        digits = digits[3:]
    elif digits.startswith("86") and len(digits) == 13:
        digits = digits[2:]
    return digits


def normalize_id(text: str) -> str:
    return _nfkc(text).strip().upper()


def normalize_address(text: str) -> str:
    return _base_normalize(text)


# Common OCR confusions (shape-similar). Applied symmetrically on both sides of
# candidate comparisons only — never on the canonical raw surface itself.
_OCR_EQUIV = {
    "0": "oO。", "1": "lI|i｜", "2": "zZ", "5": "sS", "8": "bB",
    "末": "未", "己": "已", "土": "士", "千": "干", "日": "曰",
}


def _ocr_fold(text: str) -> str:
    out = []
    for ch in text:
        mapped = ch
        for canonical, variants in _OCR_EQUIV.items():
            if ch == canonical or ch in variants:
                mapped = canonical
                break
        out.append(mapped)
    return "".join(out)


def normalize_ocr_surface(text: str) -> str:
    return _ocr_fold(_base_normalize(text))


def surfaces_match_ocr(a: str, b: str) -> bool:
    """OCR-tolerant equality used only as *weak* candidate evidence."""
    return normalize_ocr_surface(a) == normalize_ocr_surface(b)
