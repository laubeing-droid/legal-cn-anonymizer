"""Typed transform functions. Every profile transform is explicit; nothing is
guessed when a profile lacks configuration. Money and legal event dates are
never transformed (KEEP is the only legal behavior for them in ai-safe)."""

from __future__ import annotations

import re

from ..contracts.statuses import TransformKind
from .mentions import Span

_CN_DIGITS = "〇零一二三四五六七八九"
_MONEY_RE = re.compile(
    r"(?:人民币|￥|¥|元)?\s*[0-9][0-9,，]*(?:\.[0-9]+)?\s*(?:万元|万元整|亿元|元整|元)|"
    r"[零一二三四五六七八九十百千万亿]+(?:元整|元)"
)
_DATE_RE = re.compile(r"[0-9]{4}\s*年\s*[0-9]{1,2}\s*月\s*[0-9]{1,2}\s*日")


def pseudonymize(text: str, start: int, end: int, display_alias: str) -> Span:
    return Span(start, end, display_alias)


def mask_keep_last_4(value: str) -> str:
    """Keep the last 4 characters (or digits) and mask the rest; short values are
    fully masked to avoid leaking more than intended."""
    v = value.strip()
    if len(v) <= 4:
        return "*" * len(v)
    return "*" * (len(v) - 4) + v[-4:]


def mask_keep_first_1(value: str) -> str:
    v = value.strip()
    if len(v) <= 1:
        return "*"
    return v[0] + "*" * (len(v) - 1)


def generalize_birth_date(value: str) -> str:
    """出生日期 -> 出生年份. Ambiguous dates must NOT be silently generalized
    (callers decide), but an explicit birth context is safe to reduce."""
    m = _DATE_RE.search(value)
    if m:
        year = re.sub(r"[^0-9]", "", m.group(0).split("年")[0])
        return f"{year}年出生"
    year = re.search(r"[0-9]{4}", value)
    if year:
        return f"{year.group(0)}年出生"
    return "REVIEW"


def _strip_admin_tail(address: str, levels: int) -> str:
    """Cut the address after the Nth administrative unit (省/市/区县)."""
    units = list(re.finditer(r"[^省市区县]{1,8}(?:省|市|区|县|自治州)", address))
    if not units:
        return "REVIEW"
    if len(units) < levels:
        return "REVIEW"
    return address[: units[levels - 1].end()]


def generalize_personal_address(value: str) -> str:
    """个人精确地址 -> 省/市/区 + 某住所."""
    head = _strip_admin_tail(value.strip(), 3)
    if head == "REVIEW":
        return head
    return head + "某住所"


def generalize_project_address(value: str) -> str:
    """工程精确地址 -> 省/市/区 + 项目A (display alias supplied by caller)."""
    head = _strip_admin_tail(value.strip(), 3)
    if head == "REVIEW":
        return head
    return head + "{PROJECT}"


class TransformExecutor:
    """Executes a typed transform for one entity surface at one locator."""

    @staticmethod
    def span_for(
        kind: str,
        surface: str,
        start: int,
        end: int,
        display_alias: str | None = None,
    ) -> Span:
        if kind == TransformKind.PSEUDONYMIZE.value:
            if not display_alias:
                raise ValueError("PSEUDONYMIZE requires display_alias")
            return Span(start, end, display_alias)
        if kind == TransformKind.MASK_KEEP_LAST_4.value:
            return Span(start, end, mask_keep_last_4(surface))
        if kind == TransformKind.MASK_KEEP_FIRST_1.value:
            return Span(start, end, mask_keep_first_1(surface))
        if kind == TransformKind.GENERALIZE_YEAR.value:
            return Span(start, end, generalize_birth_date(surface))
        if kind == TransformKind.GENERALIZE_ADMIN_DIVISION.value:
            result = generalize_personal_address(surface)
            if result == "REVIEW":
                return Span(start, end, surface)  # caller must have flagged REVIEW
            return Span(start, end, result)
        if kind == TransformKind.PHYSICAL_REDACT.value:
            return Span(start, end, "█" * max(1, end - start))
        if kind == TransformKind.KEEP.value:
            return Span(start, end, surface)
        if kind == TransformKind.REVIEW.value:
            return Span(start, end, surface)
        raise ValueError(f"transform {kind} cannot produce a text span here")

    @staticmethod
    def project_address_span(value: str, start: int, end: int, display_alias: str) -> Span:
        head = generalize_project_address(value)
        if head == "REVIEW":
            return Span(start, end, value)
        return Span(start, end, head.replace("{PROJECT}", display_alias))


def extract_money_surfaces(text: str) -> list[str]:
    return _MONEY_RE.findall(text)


def extract_legal_date_surfaces(text: str) -> list[str]:
    return _DATE_RE.findall(text)
