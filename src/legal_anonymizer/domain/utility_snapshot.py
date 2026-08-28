"""Utility snapshot: mechanical multiset extraction of money amounts and legal
event dates, used by the independent Utility Gate to prove conservation."""

from __future__ import annotations

import re

_MONEY_RE = re.compile(
    r"(?:人民币|￥|¥)\s*[0-9][0-9,，]*(?:\.[0-9]+)?\s*(?:万元|亿元|元)|"
    r"[0-9][0-9,，]*(?:\.[0-9]+)?\s*(?:万元|亿元|元整|元)|"
    r"[零一二三四五六七八九十百千万亿]+(?:元整|元)"
)
_DATE_RE = re.compile(r"[0-9]{4}\s*年\s*[0-9]{1,2}\s*月\s*[0-9]{1,2}\s*日")
PERCENT_RE = re.compile(r"[0-9]+(?:\.[0-9]+)?\s*%")


def _canon_number(surface: str) -> str:
    return surface.replace(",", "").replace("，", "").replace(" ", "")


def money_multiset(text: str) -> list[str]:
    """Canonical money multiset: each amount normalized (commas stripped)."""
    return sorted(_canon_number(m) for m in _MONEY_RE.findall(text))


def legal_date_multiset(text: str) -> list[str]:
    return sorted(_canon_number(d) for d in _DATE_RE.findall(text))


def percent_multiset(text: str) -> list[str]:
    return sorted(_canon_number(p) for p in PERCENT_RE.findall(text))


def multiset_difference(a: list[str], b: list[str]) -> dict[str, int]:
    """Elements in a not accounted by b (per canonical value)."""
    counts: dict[str, int] = {}
    for item in a:
        counts[item] = counts.get(item, 0) + 1
    for item in b:
        counts[item] = counts.get(item, 0) - 1
    return {k: v for k, v in counts.items() if v != 0}
