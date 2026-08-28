"""Deterministic Chinese legal recognizers.

Every rule carries: rule id, source, severity, default classification and
checksum validation where the standard defines one. Money and date rules only
*classify* (for utility invariants) — they never mask by default. Rules ported
from moyupeng0422/legal-doc-redactor (MIT) are re-validated here with positive,
negative and checksum test cases; none of the upstream regexes are trusted
without their own tests."""

from __future__ import annotations

import re

from ...ports.recognizer import Detection, RecognizerPort

# --------------------------------------------------------------------------
# checksums
# --------------------------------------------------------------------------

_ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_ID_CODES = "10X98765432"


def id_card_checksum_valid(value: str) -> bool:
    if len(value) != 18:
        return False
    total = sum(int(d) * w for d, w in zip(value[:17], _ID_WEIGHTS))
    return _ID_CODES[total % 11] == value[17].upper()


_USCC_CHARS = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_USCC_WEIGHTS = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]


def uscc_checksum_valid(value: str) -> bool:
    if len(value) != 18:
        return False
    try:
        total = sum(_USCC_CHARS.index(ch) * w for ch, w in zip(value[:17], _USCC_WEIGHTS))
    except ValueError:
        return False
    check = (31 - total % 31) % 31
    return _USCC_CHARS[check] == value[17]


def luhn_valid(value: str) -> bool:
    if not value.isdigit():
        return False
    digits = [int(d) for d in value]
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# --------------------------------------------------------------------------
# rule definitions
# --------------------------------------------------------------------------


class Rule:
    def __init__(
        self,
        rule_id: str,
        pattern: str,
        entity_type: str,
        severity: str,
        *,
        checksum=None,
        flags: int = 0,
        context=None,
        source: str = "regex",
        version: str = "1.0",
        origin: str = "original",
    ):
        self.rule_id = rule_id
        self.re = re.compile(pattern, flags)
        self.entity_type = entity_type
        self.severity = severity
        self.checksum = checksum
        self.context = re.compile(context) if context else None
        self.source = source
        self.version = version
        self.origin = origin

    def find(self, text: str) -> list[Detection]:
        out = []
        for m in self.re.finditer(text):
            value = m.group(0)
            if self.checksum and not self.checksum(value):
                continue
            if self.context:
                window = text[max(0, m.start() - 24) : min(len(text), m.end() + 24)]
                if not self.context.search(window):
                    continue
            out.append(
                Detection(
                    surface=value,
                    entity_type=self.entity_type,
                    start=m.start(),
                    end=m.end(),
                    source=self.source,
                    rule_id=self.rule_id,
                    confidence=0.99 if self.checksum else 0.92,
                    severity=self.severity,
                    evidence=(f"rule:{self.rule_id}",),
                )
            )
        return out


RULES: list[Rule] = [
    # -- direct identifiers (critical) ----------------------------------------
    Rule(
        "cn.id.18", r"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]",
        "IDENTIFIER:id_card", "critical", checksum=id_card_checksum_valid,
        origin="legal-doc-redactor seed, re-validated",
    ),
    Rule("cn.phone.mobile", r"(?<!\d)1[3-9]\d{9}(?!\d)", "IDENTIFIER:phone", "critical"),
    Rule("cn.phone.landline", r"(?<!\d)0\d{2,3}-\d{7,8}(?!\d)", "IDENTIFIER:phone", "critical"),
    Rule(
        "cn.email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "IDENTIFIER:email", "critical",
    ),
    Rule(
        "cn.credit.uscc", r"[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}",
        "IDENTIFIER:credit_code", "critical", checksum=uscc_checksum_valid,
        origin="legal-doc-redactor seed, checksum re-validated (GB 32100-2015)",
    ),
    Rule(
        "cn.bank.card", r"(?<!\d)\d{16,19}(?!\d)", "IDENTIFIER:bank_account", "critical",
        checksum=luhn_valid, context=r"(?:银行卡|卡号|账号|账户|储蓄卡|借记卡|信用卡)",
    ),
    Rule(
        "cn.weixin", r"(?:微信号|微信)\s*[:：]\s*[A-Za-z][-_A-Za-z0-9]{5,19}",
        "IDENTIFIER:weixin", "critical",
    ),
    Rule(
        "cn.plate", r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领]"
        r"[A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳]",
        "IDENTIFIER:plate", "high",
    ),
    # -- legal document identifiers -------------------------------------------
    Rule(
        "cn.case.number",
        r"[\u4e00-\u9fa5]{0,12}[（〔\[]\d{4}[）〕\]][\u4e00-\u9fa5\d初终再字第]{1,14}号",
        "IDENTIFIER:case_number", "high",
        origin="legal-doc-redactor seed, tightened",
    ),
    Rule("cn.url", r"https?://[^\s，。；、）)\"]+", "IDENTIFIER:url", "high"),
    Rule(
        "cn.ip.v4", r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", "IDENTIFIER:ip", "high",
        checksum=lambda v: all(0 <= int(p) <= 255 for p in v.split(".")),
    ),
    # -- classification only: money and legal event dates are NEVER masked -----
    Rule(
        "cn.money.classify",
        r"(?:人民币|￥|¥)\s*[0-9][0-9,，]*(?:\.[0-9]+)?\s*(?:万元|亿元|元)|"
        r"[0-9][0-9,，]*(?:\.[0-9]+)?\s*(?:万元|亿元|元整|元)|"
        r"[零一二三四五六七八九十百千万亿]+元整",
        "MONEY", "normal",
    ),
    Rule(
        "cn.date.classify", r"\d{4}\s*年\s*\d{1,2}\s*月\s*\d{1,2}\s*日", "LEGAL_DATE", "normal"
    ),
]

# structural field rules: label-context -> protected value
_STRUCTURE_LABELS = [
    ("cn.structure.legal_rep", r"(?:法定代表人|负责人)\s*[:：]", "LEGAL_PERSON_OR_PERSON"),
    ("cn.structure.agent", r"(?:委托(?:诉讼)?代理人|辩护人)\s*[:：]", "PERSON"),
    ("cn.structure.contact", r"(?:联系人|经办人)\s*[:：]", "PERSON"),
    ("cn.structure.address", r"(?:住所地|住所|地址|经营场所|项目地址|工程地址)\s*[:：]", "LOCATION"),
]


class StructureFieldRecognizer(RecognizerPort):
    """Label-context recognizer: captures the value following a legal-document
    field label. Values are candidates (confidence 0.85) — they participate in
    entity resolution like any other mention."""

    name = "structure"

    def detect(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        for rule_id, label_re, kind in _STRUCTURE_LABELS:
            for m in re.finditer(label_re, text):
                rest = text[m.end() :]
                vm = re.match(r"([^，。；、\n]{2,40}?)\s*(?=[，。；、\n]|$)", rest)
                if not vm:
                    continue
                value = vm.group(1).strip()
                if not value:
                    continue
                entity_type = (
                    "LOCATION" if kind == "LOCATION"
                    else "PERSON" if kind == "PERSON"
                    else "OTHER_PROTECTED"
                )
                out.append(
                    Detection(
                        surface=value,
                        entity_type=entity_type,
                        start=m.end(),
                        end=m.end() + len(value),
                        source="structure",
                        rule_id=rule_id,
                        confidence=0.85,
                        severity="high",
                        evidence=(f"rule:{rule_id}", f"label:{m.group(0).strip()}"),
                    )
                )
        return out


class CnRuleRecognizer(RecognizerPort):
    """The deterministic rule engine. This is the built-in backend; the Presidio
    adapter (optional extra) must produce the same output contract."""

    name = "cn-rules"

    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules if rules is not None else RULES

    def detect(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        for rule in self.rules:
            out.extend(rule.find(text))
        return out


def resolve_overlaps(detections: list[Detection]) -> list[Detection]:
    """Deterministic overlap resolution: longest span wins, then higher severity
    (critical > high > normal), then earlier rule id."""
    severity_rank = {"critical": 0, "high": 1, "normal": 2}
    ordered = sorted(
        detections,
        key=lambda d: (-(d.end - d.start), severity_rank.get(d.severity, 3), d.rule_id, d.start),
    )
    selected: list[Detection] = []
    for det in ordered:
        if any(det.start < s.end and s.start < det.end for s in selected):
            continue
        selected.append(det)
    return sorted(selected, key=lambda d: d.start)
