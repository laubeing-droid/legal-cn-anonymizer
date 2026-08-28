"""S3 recognizer tests: checksums, positives/negatives, overlap resolution."""

from __future__ import annotations

import pytest

from legal_anonymizer.adapters.recognizers import (
    CnRuleRecognizer,
    ProjectDictionaryProvider,
    StructureFieldRecognizer,
    resolve_overlaps,
)
from legal_anonymizer.adapters.recognizers.cn_rules import (
    id_card_checksum_valid,
    luhn_valid,
    uscc_checksum_valid,
)
from legal_anonymizer.adapters.recognizers.registry import RecognizerRegistry
from legal_anonymizer.ports.recognizer import Detection


def make_id17_checksum(base17: str) -> str:
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    codes = "10X98765432"
    total = sum(int(d) * w for d, w in zip(base17, weights))
    return base17 + codes[total % 11]


def make_luhn(number13: str) -> str:
    digits = [int(d) for d in number13]
    checksum = 0
    parity = (len(digits) + 1) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    check = (10 - checksum % 10) % 10
    return number13 + str(check)


def make_uscc(base17: str) -> str:
    chars = "0123456789ABCDEFGHJKLMNPQRTUWXY"
    weights = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]
    total = sum(chars.index(ch) * w for ch, w in zip(base17, weights))
    return base17 + chars[(31 - total % 31) % 31]


SYNTHETIC_ID = make_id17_checksum("11010119900101123")
SYNTHETIC_CARD = make_luhn("6222020200112233")  # 16 digits
SYNTHETIC_USCC = make_uscc("91350200MA0000001")


class TestChecksums:
    def test_id_checksum(self):
        assert id_card_checksum_valid(SYNTHETIC_ID)
        assert not id_card_checksum_valid(SYNTHETIC_ID[:-1] + ("0" if SYNTHETIC_ID[-1] != "0" else "1"))

    def test_luhn(self):
        assert luhn_valid(SYNTHETIC_CARD)
        assert not luhn_valid(SYNTHETIC_CARD[:-1] + "9" if SYNTHETIC_CARD[-1] != "9" else SYNTHETIC_CARD[:-1] + "8")

    def test_uscc(self):
        assert uscc_checksum_valid(SYNTHETIC_USCC)
        assert not uscc_checksum_valid(SYNTHETIC_USCC[:-1] + "0" if SYNTHETIC_USCC[-1] != "0" else SYNTHETIC_USCC[:-1] + "1")


class TestRules:
    def setup_method(self):
        self.engine = CnRuleRecognizer()

    def _by_rule(self, text, rule_prefix):
        return [d for d in self.engine.detect(text) if d.rule_id.startswith(rule_prefix)]

    def test_id_card_detected(self):
        dets = self._by_rule(f"身份证号{SYNTHETIC_ID}，请核对。", "cn.id")
        assert len(dets) == 1

    def test_bad_checksum_id_not_detected(self):
        bad = SYNTHETIC_ID[:-1] + ("0" if SYNTHETIC_ID[-1] != "0" else "1")
        assert self._by_rule(f"身份证号{bad}，请核对。", "cn.id") == []

    def test_mobile(self):
        assert len(self._by_rule("联系电话13812345678。", "cn.phone")) == 1

    def test_mobile_wrong_prefix(self):
        assert self._by_rule("编号12812345678。", "cn.phone") == []

    def test_email(self):
        assert len(self._by_rule("邮箱 zhang.san@example.com。", "cn.email")) == 1

    def test_uscc_with_checksum(self):
        dets = self._by_rule(f"统一社会信用代码：{SYNTHETIC_USCC}。", "cn.credit")
        assert len(dets) == 1

    def test_bank_card_requires_context(self):
        text = f"卡号{SYNTHETIC_CARD}"
        assert len(self._by_rule(text, "cn.bank")) == 1
        bare = f"订单号{SYNTHETIC_CARD}"
        assert self._by_rule(bare, "cn.bank") == []

    def test_case_number(self):
        assert len(self._by_rule("根据（2023）闽0602民初1234号民事判决", "cn.case")) == 1

    def test_money_classified_not_masked(self):
        dets = self.engine.detect("工程款人民币3,000,000.00元")
        money = [d for d in dets if d.entity_type == "MONEY"]
        assert len(money) == 1

    def test_date_classified(self):
        dets = self.engine.detect("2023年5月1日开工")
        assert any(d.entity_type == "LEGAL_DATE" for d in dets)

    def test_plate(self):
        assert len(self._by_rule("车牌号闽D12345停放在", "cn.plate")) == 1


class TestStructureFields:
    def test_legal_rep(self):
        dets = StructureFieldRecognizer().detect("法定代表人：王小明，系该公司经理。")
        assert len(dets) == 1
        assert dets[0].entity_type == "OTHER_PROTECTED"  # legal rep type refined at resolution
        assert dets[0].surface == "王小明"

    def test_address_label(self):
        dets = StructureFieldRecognizer().detect("住所地：福建省漳州市芗城区X路X号。")
        assert dets[0].entity_type == "LOCATION"


class TestRegistry:
    def test_dictionary_blacklist(self):
        d = ProjectDictionaryProvider(blacklist=[{"value": "丹霞青云项目", "type": "PROJECT"}])
        dets = d.detect("丹霞青云项目的发包人为")
        assert len(dets) == 1 and dets[0].entity_type == "PROJECT"

    def test_dictionary_whitelist_suppresses(self):
        d = ProjectDictionaryProvider(
            blacklist=[{"value": "最高人民法院", "type": "PUBLIC_AUTHORITY"}],
            whitelist=["最高人民法院"],
        )
        assert d.detect("最高人民法院关于审理") == []

    def test_alias_group(self):
        d = ProjectDictionaryProvider(
            aliases=[{"canonical": "中国建筑第三工程局有限公司", "values": ["中建三局"], "type": "LEGAL_PERSON"}]
        )
        dets = d.detect("中建三局与")
        assert dets and dets[0].evidence[0].startswith("alias-canonical:")

    def test_registry_overlap_longest_wins(self):
        registry = RecognizerRegistry()
        text = f"身份证{SYNTHETIC_ID}请联系13812345678"
        dets = registry.detect(text)
        # no overlapping detections remain
        ordered = sorted(dets, key=lambda d: d.start)
        for a, b in zip(ordered, ordered[1:]):
            assert a.end <= b.start

    def test_overlap_resolution_prefers_longest(self):
        long = Detection("甲乙丙丁", "OTHER_PROTECTED", 0, 4, "dictionary", "dict:x", 1.0)
        short = Detection("甲乙", "PERSON", 0, 2, "regex", "cn.x", 0.99)
        assert resolve_overlaps([short, long])[0] is long
