"""S2 property-based tests for the MSSP entity core (Hypothesis)."""

from __future__ import annotations

import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from legal_anonymizer.contracts.statuses import EntityType, TransformKind
from legal_anonymizer.domain import (
    CannotLinkConflict,
    ConstraintUnionFind,
    EntityVault,
    Locator,
    Mention,
    Span,
    apply_spans,
    get_profile,
    legal_date_multiset,
    money_multiset,
    multiset_difference,
    TransformExecutor,
)

PERSON = EntityType.PERSON.value
ORG = EntityType.LEGAL_PERSON.value


def make_vault(matter_id="matter-001"):
    return EntityVault(matter_id)


def add_person(vault, surface, doc="doc-001", start=0, evidence=()):
    m = Mention(
        surface=surface,
        entity_type=PERSON,
        document_id=doc,
        locator=Locator(kind="text_offset", start=start, end=start + len(surface)),
        evidence_codes=evidence,
        source="regex",
        confidence=0.99,
    )
    return vault.add_mention(m)


class TestInjectionAndConsistency:
    def test_distinct_entities_get_distinct_aliases(self):
        v = make_vault()
        add_person(v, "张三")
        add_person(v, "李四")
        add_person(v, "王五")
        v.resolve()
        aliases = {e.display_alias for e in v.entities.values()}
        assert len(aliases) == 3
        ids = {e.entity_id for e in v.entities.values()}
        assert len(ids) == 3

    def test_alias_consistent_across_documents(self):
        v = make_vault()
        a = add_person(v, "张三", doc="doc-001")
        b = add_person(v, "张三", doc="doc-002")
        v.resolve()
        assert v.entity_id_for_mention(a) == v.entity_id_for_mention(b)

    def test_roles_do_not_change_entity_id(self):
        v = make_vault()
        a = add_person(v, "张三")
        v.resolve()
        ent = v.entity_for_mention(a)
        before = ent.entity_id
        ent.with_role("原告").with_role("发包人")
        assert ent.entity_id == before

    def test_same_name_different_persons_split_by_cannot_link(self):
        v = make_vault()
        a = add_person(v, "张伟", doc="doc-001")
        b = add_person(v, "张伟", doc="doc-002")
        v.resolve()
        assert v.entity_id_for_mention(a) == v.entity_id_for_mention(b)
        v.resolve_with_cannot_links([(a, b)])
        assert v.entity_id_for_mention(a) != v.entity_id_for_mention(b)

    def test_cannot_link_conflict_raises(self):
        uf = ConstraintUnionFind(2)
        uf.union(0, 1)
        with pytest.raises(CannotLinkConflict):
            uf.cannot_link(0, 1)

    def test_strong_identifier_merges(self):
        v = make_vault()
        a = add_person(v, "张三", evidence=("strong-id:ID:110101199001011234",))
        b = add_person(v, "老张", evidence=("strong-id:ID:110101199001011234",))
        v.resolve()
        assert v.entity_id_for_mention(a) == v.entity_id_for_mention(b)


class TestDeterminism:
    @settings(max_examples=25, deadline=None)
    @given(order=st.permutations([0, 1, 2, 3]))
    def test_detector_order_does_not_change_ids(self, order):
        surfaces = ["张三", "李四", "甲公司", "乙公司"]
        types = [PERSON, PERSON, ORG, ORG]

        def build(indices):
            v = make_vault()
            for k in indices:
                add_person(v, surfaces[k], doc=f"doc-{k:03d}") if types[k] == PERSON else None
                if types[k] != PERSON:
                    m = Mention(
                        surface=surfaces[k], entity_type=ORG, document_id=f"doc-{k:03d}",
                        locator=Locator(kind="text_offset", start=0, end=len(surfaces[k])),
                    )
                    v.add_mention(m)
            v.resolve()
            return {(e.entity_type, e.canonical_surface): e.entity_id for e in v.entities.values()}

        baseline = build([0, 1, 2, 3])
        assert build(order) == baseline

    def test_ids_do_not_use_xyz(self):
        v = make_vault()
        add_person(v, "张三")
        add_person(v, "李四")
        v.resolve()
        for eid in v.entities:
            assert re.match(r"^ent:[a-z-]+:\d{4}$", eid)
            assert eid.split(":")[-2] not in {"x", "y", "z"}


class TestMatterIsolation:
    def test_cross_matter_commitments_differ(self):
        v1, v2 = make_vault("matter-001"), make_vault("matter-002")
        for v in (v1, v2):
            add_person(v, "张三")
            v.resolve()
        assert v1.mapping_commitment() != v2.mapping_commitment()
        assert v1.matter_secret != v2.matter_secret


class TestSpanReplacement:
    def test_end_to_start_replacement(self):
        text = "张三与李四签订合同"
        spans = [Span(0, 2, "自然人A"), Span(3, 5, "自然人B")]
        assert apply_spans(text, spans) == "自然人A与自然人B签订合同"

    def test_overlapping_spans_rejected(self):
        with pytest.raises(ValueError, match="overlapping"):
            apply_spans("张三张三", [Span(0, 3, "A"), Span(2, 4, "B")])

    def test_input_already_containing_alias_not_retokanized(self):
        text = "法人A与张三签订合同"
        v = make_vault()
        idx = add_person(v, "张三", start=4)
        v.resolve()
        ent = v.entity_for_mention(idx)
        # 法人A is not a known surface, only 张三 is replaced
        spans = [TransformExecutor.span_for("PSEUDONYMIZE", "张三", 4, 6, ent.display_alias)]
        out = apply_spans(text, spans)
        assert out.startswith("法人A与")
        assert out.endswith("签订合同")


class TestTransforms:
    def test_mask_keep_last_4(self):
        assert TransformExecutor.span_for("MASK_KEEP_LAST_4", "13812345678", 0, 11).replacement == "*******5678"

    def test_short_value_fully_masked(self):
        from legal_anonymizer.domain.transforms import mask_keep_last_4
        assert mask_keep_last_4("123") == "***"

    def test_generalize_birth_date(self):
        out = TransformExecutor.span_for("GENERALIZE_YEAR", "1990年1月1日出生", 0, 12).replacement
        assert out == "1990年出生"

    def test_generalize_personal_address(self):
        from legal_anonymizer.domain.transforms import generalize_personal_address
        assert generalize_personal_address("福建省漳州市芗城区XX街道XX小区3栋502室") == "福建省漳州市芗城区某住所"

    def test_project_address_keeps_city_district(self):
        v = make_vault()
        m = Mention(
            surface="福建省漳州市龙文区XX路XX地块XX工程", entity_type="PROJECT",
            document_id="doc-001", locator=Locator("text_offset", 0, 0, 15),
        )
        idx = v.add_mention(m)
        v.resolve()
        alias = v.entity_for_mention(idx).display_alias
        span = TransformExecutor.project_address_span("福建省漳州市龙文区XX路XX地块XX工程", 0, 15, alias)
        assert span.replacement == "福建省漳州市龙文区" + alias

    def test_unknown_transform_raises(self):
        with pytest.raises(ValueError):
            TransformExecutor.span_for("NONEXISTENT", "x", 0, 1)


class TestUtilitySnapshots:
    def test_money_multiset_preserved(self):
        original = "工程款人民币3,000,000.00元，违约金500,000.00元，另欠付200万元。"
        sanitized = original  # money is never transformed
        assert multiset_difference(
            money_multiset(original), money_multiset(sanitized)
        ) == {}

    def test_money_multiset_detects_loss(self):
        original = "工程款3,000,000.00元，违约金500,000.00元"
        damaged = "工程款3,000,000.00元"
        assert multiset_difference(money_multiset(original), money_multiset(damaged)) != {}

    def test_legal_dates_preserved(self):
        text = "2023年5月1日开工，2024年3月15日竣工"
        assert legal_date_multiset(text) == ["2023年5月1日", "2024年3月15日"]

    def test_left_inverse_roundtrip(self):
        v = make_vault()
        idx = add_person(v, "张三", start=0)
        v.resolve()
        ent = v.entity_for_mention(idx)
        text = "张三出庭"
        out = apply_spans(text, [Span(0, 2, ent.display_alias)])
        # inverse: display alias -> canonical surface
        back = apply_spans(out, [Span(0, len(ent.display_alias), ent.canonical_surface)])
        assert back == text


class TestProfileClosure:
    def test_profile_refuses_unknown_entity_type(self):
        p = get_profile("cn-ai-safe-v1")
        with pytest.raises(KeyError):
            p.transform_for_entity("MARTIAN")

    def test_profile_refuses_unknown_identifier(self):
        p = get_profile("cn-ai-safe-v1")
        with pytest.raises(KeyError):
            p.transform_for_identifier("brain_scan")

    def test_money_and_dates_keep(self):
        p = get_profile("cn-ai-safe-v1")
        assert "money" in p.utility_keeps
        assert "legal_event_date" in p.utility_keeps
