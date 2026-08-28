"""S12 end-to-end scenarios A-F (construction plan S12.7).

A 纯文本自动路径; B 扫描件人工路径; C 严重残留; D mapping 泄露尝试;
E 金额效用; F 旧 receipt 重放."""

from __future__ import annotations

from pathlib import Path

import pytest

from legal_anonymizer.adapters.recognizers.project_dictionary import (
    ProjectDictionaryProvider,
)
from legal_anonymizer.application.consumer_bundle_service import build_harness_handoff
from legal_anonymizer.application.rehydrate_service import RehydrateService
from legal_anonymizer.application.review_service import issue_review_receipt
from legal_anonymizer.application.sanitize_service import SanitizeService
from legal_anonymizer.application.scan_pipeline import ScanPipeline
from legal_anonymizer.application.state import MatterState
from legal_anonymizer.application.verify_service import VerifyService
from tests.consumer.mock_consumer import (
    ACCEPTABLE_FOR_IMPORT,
    REJECTED_BAD_SIGNATURE,
    REJECTED_MAPPING_IN_BUNDLE,
    REJECTED_MISSING_REVIEW,
    REJECTED_STALE_RECEIPT,
    verify_consumer_bundle,
)
from tests.recognizers.test_cn_rules import SYNTHETIC_ID

CONTRACT = """# 建设工程施工合同

发包人：临江建设有限公司，项目负责人周敏（身份证{sid}，电话13711112222）。
工程款5,000,000.00元，2023年7月1日开工，2024年5月30日竣工。
"""

DICTIONARY = ProjectDictionaryProvider(
    blacklist=[
        {"value": "周敏", "type": "PERSON"},
        {"value": "临江建设有限公司", "type": "LEGAL_PERSON"},
    ]
)


@pytest.fixture(scope="class")
def installation(tmp_path_factory):
    """One installation = one signer identity shared by all matters."""
    base = tmp_path_factory.mktemp("e2e")
    state_root = base / "state"
    from legal_anonymizer.application.consumer_protocol import build_consumer_protocol

    pack = base / "consumer-protocol"
    build_consumer_protocol(state_root, pack)
    return base, state_root, pack


def _make_matter(installation, matter_id: str, text: str):
    base, state_root, _pack = installation
    input_dir = base / f"in-{matter_id}"
    out_dir = base / f"out-{matter_id}"
    input_dir.mkdir(parents=True, exist_ok=True)
    (input_dir / "合同.md").write_text(text.format(sid=SYNTHETIC_ID), encoding="utf-8")
    MatterState(state_root, matter_id).init("cn-ai-safe-v1")
    return state_root, input_dir, out_dir


class TestScenarioA:
    """纯文本自动路径: AUTO_READY → consumer bundle → mock consumer accepts →
    JC facts → rehydrate."""

    def test_auto_ready_chain(self, installation):
        _base, _pack = installation[0], installation[2]
        state_root, input_dir, out_dir = _make_matter(
            installation, "matter-a", CONTRACT
        )
        result = SanitizeService(state_root).sanitize(
            "matter-a", input_dir, out_dir, dictionary=DICTIONARY
        )
        assert result.status == "AUTO_READY"
        VerifyService(state_root).verify("matter-a", out_dir)
        handoff = installation[0] / "handoff-a"
        build_harness_handoff(state_root, "matter-a", handoff, source_dir=out_dir)
        ok, reason = verify_consumer_bundle(handoff, _pack)
        assert ok == ACCEPTABLE_FOR_IMPORT, reason
        # JC facts emit cleanly
        from legal_anonymizer.adapters.integrations.juris_calculus import emit_jc_facts

        facts = emit_jc_facts(state_root, "matter-a", out_dir,
                              installation[0] / "jc-facts.json")
        assert facts["facts"]["HumanReviewRequired"] is False
        # rehydrate
        md = (out_dir / "sanitized" / "doc-001.ai.md").read_text(encoding="utf-8")
        restored = RehydrateService(state_root).rehydrate_text("matter-a", md)
        assert "周敏" in restored.output_text


class TestScenarioB:
    """扫描件人工路径: REVIEW_REQUIRED → manual box + reviewer receipt →
    READY_BY_HUMAN → signed bundle accepted."""

    def test_scan_ready_by_human(self, installation):
        from tests.pdf_scan.test_scan_pipeline import make_image_only_pdf

        _base, _pack = installation[0], installation[2]
        state_root, input_dir, out_dir = _make_matter(installation, "matter-b", CONTRACT)
        src = installation[0] / "scan-b.pdf"
        make_image_only_pdf(src, "项目负责人周敏 5,000,000.00元")
        ScanPipeline(state_root).sanitize_scan(
            "matter-b", src, out_dir, "doc-002", dictionary=DICTIONARY,
            decisions={"manual_boxes": [
                {"document_id": "doc-002", "page": 1, "box": [30, 30, 200, 60],
                 "entity_type": "SIGNATURE", "action": "REDACT"},
            ]},
        )
        result = issue_review_receipt(
            state_root, "matter-b", out_dir,
            {"matter_id": "matter-b", "decisions": [], "manual_boxes": [
                {"document_id": "doc-002", "page": 1, "box": [30, 30, 200, 60]}
            ]},
            "reviewer-b", "MATTER_LEAD",
        )
        assert result["sanitized_bundle_hash"]
        verify = VerifyService(state_root).verify("matter-b", out_dir)
        assert verify.status in ("READY_BY_HUMAN", "AUTO_READY"), verify.gates


class TestScenarioC:
    """严重残留: independent verifier detects planted ID → CLOSED_BLOCK →
    consumer bundle refused."""

    def test_planted_residual_blocks_handoff(self, installation):
        _base, _pack = installation[0], installation[2]
        state_root, input_dir, out_dir = _make_matter(
            installation, "matter-c", CONTRACT
        )
        SanitizeService(state_root).sanitize(
            "matter-c", input_dir, out_dir, dictionary=DICTIONARY
        )
        planted = out_dir / "sanitized" / "doc-001.ai.md"
        planted.write_text(
            planted.read_text(encoding="utf-8") + f"\n漏检{SYNTHETIC_ID}\n",
            encoding="utf-8",
        )
        verify = VerifyService(state_root).verify("matter-c", out_dir)
        assert verify.status == "CLOSED_BLOCK"
        # consumer bundle must be refused (no valid handoff from CLOSED_BLOCK)
        from legal_anonymizer.application.consumer_bundle_service import HandoffError

        with pytest.raises(HandoffError):
            build_harness_handoff(state_root, "matter-c", installation[0] / "handoff-c",
                                  source_dir=out_dir)


class TestScenarioD:
    """mapping 泄露尝试: bundle 人为加入 private mapping → mock consumer reject."""

    def test_mapping_in_bundle_rejected(self, installation):
        _base, _pack = installation[0], installation[2]
        state_root, input_dir, out_dir = _make_matter(
            installation, "matter-d", CONTRACT
        )
        SanitizeService(state_root).sanitize(
            "matter-d", input_dir, out_dir, dictionary=DICTIONARY
        )
        VerifyService(state_root).verify("matter-d", out_dir)
        handoff = installation[0] / "handoff-d"
        build_harness_handoff(state_root, "matter-d", handoff, source_dir=out_dir)
        # inject private field into a structured object
        import json as _json

        bundle_path = handoff / "sanitized-bundle.json"
        doc = _json.loads(bundle_path.read_text(encoding="utf-8"))
        if doc["structured_objects"]:
            doc["structured_objects"][0]["aliases"] = ["周敏"]
        else:
            doc["structured_objects"].append({"aliases": ["周敏"]})
        bundle_path.write_text(
            _json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        ok, reason = verify_consumer_bundle(handoff, _pack)
        assert ok == REJECTED_MAPPING_IN_BUNDLE, reason


class TestScenarioE:
    """金额效用: 多笔工程款、利息和日期 → 脱敏前后多重集相同 → 回填只恢复主体."""

    def test_money_multiset_conserved(self, installation):
        text = (
            "发包人临江建设有限公司应付：工程款5,000,000.00元、利息250,000.00元、"
            "违约金100,000.00元。2023年7月1日开工，2024年5月30日竣工，2024年6月30日结算。"
            "项目负责人周敏，身份证{sid}。\n"
        )
        _base, _pack = installation[0], installation[2]
        state_root, input_dir, out_dir = _make_matter(installation, "matter-e", text)
        SanitizeService(state_root).sanitize(
            "matter-e", input_dir, out_dir, dictionary=DICTIONARY
        )
        report = out_dir / "reports" / "doc-001.report.json"
        import json as _json

        payload = _json.loads(report.read_text(encoding="utf-8"))
        original_money = payload["money_multiset"]
        assert len(original_money) == 3
        verify = VerifyService(state_root).verify("matter-e", out_dir)
        assert verify.gates["utility"] == "PASS"
        restored = RehydrateService(state_root).rehydrate_text(
            "matter-e",
            (out_dir / "sanitized" / "doc-001.ai.md").read_text(encoding="utf-8"),
        )
        restored_flat = restored.output_text.replace(",", "")
        for amount in original_money:
            assert amount in restored_flat
        assert "周敏" in restored.output_text


class TestScenarioF:
    """旧 receipt 重放: 材料更新后旧 receipt → bundle hash mismatch → reject."""

    def test_stale_receipt_rejected(self, installation):
        _base, _pack = installation[0], installation[2]
        state_root, input_dir, out_dir = _make_matter(
            installation, "matter-f", CONTRACT
        )
        SanitizeService(state_root).sanitize(
            "matter-f", input_dir, out_dir, dictionary=DICTIONARY
        )
        VerifyService(state_root).verify("matter-f", out_dir)
        handoff = installation[0] / "handoff-f"
        build_harness_handoff(state_root, "matter-f", handoff, source_dir=out_dir)
        # material updated after the receipt was signed
        f = handoff / "sanitized" / "doc-001.ai.md"
        f.write_text(f.read_text(encoding="utf-8") + "\n追加材料\n", encoding="utf-8")
        ok, reason = verify_consumer_bundle(handoff, _pack)
        assert ok == REJECTED_STALE_RECEIPT, reason
