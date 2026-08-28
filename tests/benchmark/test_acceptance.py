"""S9 acceptance tests: review receipts, stale-receipt binding, planted
residual detection, no-SAFE wording, synthetic benchmark."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from legal_anonymizer.application.benchmark import BenchmarkRunner, BenchmarkMetrics
from legal_anonymizer.application.review_service import (
    ReviewError,
    artifact_set_hash,
    compute_decisions_hash,
    issue_review_receipt,
)
from legal_anonymizer.application.sanitize_service import SanitizeService
from legal_anonymizer.application.state import MatterState
from legal_anonymizer.application.verify_service import VerifyService
from tests.markdown.test_pipeline import make_dictionary
from tests.markdown.test_pipeline import workspace  # noqa: F401


def _sanitize(workspace):
    state_root, input_dir, out_dir = workspace
    return SanitizeService(state_root).sanitize(
        "matter-001", input_dir, out_dir, dictionary=make_dictionary()
    ), state_root, out_dir


class TestReviewReceipts:
    def test_reviewed_matter_becomes_ready_by_human(self, workspace):
        result, state_root, out_dir = _sanitize(workspace)
        assert result.status == "AUTO_READY"  # dictionary-covered, no review required
        # simulate a REVIEW_REQUIRED matter by flipping public status
        state = MatterState.load(state_root, "matter-001")
        public = state.read_public()
        public["status"] = "REVIEW_REQUIRED"
        state.write_public(public)
        decisions = {"matter_id": "matter-001", "decisions": []}
        receipt = issue_review_receipt(
            state_root, "matter-001", out_dir, decisions,
            "reviewer-1", "MATTER_LEAD",
        )
        assert receipt["signature"]["algorithm"] == "Ed25519"
        verify = VerifyService(state_root).verify("matter-001", out_dir)
        assert verify.status == "READY_BY_HUMAN", verify.gates

    def test_review_required_without_receipt_stays_review(self, workspace):
        result, state_root, out_dir = _sanitize(workspace)
        state = MatterState.load(state_root, "matter-001")
        public = state.read_public()
        public["status"] = "REVIEW_REQUIRED"
        state.write_public(public)
        verify = VerifyService(state_root).verify("matter-001", out_dir)
        assert verify.status == "REVIEW_REQUIRED"

    def test_unknown_reviewer_role_rejected(self, workspace):
        result, state_root, out_dir = _sanitize(workspace)
        with pytest.raises(ReviewError, match="role"):
            issue_review_receipt(
                state_root, "matter-001", out_dir, {"matter_id": "matter-001"},
                "someone", "CEO",
            )


class TestReceiptBinding:
    def test_stale_receipt_rejected(self, workspace):
        result, state_root, out_dir = _sanitize(workspace)
        state = MatterState.load(state_root, "matter-001")
        public = state.read_public()
        public["status"] = "REVIEW_REQUIRED"
        state.write_public(public)
        issue_review_receipt(
            state_root, "matter-001", out_dir, {"matter_id": "matter-001"},
            "reviewer-1", "MATTER_LEAD",
        )
        # material changed after review: append a new file (artifact set hash changes)
        (out_dir / "sanitized" / "doc-002.ai.md").write_text("extra", encoding="utf-8")
        verify = VerifyService(state_root).verify("matter-001", out_dir)
        assert verify.status == "CLOSED_BLOCK"
        assert verify.residual_counts["output_hash_mismatch"] == 1

    def test_planted_residual_detected_by_independent_verifier(self, workspace):
        result, state_root, out_dir = _sanitize(workspace)
        # recognizer bypassed: plant a critical residual directly in the output
        planted = out_dir / "sanitized" / "doc-001.ai.md"
        planted.write_text(
            planted.read_text(encoding="utf-8") + "\n残留身份证11010119900101123X\n",
            encoding="utf-8",
        )
        from tests.recognizers.test_cn_rules import SYNTHETIC_ID

        planted.write_text(
            planted.read_text(encoding="utf-8").replace(
                "11010119900101123X", SYNTHETIC_ID
            ),
            encoding="utf-8",
        )
        verify = VerifyService(state_root).verify("matter-001", out_dir)
        assert verify.status == "CLOSED_BLOCK"
        assert verify.gates["privacy"] == "FAIL"
        assert verify.residual_counts["critical_identifier_residual"] >= 1

    def test_no_safe_wording_in_outputs(self, workspace):
        result, state_root, out_dir = _sanitize(workspace)
        for f in (out_dir / "receipts").glob("*.json"):
            text = f.read_text(encoding="utf-8")
            assert '"SAFE"' not in text
            assert "100% ANONYMIZED" not in text
            assert "ZERO RISK" not in text


class TestBenchmark:
    def test_synthetic_benchmark_runs_and_reports(self, tmp_path):
        state_root = tmp_path / "state"
        runner = BenchmarkRunner(state_root)
        metrics = runner.run(tmp_path / "bench")
        assert isinstance(metrics, BenchmarkMetrics)
        payload = metrics.to_payload()
        assert payload["documents"] == 5
        assert payload["critical_identifier_occurrences"] > 0
        # honest reporting: NER not qualified, no fabricated recall numbers
        assert payload["ner_auto_release_qualified"] is False
        assert "person_recall" not in payload and "organization_recall" not in payload
        assert "no NER recall number is claimed" in payload["note"]
        # the mechanical invariants must hold
        assert metrics.critical_identifier_misses == 0
        assert metrics.subject_misses == 0
        assert metrics.money_multiset_failures == 0
        assert metrics.legal_date_multiset_failures == 0
        assert metrics.roundtrip_failures == 0
        (tmp_path / "bench" / "acceptance-report.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
