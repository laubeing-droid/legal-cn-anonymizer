"""S11 anonymizer-side tests: privacy facts for Juris Calculus."""

from __future__ import annotations

import json

from legal_anonymizer.adapters.integrations.juris_calculus import (
    JcAdapterError,
    collect_privacy_facts,
    emit_jc_facts,
)
from legal_anonymizer.application.sanitize_service import SanitizeService
from legal_anonymizer.application.verify_service import VerifyService
from legal_anonymizer.security.receipt_identity import ReceiptIdentity
from tests.markdown.test_pipeline import make_dictionary, workspace  # noqa: F401


def _full_run(workspace):
    state_root, input_dir, out_dir = workspace
    SanitizeService(state_root).sanitize(
        "matter-001", input_dir, out_dir, dictionary=make_dictionary()
    )
    VerifyService(state_root).verify("matter-001", out_dir)
    return state_root, out_dir


class TestJcFacts:
    def test_facts_emitted_and_signed(self, workspace):
        state_root, out_dir = _full_run(workspace)
        output = out_dir / "jc-privacy-facts.json"
        payload = emit_jc_facts(state_root, "matter-001", out_dir, output)
        assert payload["facts"]["Purpose"] == "CLOUD_LEGAL_ANALYSIS"
        assert payload["facts"]["CriticalResidualCount"] == 0
        assert payload["facts"]["MappingExcludedFromExternalBundle"] is True
        assert payload["facts"]["MoneyPreserved"] is True
        assert payload["facts"]["LegalEventDatesPreserved"] is True
        # signature verifies against exported public key
        ident = ReceiptIdentity(state_root / "identity").ensure()
        body = {k: v for k, v in payload.items() if k != "signature"}
        ident.verify(body, payload["signature"])

    def test_no_raw_surfaces_in_facts(self, workspace):
        state_root, out_dir = _full_run(workspace)
        output = out_dir / "jc-privacy-facts.json"
        payload = emit_jc_facts(state_root, "matter-001", out_dir, output)
        text = json.dumps(payload)
        assert "张三" not in text and "丹霞" not in text

    def test_stale_artifacts_refused(self, workspace):
        state_root, out_dir = _full_run(workspace)
        # change an artifact after receipt signing
        f = out_dir / "sanitized" / "doc-001.ai.md"
        f.write_text(f.read_text(encoding="utf-8") + "\n改动\n", encoding="utf-8")
        try:
            collect_privacy_facts(state_root, "matter-001", out_dir)
            raise AssertionError("should have refused")
        except JcAdapterError as exc:
            assert "artifacts" in str(exc)

    def test_verify_required_before_facts(self, workspace):
        state_root, input_dir, out_dir = workspace
        SanitizeService(state_root).sanitize(
            "matter-001", input_dir, out_dir, dictionary=make_dictionary()
        )
        try:
            collect_privacy_facts(state_root, "matter-001", out_dir)
            raise AssertionError("should have refused")
        except JcAdapterError as exc:
            assert "verify" in str(exc)

    def test_output_wording_forbidden_phrases_absent(self, workspace):
        state_root, out_dir = _full_run(workspace)
        output = out_dir / "jc-privacy-facts.json"
        payload = emit_jc_facts(state_root, "matter-001", out_dir, output)
        text = json.dumps(payload, ensure_ascii=False)
        for forbidden in ("已经完全匿名", "绝无泄露风险", "100% ANONYMIZED", "ZERO RISK"):
            assert forbidden not in text
