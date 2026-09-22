"""Production NER + heterogeneous verification tests (plan-v4.2 card 05-1/05-2).

All materials synthetic. These tests exercise the REAL installed engines when
the hash-locked model assets are present, and the named fail-closed degradation
paths when they are not."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from legal_anonymizer.adapters.recognizers import model_assets
from legal_anonymizer.adapters.recognizers.cn_rules import CnRuleRecognizer
from legal_anonymizer.adapters.recognizers.presidio_ner import (
    CLUENER_LABEL_MAP,
    CLUENER_NON_PII_LABELS,
    PresidioCnNerRecognizer,
    build_production_providers,
    normalize_bioes_label,
)
from legal_anonymizer.adapters.recognizers.registry import RecognizerRegistry

REPO = Path(__file__).resolve().parents[2]

requires_ner = pytest.mark.skipif(
    not PresidioCnNerRecognizer().availability()[0],
    reason="CLUENER model stack not installed on this machine "
           "(" + PresidioCnNerRecognizer().availability()[1] + ")",
)


# ---------------------------------------------------------------- BIOES 契约
def test_bioes_normalization_covers_real_cluener_labels():
    cfg = json.loads((REPO / "models/ner/cluener/config.json").read_text("utf-8"))
    labels = {v for v in cfg["id2label"].values() if v not in ("O", "[PAD]")}
    assert any(l.startswith("S-") for l in labels), "real config must include S- tags"
    for label in labels:
        plain = normalize_bioes_label(label)
        assert plain in CLUENER_LABEL_MAP or plain in CLUENER_NON_PII_LABELS, plain
    assert normalize_bioes_label("S-name") == "name"
    assert normalize_bioes_label("B-address") == "address"


def test_non_pii_labels_never_mapped():
    for label in CLUENER_NON_PII_LABELS:
        assert label not in CLUENER_LABEL_MAP


# ------------------------------------------------------------- 默认生产构造
@requires_ner
def test_default_registry_includes_rules_and_cluener():
    reg = RecognizerRegistry()
    assert reg.ner_available, reg.status
    stack_ids = {d["modelId"] for d in reg.detector_stack()}
    assert "uer/roberta-base-finetuned-cluener2020-chinese" in stack_ids
    assert any(d["mechanism"] == "deterministic-regex" for d in reg.detector_stack())


@requires_ner
def test_cluener_span_offsets_on_synthetic_case():
    ner = PresidioCnNerRecognizer()
    text = "王某在深圳某公司签约，李明担任华宇集团董事长。"
    dets = ner.detect(text)
    assert dets, "model must produce detections on the card's worked example"
    for d in dets:
        assert text[d.start:d.end] == d.surface
        assert d.source == "ner"
        assert d.entity_type in set(CLUENER_LABEL_MAP.values())


def test_missing_components_report_unavailable_not_silent_rules():
    providers, status = build_production_providers()
    assert providers, "rules engine still runs"
    if not status["ner_available"]:
        # degradation must be NAMED and carry an error code — the caller turns
        # this into REVIEW_REQUIRED; a rules-only fallback is never "normal"
        assert status["error_code"] == "ner_model_unavailable"
        assert status["reason"]
    else:
        assert any(isinstance(p, PresidioCnNerRecognizer) for p in providers)


def test_asset_digest_mismatch_is_named(tmp_path, monkeypatch):
    monkeypatch.setattr(model_assets, "load_ner_assets", lambda: [
        model_assets.NerAsset(
            asset_id="fake", model_id="m", revision="r",
            local_dir="nope", files={"x.bin": {"sha256": "0" * 64}},
        )
    ])
    ok, reason = model_assets.check_asset("fake")
    assert not ok and "missing" in reason


# ------------------------------------------------------------- 异构强制
from legal_anonymizer.application.verify_service import (
    VerifierHomogeneityError,
    ensure_heterogeneous,
)

CLUENER_DESC = {"mechanism": "transformers-token-classification",
                "modelId": "uer/roberta-base-finetuned-cluener2020-chinese",
                "modelVersion": "rev-1"}


def test_same_model_different_instance_is_not_heterogeneous():
    prod = [dict(CLUENER_DESC)]
    same_but_new_instance = dict(CLUENER_DESC)
    with pytest.raises(VerifierHomogeneityError):
        ensure_heterogeneous(prod, [same_but_new_instance])


def test_different_mechanism_is_heterogeneous():
    ensure_heterogeneous(
        [CLUENER_DESC],
        [{"mechanism": "zero-shot-span-gliner-v21",
          "modelId": "urchade/gliner_medium-v2.1", "modelVersion": "rev-2"}],
    )


def test_different_revision_counts_as_different_model():
    """换权重版本=不同模型（异构成立的必要条件由 trusted config 另行核对）。"""
    prod = [dict(CLUENER_DESC)]
    bumped = dict(CLUENER_DESC, modelVersion="rev-2")
    ensure_heterogeneous(prod, [bumped])  # must not raise


# ------------------------------------------------- 漏检残差反例（真实模型）
def _make_matter(tmp_path, matter_id="het-matter"):
    from legal_anonymizer.application.state import MatterState

    state = MatterState(tmp_path, matter_id)
    state.init("cn-ai-safe-v1")
    public = state.read_public()
    public["documents"] = ["doc-001"]
    public["status"] = "REVIEW_REQUIRED"
    state.write_public(public)
    return state


requires_verifier = pytest.mark.skipif(
    not model_assets.import_ok("gliner")
    or model_assets.check_asset("gliner-medium-v21")[0] is False,
    reason="heterogeneous GLiNER verifier asset not installed",
)


@requires_verifier
def test_production_miss_residual_forces_privacy_fail(tmp_path):
    """反例：无标签中文姓名 王某/赵某 生产层(CLUENER)漏检、异构复核引擎检出 →
    残差>0 判 privacy=FAIL 且 residual_counts.ner_residual 具名。"""
    from legal_anonymizer.application.verify_service import VerifyService

    _make_matter(tmp_path)
    out = tmp_path / "out"
    (out / "sanitized").mkdir(parents=True)
    # simulate a sanitized deliverable where production never masked the names
    residual_text = "王某与赵某均经本院合法传唤无正当理由拒不到庭。"
    (out / "sanitized" / "doc-001.ai.md").write_text(residual_text, "utf-8")

    result = VerifyService(state_root=tmp_path).verify("het-matter", out)
    assert result.residual_counts["ner_residual"] > 0
    assert result.gates["privacy"] == "FAIL"
    assert result.status == "CLOSED_BLOCK"
    receipt = json.loads(
        (out / "receipts" / "privacy-verification-receipt.json").read_text("utf-8"))
    assert receipt["schema_version"] == "2.0"
    assert "ner_residual" in receipt["residual_counts"]
    mech = {v["mechanism"] for v in receipt["verifier_stack"]}
    assert mech and "transformers-token-classification" not in mech


@requires_verifier
def test_verifier_unavailable_never_passes(tmp_path, monkeypatch):
    from legal_anonymizer.application.verify_service import VerifyService

    class Unavailable:
        def availability(self):
            return False, "gliner package not installed (simulated)"

        def stack_descriptor(self):
            return {}

        def detect(self, text):
            raise AssertionError("must not be called")

    _make_matter(tmp_path)
    out = tmp_path / "out"
    (out / "sanitized").mkdir(parents=True)
    (out / "sanitized" / "doc-001.ai.md").write_text("双方按约履行。", "utf-8")

    result = VerifyService(tmp_path, verifier=Unavailable()).verify("het-matter", out)
    assert result.status == "REVIEW_REQUIRED"
    assert result.gates["privacy"] == "REVIEW_REQUIRED"
    assert result.coverage["complete"] is False
    assert any("verifier_unavailable" in r for r in result.coverage["reasons"])


def test_rules_only_verify_is_not_heterogeneous(tmp_path):
    """旧行为回归防线：只拿 CnRuleRecognizer 复核生产规则 = 自己改自己的作业。"""
    from legal_anonymizer.application.verify_service import VerifyService

    class RulesVerifier:
        def availability(self):
            return True, "ok"

        def stack_descriptor(self):
            return {"mechanism": "deterministic-regex", "modelId": "cn-rules",
                    "modelVersion": "1.0"}

        def detect(self, text):
            return []

    reg = RecognizerRegistry(providers=[CnRuleRecognizer()])
    result = VerifyService(tmp_path, verifier=RulesVerifier(),
                           production_registry=reg)
    _make_matter(tmp_path)
    out = tmp_path / "out"
    (out / "sanitized").mkdir(parents=True)
    (out / "sanitized" / "doc-001.ai.md").write_text("协议自签署生效。", "utf-8")
    verified = result.verify("het-matter", out)
    # detector stack contains cn-rules => verifier citing cn-rules is rejected
    assert verified.status in ("REVIEW_REQUIRED", "CLOSED_BLOCK")
    assert any("verifier" in r or "heterogeneous" in r.lower()
               for r in verified.coverage["reasons"])
