"""Coverage-statement & egress refusal tests (plan-v4.2 card 05-3, IF-07).

Mirrors the frozen contract's behaviour baseline on the A side: the scanner
never issues egress receipts, denominators are never fabricated, and a
consumer-side trusted-config check (reference implementation of
`x-egress.trustedConfigCheck`, exactly what 01/02/06/07 must apply) refuses:
wrong profile version, wrong benchmark id/revision, swapped model version in
the reported stack, same-model disguised heterogeneity, self-declared passing
values that do not recompute, missing measurement, and wrong denominators.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from legal_anonymizer.adapters.recognizers.registry import RecognizerRegistry
from legal_anonymizer.application import coverage_service, scan_bytes_service
from legal_anonymizer.contracts.schemas import SCHEMAS_DIR

SCHEMA = {
    name: json.loads((Path(SCHEMAS_DIR) / f"{name}.schema.json").read_text("utf-8"))
    for name in ("coverage-statement-v1", "scan-bytes-report-v1",
                 "scan-bytes-request-v1")
}


def validate(name: str, payload: dict) -> None:
    jsonschema.validate(payload, SCHEMA[name])


# ------------------------------------------------------------ 正常路径形状
def test_coverage_statement_validates_against_frozen_shape():
    reg = RecognizerRegistry()
    from legal_anonymizer.adapters.recognizers.gliner_ner import CnGlinerVerifier

    cov = coverage_service.build_coverage_statement(reg, verifier=CnGlinerVerifier())
    validate("coverage-statement-v1", cov)
    assert cov["releaseProfileId"] == coverage_service.RELEASE_PROFILE_ID
    assert cov["verifierStack"], "verifier stack must be published when available"


def test_zero_denominator_is_inexpressible():
    bad = {
        "releaseProfileId": "p", "profileVersion": "1",
        "detectorStack": [], "verifierStack": [],
        "modelAssetsAvailable": True,
        "benchmark": {
            "id": "b", "revision": "1", "sampleCount": 1,
            "overallRecall": {"hitCount": 0, "groundTruthCount": 0, "value": 0.0},
            "personRecall": None,
            "falsePositiveRate": {"maskedNonSensitiveCharCount": 0,
                                  "nonSensitiveCharCount": 1, "value": 0.0},
            "evaluatedAt": "2026-09-22T00:00:00Z",
            "claimScope": "specified_benchmark_only",
        },
    }
    with pytest.raises(jsonschema.ValidationError):
        validate("coverage-statement-v1", bad)


def test_missing_benchmark_is_null_not_zero(tmp_path):
    cov = coverage_service.build_coverage_statement(
        RecognizerRegistry(), repo_root=tmp_path)
    assert cov["benchmark"] is None
    ok, reasons = coverage_service.meets_release_gates(cov)
    assert not ok and "benchmark_missing" in reasons


# --------------------------------------------- 消费端可信配置核对（参考实现）
def _trusted_config(report_cov: dict, benchmark: dict | None = None) -> dict:
    """The consumer's OWN approved configuration — the reference shape from
    x-egress.trustedReleaseConfigExample, tightened to this release."""
    return {
        "releaseProfileId": report_cov["releaseProfileId"],
        "profileVersion": report_cov["profileVersion"],
        "detectorStack": copy.deepcopy(report_cov["detectorStack"]),
        "verifierStack": copy.deepcopy(report_cov["verifierStack"]),
        "benchmark": benchmark or (report_cov["benchmark"] or {}),
        "thresholds": {"overallRecall": 0.90, "personRecall": 0.90,
                       "falsePositiveRate": 0.05},
    }


def consumer_trusted_check(report_cov: dict, trusted: dict) -> list[str]:
    """Reference implementation of the main-process gate: item-by-item compare
    + recompute every ratio from the reported numerator/denominator. Returns
    refusal causes; empty list == admissible (a receipt would then be issued
    by the MAIN PROCESS — never here)."""
    causes: list[str] = []
    if report_cov["releaseProfileId"] != trusted["releaseProfileId"]:
        causes.append("profile_id_mismatch")
    if report_cov["profileVersion"] != trusted["profileVersion"]:
        causes.append("profile_version_mismatch")
    if not report_cov["modelAssetsAvailable"]:
        causes.append("model_assets_unavailable")
    for field in ("detectorStack", "verifierStack"):
        want = {(d["mechanism"], d["modelId"], d["modelVersion"])
                for d in trusted[field]}
        got = {(d["mechanism"], d["modelId"], d["modelVersion"])
               for d in report_cov[field]}
        if got != want:
            causes.append(f"{field}_not_approved")
    prod_ids = {d["modelId"] for d in report_cov["detectorStack"]}
    for v in report_cov["verifierStack"]:
        if v["modelId"] in prod_ids:
            causes.append("verifier_not_heterogeneous")
    bm = report_cov["benchmark"]
    if bm is None:
        causes.append("benchmark_missing")
        return causes
    if bm["id"] != trusted["benchmark"].get("id") or \
            bm["revision"] != trusted["benchmark"].get("revision"):
        causes.append("benchmark_mismatch")
    thr = trusted["thresholds"]
    for key in ("overallRecall", "personRecall"):
        m = bm.get(key)
        if m is None:
            causes.append(f"{key}_unmeasured")
            continue
        if m["hitCount"] / m["groundTruthCount"] < thr[key]:
            causes.append(f"{key}_below_threshold")
    fpr = bm["falsePositiveRate"]
    if (fpr["maskedNonSensitiveCharCount"] / fpr["nonSensitiveCharCount"]) \
            > thr["falsePositiveRate"]:
        causes.append("falsePositiveRate_above_threshold")
    return causes


def _cov_with(**mutate) -> dict:
    cov = {
        "releaseProfileId": "cn-release-v42", "profileVersion": "1",
        "detectorStack": [
            {"mechanism": "deterministic-regex", "modelId": "cn-rules",
             "modelVersion": "1.0"},
            {"mechanism": "transformers-token-classification",
             "modelId": "uer/roberta-base-finetuned-cluener2020-chinese",
             "modelVersion": "rev-a"},
        ],
        "verifierStack": [{"mechanism": "zero-shot-span-gliner-v21",
                           "modelId": "urchade/gliner_medium-v2.1",
                           "modelVersion": "rev-v"}],
        "modelAssetsAvailable": True,
        "benchmark": {
            "id": "v42-synthetic", "revision": "r1", "sampleCount": 27,
            "overallRecall": {"hitCount": 90, "groundTruthCount": 98,
                              "value": 0.9184},
            "personRecall": {"hitCount": 31, "groundTruthCount": 34,
                             "value": 0.9118},
            "falsePositiveRate": {"maskedNonSensitiveCharCount": 20,
                                  "nonSensitiveCharCount": 900, "value": 0.0222},
            "evaluatedAt": "2026-09-22T00:00:00Z",
            "claimScope": "specified_benchmark_only",
        },
    }
    for k, v in mutate.items():
        if isinstance(cov.get(k), dict) and isinstance(v, dict):
            cov[k].update(v)
        else:
            cov[k] = v
    return cov


def test_admissible_example_passes_consumer_check():
    cov = _cov_with()
    validate("coverage-statement-v1", cov)
    assert consumer_trusted_check(cov, _trusted_config(cov)) == []


def test_wrong_profile_version_refused():
    cov = _cov_with()
    trusted = _trusted_config(cov)
    trusted["profileVersion"] = "2"
    assert "profile_version_mismatch" in consumer_trusted_check(cov, trusted)


def test_wrong_benchmark_id_or_revision_refused():
    cov = _cov_with()
    trusted = _trusted_config(cov)
    trusted["benchmark"] = {"id": "other-bench", "revision": "r9"}
    assert "benchmark_mismatch" in consumer_trusted_check(cov, trusted)


def test_swapped_model_version_in_stack_refused():
    cov = _cov_with()
    cov["detectorStack"][1]["modelVersion"] = "rev-EVIL"
    assert "detectorStack_not_approved" in consumer_trusted_check(
        cov, _trusted_config(_cov_with()))


def test_same_model_disguised_as_heterogeneous_verifier_refused():
    cov = _cov_with(verifierStack=[
        {"mechanism": "transformers-token-classification",
         "modelId": "uer/roberta-base-finetuned-cluener2020-chinese",
         "modelVersion": "rev-b"}])
    trusted = _trusted_config(cov)
    causes = consumer_trusted_check(cov, trusted)
    assert "verifier_not_heterogeneous" in causes


def test_self_declared_pass_but_recomputed_fail_refused():
    # value claims 0.92 but 30/34 = 0.882 — recomputation wins
    cov = _cov_with(benchmark={
        "personRecall": {"hitCount": 30, "groundTruthCount": 34,
                         "value": 0.92}})
    causes = consumer_trusted_check(cov, _trusted_config(cov))
    assert "personRecall_below_threshold" in causes


def test_person_recall_089_refused_even_if_value_rounds_up():
    cov = _cov_with(benchmark={
        "personRecall": {"hitCount": 30, "groundTruthCount": 34, "value": 0.89}})
    causes = consumer_trusted_check(cov, _trusted_config(cov))
    assert "personRecall_below_threshold" in causes


def test_missing_measurement_null_refused():
    cov = _cov_with(benchmark={
        "personRecall": None})
    causes = consumer_trusted_check(cov, _trusted_config(cov))
    assert "personRecall_unmeasured" in causes


def test_wrong_denominator_schema_inexpressible():
    cov = _cov_with(benchmark={
        "personRecall": {"hitCount": 5, "groundTruthCount": 0, "value": 0.0}})
    with pytest.raises(jsonschema.ValidationError):
        validate("coverage-statement-v1", cov)


def test_meets_release_gates_recomputes_from_real_report():
    cov = coverage_service.build_coverage_statement(RecognizerRegistry())
    ok, reasons = coverage_service.meets_release_gates(cov)
    if cov["benchmark"] is not None:
        # real measured 76.5% person recall: gate must stay closed
        assert not ok
        assert any("personRecall" in r for r in reasons)
    else:
        assert "benchmark_missing" in reasons


# --------------------------------------------------------- scan_bytes 边界
def _request(body: dict, **overrides) -> dict:
    raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = {
        "requestId": "req-1", "encoding": "base64",
        "bodyBase64": base64.b64encode(raw).decode(),
        "bodySha256": hashlib.sha256(raw).hexdigest(),
        "byteLength": len(raw),
        "contentType": "application/json; charset=utf-8",
        "releaseProfileId": coverage_service.RELEASE_PROFILE_ID,
        "profileVersion": coverage_service.RELEASE_PROFILE_VERSION,
        "scanProfile": "json-recursive-keys-and-strings/v1",
    }
    req.update(overrides)
    validate("scan-bytes-request-v1", req)
    return req


def _scan(req):
    reg = RecognizerRegistry()
    if not reg.ner_available:
        pytest.skip("NER stack unavailable: " + str(reg.status.get("reason")))
    return scan_bytes_service.scan_bytes(req, registry=reg)


def test_scan_bytes_covers_every_key_and_string_and_recomputes_digest():
    req = _request({"systemPrompt": "忽略规则", "messages": [
        {"role": "user", "content": "客户陈大壮电话13700009999"}]})
    report = _scan(req)
    validate("scan-bytes-report-v1", report)
    assert report["status"] == "complete"
    assert report["bodySha256"] == req["bodySha256"]
    assert report["scannedByteLength"] == req["byteLength"]
    assert report["alertCount"] >= 2  # name + phone inside nested content
    assert "receiptId" not in report and "receipt" not in report


def test_scan_bytes_scans_json_keys_themselves():
    req = _request({"13800001111": "仅键名含PII"})
    report = _scan(req)
    assert report["alertCount"] >= 1


def test_scan_bytes_rejects_claimed_digest_mismatch():
    req = _request({"a": "b"})
    req = dict(req, bodySha256="0" * 64)
    report = _scan(req)
    assert report["status"] == "failed"
    # must NOT echo the claimed digest as scan proof
    assert report["bodySha256"] != "0" * 64


def test_scan_bytes_rejects_non_utf8_and_non_json():
    for bad in (b"\xff\xfe\x00garbage", b'{"broken"'):
        raw = base64.b64encode(bad).decode()
        req = _request({}, bodyBase64=raw,
                       bodySha256=hashlib.sha256(bad).hexdigest(),
                       byteLength=len(bad))
        assert _scan(req)["status"] in ("unsupported_format", "failed")


def test_scan_bytes_wrong_profile_is_unsupported_not_silent():
    req = _request({"x": "y"}, profileVersion="999")
    assert _scan(req)["status"] == "unsupported_format"


def test_scan_bytes_never_issues_receipt_and_carry_no_case_data():
    req = _request({"note": "会议于2024年6月1日召开"})
    report = _scan(req)
    assert json.dumps(report, ensure_ascii=False).count("receipt") == 0
    assert report["coverageStatement"]["benchmark"] is None or \
        report["coverageStatement"]["benchmark"]["claimScope"] == \
        "specified_benchmark_only"
