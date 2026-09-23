"""Bridge contract tests (V42-R2 item 1, corrected to the FROZEN plan-v4.2
shapes after checking jusbench contracts directly).

Sources checked (read-only): specs/construction/plan-v4/05-anonymizer卡.md,
contracts/source/methods-core.json, contracts/schemas/ifc-2.schema.json,
contracts/schemas/common.schema.json, contracts/source/types-ifc2.json.

- pii.scan: PiiScanRequest{payloadRoot, expectedFiles, expectedPayloadDigest}
  -> PiiScanReport(+coverageStatement); IF-03 set digest; envelopes
  payload_modified/scan_incomplete/unsupported_format/timeout
- ingest.*: submit returns {jobId}; status carries the wire state enum;
  cancel/resume return Saved; only ref_not_found/unsupported_format errors
- anon.build_harness_handoff: manifest= must satisfy the frozen
  HandoffManifest closure (manifestVersion "1.1", 17 required fields)

Every test drives the REAL authorization/state chain (real registry, real
signer identity, real ledger on disk) in the exact call shape the bridge
uses — no string stubs. All fixtures are synthetic; no sensitive surface is
printed.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from legal_anonymizer.application import (
    consumer_bundle_service,
    ingest_service,
    pii_scan_service,
)
from legal_anonymizer.application.consumer_bundle_service import (
    HandoffError,
    build_harness_handoff,
)
from legal_anonymizer.application.sanitize_service import SanitizeService
from legal_anonymizer.application.state import MatterState
from tests.recognizers.test_cn_rules import SYNTHETIC_ID

_CONTRACT = (
    f"委托代理合同\n"
    f"委托人：周敏（身份证{SYNTHETIC_ID}，电话13711112222）。\n"
    f"代理费5,000,000.00元，2023年7月1日签订。\n"
)

_SYNTH_BODY = "客户陈大壮，电话13700009999。\n"


def _real_registry():
    from legal_anonymizer.adapters.recognizers.registry import RecognizerRegistry

    return RecognizerRegistry()


def _rules_only_registry():
    from legal_anonymizer.adapters.recognizers.registry import RecognizerRegistry

    return RecognizerRegistry(providers=[])


def _requires_ner() -> None:
    if not _real_registry().ner_available:
        pytest.skip("NER stack unavailable")


def _if03_digest(entries: list[tuple[str, bytes]]) -> str:
    joined = "".join(
        f"{rel}\n{hashlib.sha256(data).hexdigest()}\n"
        for rel, data in sorted(entries))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


# ==================================================================== pii.scan
@pytest.fixture()
def payload_root(tmp_path):
    root = tmp_path / "payload"
    root.mkdir()
    (root / "a.txt").write_text(_SYNTH_BODY, "utf-8")
    (root / "b.md").write_text("# 说明\n\n金额5,000元，2024年6月1日签约。\n", "utf-8")
    return root


def _scan_request(payload_root, files=("a.txt", "b.md"),
                  digest=None) -> dict:
    entries = [(f, (payload_root / f).read_bytes())
               for f in files if (payload_root / f).is_file()]
    return {
        "payloadRoot": str(payload_root),
        "expectedFiles": list(files),
        "expectedPayloadDigest": digest or _if03_digest(entries),
    }


class TestPiiScanService:
    def test_frozen_shape_complete_zero_alerts(self, payload_root):
        _requires_ner()
        # b.md is PII-free: whole-set scan can honestly reach alertCount==0
        b_only = _scan_request(payload_root, files=("b.md",))
        report = pii_scan_service.scan_release_payload(b_only)
        assert set(report) >= {
            "tool", "toolVersion", "ruleVersion", "status", "expectedFiles",
            "actualScannedFiles", "payloadDigest", "alertCount", "alerts",
            "coverageStatement"}
        assert report["status"] == "complete"
        assert report["alertCount"] == 0
        assert report["expectedFiles"] == ["b.md"]
        assert report["actualScannedFiles"] == ["b.md"]
        assert report["payloadDigest"] == b_only["expectedPayloadDigest"]
        assert "receipt" not in json.dumps(report).replace("receipt_ref", "")

    def test_alerts_report_offsets_never_surfaces(self, payload_root):
        _requires_ner()
        report = pii_scan_service.scan_release_payload(
            _scan_request(payload_root, files=("a.txt",)))
        assert report["alertCount"] >= 1  # phone rule always fires
        for alert in report["alerts"]:
            assert set(alert) == {"file", "rule", "detail"}
            assert alert["file"] == "a.txt"
            for surface in ("陈大壮", "13700009999"):
                assert surface not in json.dumps(alert, ensure_ascii=False)
            assert alert["detail"].startswith("chars ")

    def test_payload_modified_envelope_on_digest_mismatch(self, payload_root):
        request = _scan_request(payload_root)
        tampered = dict(request, expectedPayloadDigest="0" * 64)
        with pytest.raises(pii_scan_service.PiiScanError) as excinfo:
            pii_scan_service.scan_release_payload(tampered)
        assert excinfo.value.code == "payload_modified"

    def test_scan_incomplete_envelope_on_missing_file(self, payload_root):
        request = _scan_request(payload_root, files=("a.txt", "404.txt"))
        with pytest.raises(pii_scan_service.PiiScanError) as excinfo:
            pii_scan_service.scan_release_payload(request)
        assert excinfo.value.code == "scan_incomplete"
        assert "404.txt" in str(excinfo.value)

    def test_scan_incomplete_on_rules_only_registry(self, payload_root):
        # real RecognizerRegistry with explicit empty provider list — the
        # honest no-model path; NER-less scan may not pass as complete
        request = _scan_request(payload_root)
        with pytest.raises(pii_scan_service.PiiScanError) as excinfo:
            pii_scan_service.scan_release_payload(
                request, registry=_rules_only_registry())
        assert excinfo.value.code == "scan_incomplete"
        assert "ner_model_unavailable" in str(excinfo.value)

    def test_unsupported_format_envelopes(self, payload_root, tmp_path):
        with pytest.raises(pii_scan_service.PiiScanError) as bad_root:
            pii_scan_service.scan_release_payload(
                _scan_request(tmp_path / "nope"))
        assert bad_root.value.code == "unsupported_format"
        (payload_root / "c.bin").write_bytes(b"\xff\xfe\x00garbage")
        request = _scan_request(payload_root, files=("c.bin",))
        with pytest.raises(pii_scan_service.PiiScanError) as bad_text:
            pii_scan_service.scan_release_payload(request)
        assert bad_text.value.code == "unsupported_format"

    def test_timeout_envelope_fails_closed(self, payload_root):
        _requires_ner()
        with pytest.raises(pii_scan_service.PiiScanError) as excinfo:
            pii_scan_service.scan_release_payload(
                _scan_request(payload_root), timeout_seconds=0)
        assert excinfo.value.code == "timeout"

    @pytest.mark.parametrize("request_body", [
        {"expectedFiles": [], "expectedPayloadDigest": "x"},       # no payloadRoot
        {"payloadRoot": "/tmp", "expectedPayloadDigest": "x"},     # no files
        {"payloadRoot": "/tmp", "expectedFiles": []},              # no digest
        {"payloadRoot": "/tmp", "expectedFiles": [], "expectedPayloadDigest": "x",
         "surprise": 1},                                           # unknown field
        "not-a-dict",
    ])
    def test_schema_invalid_carries_code(self, request_body):
        with pytest.raises(pii_scan_service.PiiScanError) as excinfo:
            pii_scan_service.scan_release_payload(request_body)
        assert excinfo.value.code == "schema_invalid"
        assert isinstance(excinfo.value.code, str)

    def test_if03_digest_formula_matches_reference(self, payload_root):
        entries = [("a.txt", (payload_root / "a.txt").read_bytes()),
                   ("b.md", (payload_root / "b.md").read_bytes())]
        joined = "".join(
            f"{rel}\n{hashlib.sha256(data).hexdigest()}\n"
            for rel, data in sorted(entries))
        assert pii_scan_service.payload_digest(entries) == \
            hashlib.sha256(joined.encode("utf-8")).hexdigest()


# ================================================================== ingest.*
class TestIngestService:
    @pytest.fixture()
    def workspace(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.md").write_text(_CONTRACT, "utf-8")
        (tmp_path / "src" / "b.txt").write_text("合成说明文：金额 12,000 元。", "utf-8")
        return tmp_path

    def test_submit_returns_wire_jobid_and_persists_ledger(self, workspace):
        # exact bridge call shape: positional (state_root, sourceRefs,
        # parserProfileRef); wire output is {jobId}
        view = ingest_service.ingest_submit(
            workspace, ["src/a.md", "src/b.txt"], "cn")
        assert set(view) == {"jobId"}
        job_id = view["jobId"]
        ledger = json.loads((
            workspace / ingest_service.LEDGER_DIR / f"{job_id}.json"
        ).read_text("utf-8"))
        assert ledger["state"] == "done"
        assert ledger["counts"] == {"total": 2, "snapshotted": 2, "failed": 0}
        raw = (workspace / "src" / "a.md").read_bytes()
        by_ref = {f["ref"]: f for f in ledger["files"]}
        assert by_ref["src/a.md"]["sha256"] == hashlib.sha256(raw).hexdigest()
        assert by_ref["src/a.md"]["format"] == "markdown"

    def test_status_wire_shape(self, workspace):
        job_id = ingest_service.ingest_submit(
            workspace, ["src/a.md"], None)["jobId"]
        status = ingest_service.ingest_status(workspace, job_id)
        assert set(status) == {"state", "stage", "completedUnits",
                               "totalUnits", "resultRefs", "error"}
        assert status["state"] == "done"
        assert status["completedUnits"] == 1 and status["totalUnits"] == 1
        assert status["error"] is None
        ref = status["resultRefs"][0]
        assert ref["owner"] == "anonymizer" and ref["kind"] == "ingest-job"

    def test_ledger_never_contains_file_content(self, workspace):
        job_id = ingest_service.ingest_submit(workspace, ["src/a.md"], None)["jobId"]
        ledger_text = (
            workspace / ingest_service.LEDGER_DIR / f"{job_id}.json"
        ).read_text("utf-8")
        assert "13711112222" not in ledger_text
        assert "委托人" not in ledger_text

    def test_failed_unit_yields_error_state_with_typed_body(self, workspace):
        job_id = ingest_service.ingest_submit(
            workspace, ["src/a.md", "src/404.txt"], None)["jobId"]
        status = ingest_service.ingest_status(workspace, job_id)
        assert status["state"] == "error"
        assert status["completedUnits"] == 1 and status["totalUnits"] == 2
        body = status["error"]
        assert body["code"] == "ref_not_found"
        assert set(body) == {"code", "retryable", "requestId", "stage",
                             "currentRevision", "obligations"}

    def test_submit_error_envelopes_stay_in_frozen_set(self, workspace):
        with pytest.raises(ingest_service.IngestError) as empty:
            ingest_service.ingest_submit(workspace, [], None)
        assert empty.value.code == "unsupported_format"
        with pytest.raises(ingest_service.IngestError) as root:
            ingest_service.ingest_submit(workspace / "nope", ["src/a.md"], None)
        assert root.value.code == "ref_not_found"
        with pytest.raises(ingest_service.IngestError) as refs:
            ingest_service.ingest_submit(workspace, [42], None)
        assert refs.value.code == "unsupported_format"

    def test_cancel_is_idempotent_on_terminal_job(self, workspace):
        job_id = ingest_service.ingest_submit(workspace, ["src/a.md"], None)["jobId"]
        saved = ingest_service.ingest_cancel(workspace, job_id)
        assert set(saved) == {"ref", "revision", "changeSeq", "receipt"}
        again = ingest_service.ingest_cancel(workspace, job_id)
        assert again["ref"] == saved["ref"]
        receipt = saved["receipt"]
        assert set(receipt) == {"ref", "scope", "inputRefs", "outputRefs",
                                "issuedAt"}
        assert receipt["scope"]["kind"] == "workspace"

    def test_cancel_cancels_crash_residue_running_job(self, workspace):
        job_id = ingest_service.ingest_submit(workspace, ["src/a.md"], None)["jobId"]
        ledger_path = (workspace / ingest_service.LEDGER_DIR
                       / f"{job_id}.json")
        entry = json.loads(ledger_path.read_text("utf-8"))
        entry["state"] = "running"  # simulate a crash residue honestly
        ledger_path.write_text(json.dumps(entry), "utf-8")
        saved = ingest_service.ingest_cancel(workspace, job_id)
        assert saved["revision"] >= 1
        assert ingest_service.ingest_status(workspace, job_id)["state"] == \
            "cancelled"

    def test_resume_fails_closed_on_drifted_source(self, workspace):
        job_id = ingest_service.ingest_submit(
            workspace, ["src/a.md", "src/b.txt"], None)["jobId"]
        (workspace / "src" / "a.md").write_text("内容已被替换。\n", "utf-8")
        saved = ingest_service.ingest_resume(workspace, job_id)
        assert set(saved) == {"ref", "revision", "changeSeq", "receipt"}
        status = ingest_service.ingest_status(workspace, job_id)
        assert status["state"] == "error"
        assert status["error"]["code"] == "hash_mismatch"

    def test_unknown_job_is_ref_not_found(self, workspace):
        with pytest.raises(ingest_service.IngestError) as excinfo:
            ingest_service.ingest_status(workspace, "ingest-nope")
        assert excinfo.value.code == "ref_not_found"


# ==================================================== anon.build_harness_handoff
def _handoff_manifest(**overrides) -> dict:
    manifest = {
        "manifestVersion": "1.1",
        "documentId": "doc-001",
        "sourceKind": "digital_text",
        "sourceFormat": "md",
        "sourceVersion": None,
        "declaredPageCount": 3,
        "availablePageCount": 3,
        "parsedPages": [0, 1, 2],
        "failedPages": [],
        "ocrEngineVersion": None,
        "parserProfileVersion": "handoff-1.1",
        "redactionVersion": None,
        "reviewRequired": False,
        "reviewReceiptRef": None,
        "blocksManifestRef": None,
        "tablesManifestRef": None,
        "coverage": "complete",
    }
    manifest.update(overrides)
    return manifest


@pytest.fixture()
def sanitized_matter(tmp_path):
    """Real chain: matter init → sanitize (dictionary-confirmed, AUTO_READY)
    → signed receipt, ready for handoff."""
    from legal_anonymizer.adapters.recognizers.project_dictionary import (
        ProjectDictionaryProvider,
    )

    dictionary = ProjectDictionaryProvider(blacklist=[{"value": "周敏",
                                                       "type": "PERSON"}])
    state_root = tmp_path / "state"
    input_dir = tmp_path / "in"
    out_dir = tmp_path / "out"
    input_dir.mkdir()
    (input_dir / "合同.md").write_text(_CONTRACT, "utf-8")
    MatterState(state_root, "matter-bridge").init("cn-ai-safe-v1")
    result = SanitizeService(state_root).sanitize(
        "matter-bridge", input_dir, out_dir, dictionary=dictionary)
    assert result.status == "AUTO_READY", result.review_reasons
    return state_root, out_dir


class TestBuildHarnessHandoffManifest:
    def test_bridge_kwargs_shape_writes_source_manifest(self, sanitized_matter,
                                                        tmp_path):
        state_root, out_dir = sanitized_matter
        handoff = tmp_path / "handoff"
        # exact bridge call shape, incl. source_dir= + manifest= kwargs
        result = build_harness_handoff(state_root, "matter-bridge", handoff,
                                       source_dir=out_dir,
                                       manifest=_handoff_manifest())
        assert result["artifact_count"] == 1
        written = json.loads(
            (handoff / "source-manifest.json").read_text("utf-8"))
        for key, value in _handoff_manifest().items():
            assert written[key] == value
        assert written["matterId"] == "matter-bridge"
        assert written["bundleHash"]
        # wire output closure {bundleRef, receiptRef, manifestRef}
        assert result["receipt_ref"]["kind"] == "sanitization-receipt"
        assert result["receipt_ref"]["digest"]
        assert result["manifest_ref"]["kind"] == "source-manifest"
        assert result["manifest_ref"]["id"] == "doc-001"

    def test_no_manifest_keeps_previous_behavior(self, sanitized_matter, tmp_path):
        state_root, out_dir = sanitized_matter
        result = build_harness_handoff(state_root, "matter-bridge",
                                       tmp_path / "handoff", source_dir=out_dir)
        assert not (tmp_path / "handoff" / "source-manifest.json").exists()
        assert "manifest_ref" not in result
        assert result["receipt_ref"]["kind"] == "sanitization-receipt"

    def test_manifest_v10_or_unknown_fields_refused(self, sanitized_matter,
                                                    tmp_path):
        state_root, out_dir = sanitized_matter
        with pytest.raises(HandoffError) as version:
            build_harness_handoff(
                state_root, "matter-bridge", tmp_path / "h0",
                source_dir=out_dir,
                manifest=_handoff_manifest(manifestVersion="1.0"))
        assert "manifestVersion" in str(version.value)
        with pytest.raises(HandoffError) as unknown:
            build_harness_handoff(
                state_root, "matter-bridge", tmp_path / "h1",
                source_dir=out_dir,
                manifest=_handoff_manifest(payloadDigest="a" * 64))
        assert "payloadDigest" in str(unknown.value)

    def test_manifest_missing_required_field_refused(self, sanitized_matter,
                                                     tmp_path):
        state_root, out_dir = sanitized_matter
        incomplete = _handoff_manifest()
        del incomplete["coverage"]
        with pytest.raises(HandoffError) as excinfo:
            build_harness_handoff(state_root, "matter-bridge", tmp_path / "h2",
                                  source_dir=out_dir, manifest=incomplete)
        assert "coverage" in str(excinfo.value)

    def test_manifest_wrong_enums_or_types_refused(self, sanitized_matter,
                                                   tmp_path):
        state_root, out_dir = sanitized_matter
        for bad in (_handoff_manifest(sourceKind="fax"),
                    _handoff_manifest(coverage="mostly"),
                    _handoff_manifest(reviewRequired="no"),
                    _handoff_manifest(parsedPages=["0"]),
                    _handoff_manifest(documentId="")):
            with pytest.raises(HandoffError):
                build_harness_handoff(state_root, "matter-bridge",
                                      tmp_path / "hx", source_dir=out_dir,
                                      manifest=bad)

    def test_manifest_with_private_marker_refused(self, sanitized_matter, tmp_path):
        state_root, out_dir = sanitized_matter
        with pytest.raises(HandoffError):
            build_harness_handoff(
                state_root, "matter-bridge", tmp_path / "h3",
                source_dir=out_dir,
                manifest=_handoff_manifest(sourceFormat="leak canonical_surface"))


def test_module_import_lightweight_like_bridge_probe():
    """The bridge probes availability with a bare __import__; the modules must
    import without touching model assets."""
    import importlib

    import legal_anonymizer.application.ingest_service as ingest_mod
    import legal_anonymizer.application.pii_scan_service as scan_mod

    assert importlib.reload(ingest_mod) is ingest_mod
    assert importlib.reload(scan_mod) is scan_mod
    assert consumer_bundle_service is not None
