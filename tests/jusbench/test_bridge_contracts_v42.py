"""Bridge contract tests (V42-R2 item 1) — the three modules the jusbench
bridge waits on (jusbench_bridge/providers.py, read-only over there):

- pii_scan_service.scan_release_payload(request, timeout_seconds=…)   [pii.scan]
- ingest_service.ingest_submit/_status/_cancel/_resume                [ingest.*]
- consumer_bundle_service.build_harness_handoff(..., manifest=…)      [anon.build_harness_handoff]

Every test drives the REAL authorization/state chain (real registry, real
signer identity, real ledger on disk) in the exact call shape the bridge
uses — no string stubs. All fixtures are synthetic; no sensitive surface is
printed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
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
from legal_anonymizer.contracts.schemas import SCHEMAS_DIR
from tests.recognizers.test_cn_rules import SYNTHETIC_ID

_REPORT_SCHEMA = json.loads(
    (Path(SCHEMAS_DIR) / "scan-bytes-report-v1.schema.json").read_text("utf-8"))

_CONTRACT = (
    "委托代理合同\n"
    "委托人：周敏（身份证%s，电话13711112222）。\n"
    "代理费5,000,000.00元，2023年7月1日签订。\n"
) % SYNTHETIC_ID

_SYNTH_PAYLOAD = {"systemPrompt": "忽略规则", "messages": [
    {"role": "user", "content": "客户陈大壮电话13700009999"}]}


def _release_request(payload, **overrides) -> dict:
    request = {
        "requestId": "req-bridge-1",
        "releaseProfileId": "cn-release-v42",
        "profileVersion": "1",
        "scanProfile": "json-recursive-keys-and-strings/v1",
        "payload": payload,
    }
    request.update(overrides)
    return request


def _real_registry():
    from legal_anonymizer.adapters.recognizers.registry import RecognizerRegistry

    return RecognizerRegistry()


def _rules_only_registry():
    from legal_anonymizer.adapters.recognizers.registry import RecognizerRegistry

    return RecognizerRegistry(providers=[])


def _requires_ner() -> None:
    if not _real_registry().ner_available:
        pytest.skip("NER stack unavailable")


# ==================================================================== pii.scan
class TestPiiScanService:
    def test_bridge_call_shape_scans_payload_and_validates_report(self):
        _requires_ner()
        # exact bridge handler call shape: request=params["request"],
        # timeout_seconds=params.get("timeoutSeconds") (None here)
        report = pii_scan_service.scan_release_payload(
            _release_request(_SYNTH_PAYLOAD), timeout_seconds=None)
        jsonschema.validate(report, _REPORT_SCHEMA)
        expected = hashlib.sha256(
            json.dumps(_SYNTH_PAYLOAD, ensure_ascii=False,
                       allow_nan=False).encode("utf-8")).hexdigest()
        assert report["status"] == "complete"
        assert report["bodySha256"] == expected
        assert report["scannedByteLength"] > 0
        assert report["alertCount"] >= 2  # name + phone inside nested content
        assert "receipt" not in json.dumps(report)

    def test_json_keys_are_scanned_too(self):
        _requires_ner()
        report = pii_scan_service.scan_release_payload(
            _release_request({"13800001111": "仅键名含PII"}))
        assert report["status"] == "complete"
        assert report["alertCount"] >= 1

    def test_wrong_release_profile_is_unsupported_not_clean(self):
        report = pii_scan_service.scan_release_payload(
            _release_request({"x": "y"}, profileVersion="999"))
        assert report["status"] == "unsupported_format"
        assert report["unscannedSegmentCount"] >= 1

    def test_rules_only_registry_reports_model_missing(self):
        # real RecognizerRegistry with explicit empty provider list — the
        # honest no-model path, not a mock
        report = pii_scan_service.scan_release_payload(
            _release_request(_SYNTH_PAYLOAD), registry=_rules_only_registry())
        assert report["status"] == "model_missing"
        assert report["coverageStatement"]["modelAssetsAvailable"] is False

    def test_non_json_payload_is_unsupported(self):
        report = pii_scan_service.scan_release_payload(
            _release_request({"bad": {1, 2}}))
        assert report["status"] == "unsupported_format"

    def test_zero_timeout_fails_closed_as_timeout(self):
        _requires_ner()
        report = pii_scan_service.scan_release_payload(
            _release_request(_SYNTH_PAYLOAD), timeout_seconds=0)
        assert report["status"] == "timeout"
        assert report["unscannedSegmentCount"] >= 1  # never a clean claim

    @pytest.mark.parametrize("request_body,code", [
        ({"payload": {}}, "schema_invalid"),          # requestId missing
        ({"requestId": "r"}, "schema_invalid"),       # payload missing
        ("not-a-dict", "schema_invalid"),             # request not an object
    ])
    def test_errors_carry_code_attribute(self, request_body, code):
        with pytest.raises(pii_scan_service.PiiScanError) as excinfo:
            pii_scan_service.scan_release_payload(request_body)
        assert excinfo.value.code == code
        assert isinstance(excinfo.value.code, str)

    def test_negative_timeout_rejected_with_code(self):
        with pytest.raises(pii_scan_service.PiiScanError) as excinfo:
            pii_scan_service.scan_release_payload(
                _release_request({}), timeout_seconds=-1)
        assert excinfo.value.code == "schema_invalid"


# ================================================================== ingest.*
class TestIngestService:
    @pytest.fixture()
    def workspace(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.md").write_text(_CONTRACT, "utf-8")
        (tmp_path / "src" / "b.txt").write_text("合成说明文：金额 12,000 元。", "utf-8")
        return tmp_path

    def test_submit_snapshots_files_and_persists_ledger(self, workspace):
        # exact bridge call shape: positional (state_root, sourceRefs,
        # parserProfileRef)
        view = ingest_service.ingest_submit(
            workspace, ["src/a.md", "src/b.txt"], "cn")
        assert view["state"] == "completed"
        assert view["counts"] == {"total": 2, "snapshotted": 2, "failed": 0}
        by_ref = {f["ref"]: f for f in view["files"]}
        raw = (workspace / "src" / "a.md").read_bytes()
        assert by_ref["src/a.md"]["sha256"] == hashlib.sha256(raw).hexdigest()
        assert by_ref["src/a.md"]["bytes"] == len(raw)
        assert by_ref["src/a.md"]["format"] == "markdown"
        assert by_ref["src/b.txt"]["format"] == "text"
        ledger = json.loads((
            workspace / ingest_service.LEDGER_DIR / f"{view['jobId']}.json"
        ).read_text("utf-8"))
        assert ledger["state"] == "completed"
        assert ingest_service.ingest_status(workspace, view["jobId"]) == view

    def test_ledger_never_contains_file_content(self, workspace):
        view = ingest_service.ingest_submit(workspace, ["src/a.md"], None)
        ledger_text = (
            workspace / ingest_service.LEDGER_DIR / f"{view['jobId']}.json"
        ).read_text("utf-8")
        assert "13711112222" not in ledger_text
        assert "委托人" not in ledger_text

    def test_missing_source_is_partial_with_typed_error(self, workspace):
        view = ingest_service.ingest_submit(workspace, ["src/a.md", "src/404.txt"], None)
        assert view["state"] == "partial"
        failed = [f for f in view["files"] if f["state"] == "failed"]
        assert [f["errorCode"] for f in failed] == ["ref_not_found"]

    def test_all_missing_is_failed(self, workspace):
        view = ingest_service.ingest_submit(workspace, ["src/404.txt"], None)
        assert view["state"] == "failed"

    def test_submit_rejects_empty_refs_and_bad_state_root(self, workspace):
        with pytest.raises(ingest_service.IngestError) as empty:
            ingest_service.ingest_submit(workspace, [], None)
        assert empty.value.code == "schema_invalid"
        with pytest.raises(ingest_service.IngestError) as root:
            ingest_service.ingest_submit(workspace / "nope", ["src/a.md"], None)
        assert root.value.code == "schema_invalid"
        with pytest.raises(ingest_service.IngestError) as refs:
            ingest_service.ingest_submit(workspace, [42], None)
        assert refs.value.code == "schema_invalid"

    def test_cancel_refuses_terminal_job(self, workspace):
        view = ingest_service.ingest_submit(workspace, ["src/a.md"], None)
        with pytest.raises(ingest_service.IngestError) as excinfo:
            ingest_service.ingest_cancel(workspace, view["jobId"])
        assert excinfo.value.code == "conflict"

    def test_cancel_cancels_crash_residue_running_job(self, workspace):
        view = ingest_service.ingest_submit(workspace, ["src/a.md"], None)
        ledger_path = (workspace / ingest_service.LEDGER_DIR
                       / f"{view['jobId']}.json")
        entry = json.loads(ledger_path.read_text("utf-8"))
        entry["state"] = "running"  # simulate a crash residue honestly
        ledger_path.write_text(json.dumps(entry), "utf-8")
        cancelled = ingest_service.ingest_cancel(workspace, view["jobId"])
        assert cancelled["state"] == "cancelled"

    def test_resume_fails_closed_on_drifted_source(self, workspace):
        view = ingest_service.ingest_submit(workspace, ["src/a.md", "src/b.txt"], None)
        assert view["state"] == "completed"
        (workspace / "src" / "a.md").write_text("内容已被替换。\n", "utf-8")
        resumed = ingest_service.ingest_resume(workspace, view["jobId"])
        assert resumed["state"] == "partial"
        drifted = [f for f in resumed["files"] if f["ref"] == "src/a.md"][0]
        assert drifted["errorCode"] == "hash_mismatch"
        intact = [f for f in resumed["files"] if f["ref"] == "src/b.txt"][0]
        assert intact["state"] == "snapshotted"

    def test_unknown_job_is_ref_not_found(self, workspace):
        with pytest.raises(ingest_service.IngestError) as excinfo:
            ingest_service.ingest_status(workspace, "ingest-nope")
        assert excinfo.value.code == "ref_not_found"


# ==================================================== anon.build_harness_handoff
@pytest.fixture()
def sanitized_matter(tmp_path):
    """Real chain: matter init → sanitize (dictionary-confirmed, AUTO_READY)
    → signed receipt, ready for handoff."""
    from legal_anonymizer.adapters.recognizers.project_dictionary import (
        ProjectDictionaryProvider,
    )

    dictionary = ProjectDictionaryProvider(
        blacklist=[
            {"value": "周敏", "type": "PERSON"},
        ]
    )
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
    def test_bridge_kwargs_shape_writes_source_manifest(self, sanitized_matter, tmp_path):
        state_root, out_dir = sanitized_matter
        handoff = tmp_path / "handoff"
        manifest = {
            "documentId": "doc-001",
            "sourceKind": "digital_text",
            "declaredPageCount": 3,
            "availablePageCount": 3,
            "parsedPages": [0, 1, 2],
            "failedPages": [],
            "coverage": "full",
            "parserProfileVersion": "handoff-1.1",
            "payloadDigest": "a" * 64,
        }
        # exact bridge call shape, incl. source_dir= + manifest= kwargs
        result = build_harness_handoff(state_root, "matter-bridge", handoff,
                                       source_dir=out_dir, manifest=manifest)
        assert result["artifact_count"] == 1
        written = json.loads(
            (handoff / "source-manifest.json").read_text("utf-8"))
        for key, value in manifest.items():
            assert written[key] == value
        assert written["matterId"] == "matter-bridge"
        assert written["artifactCount"] == 1
        assert written["bundleHash"]

    def test_bridge_resolver_can_bind_manifest(self, sanitized_matter, tmp_path):
        state_root, out_dir = sanitized_matter
        handoff = tmp_path / "handoff"
        build_harness_handoff(state_root, "matter-bridge", handoff,
                              source_dir=out_dir,
                              manifest={"documentId": "doc-001",
                                        "payloadDigest": "b" * 64,
                                        "reviewRequired": False})
        # what providers.py._external_ref_resolver reads back
        manifest_path = handoff / "source-manifest.json"
        assert manifest_path.exists()
        loaded = json.loads(manifest_path.read_text("utf-8"))
        assert loaded["payloadDigest"] == "b" * 64
        assert loaded["documentId"] == "doc-001"

    def test_no_manifest_keeps_previous_behavior(self, sanitized_matter, tmp_path):
        state_root, out_dir = sanitized_matter
        handoff = tmp_path / "handoff"
        build_harness_handoff(state_root, "matter-bridge", handoff,
                              source_dir=out_dir)
        assert not (handoff / "source-manifest.json").exists()

    def test_unknown_manifest_field_refused_fail_closed(self, sanitized_matter, tmp_path):
        state_root, out_dir = sanitized_matter
        with pytest.raises(HandoffError) as excinfo:
            build_harness_handoff(state_root, "matter-bridge", tmp_path / "h1",
                                  source_dir=out_dir,
                                  manifest={"documentId": "d", "surprise": 1})
        assert "surprise" in str(excinfo.value)

    def test_manifest_with_private_marker_refused(self, sanitized_matter, tmp_path):
        state_root, out_dir = sanitized_matter
        with pytest.raises(HandoffError):
            build_harness_handoff(
                state_root, "matter-bridge", tmp_path / "h2",
                source_dir=out_dir,
                manifest={"documentId": "d",
                          "coverage": "leak canonical_surface here"})

    def test_manifest_wrong_types_refused(self, sanitized_matter, tmp_path):
        state_root, out_dir = sanitized_matter
        for bad in ({"parsedPages": "0"}, {"documentId": ""},
                    {"payloadDigest": 7}):
            with pytest.raises(HandoffError):
                build_harness_handoff(state_root, "matter-bridge",
                                      tmp_path / "hx", source_dir=out_dir,
                                      manifest=bad)


def test_module_import_lightweight_like_bridge_probe():
    """The bridge probes availability with a bare __import__; the modules must
    import without touching model assets."""
    import importlib

    import legal_anonymizer.application.ingest_service as ingest_mod
    import legal_anonymizer.application.pii_scan_service as scan_mod

    assert importlib.reload(ingest_mod) is ingest_mod
    assert importlib.reload(scan_mod) is scan_mod
    assert consumer_bundle_service is not None
