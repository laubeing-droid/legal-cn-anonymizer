"""CLI scan-bytes subcommand (V42-R2 item 7): final-byte scan from the shell.

Drives cli.main exactly as a user would (real registry; NER-dependent
assertions skip when the model stack is absent). Reports are validated
against the frozen scan-bytes-request/report schemas; nothing is printed to
stdout but the report (JSON), and no egress receipt is ever produced.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from legal_anonymizer.cli import main
from legal_anonymizer.contracts.schemas import SCHEMAS_DIR

_REPORT_SCHEMA = json.loads(
    (Path(SCHEMAS_DIR) / "scan-bytes-report-v1.schema.json").read_text("utf-8"))

_CLEAN = json.dumps({"note": "本合同已按约定履行完毕。"}, ensure_ascii=False)
_WITH_PII = json.dumps({"content": "客户陈大壮电话13700009999"},
                       ensure_ascii=False)


def _run_scan(tmp_path, body: str, extra=None):
    infile = tmp_path / "payload.json"
    infile.write_text(body, encoding="utf-8")
    code = main(["scan-bytes", str(infile), *extra] if extra
                else ["scan-bytes", str(infile)])
    return code


def _requires_ner() -> None:
    from legal_anonymizer.adapters.recognizers.registry import RecognizerRegistry

    if not RecognizerRegistry().ner_available:
        pytest.skip("NER stack unavailable")


def test_scan_bytes_complete_on_clean_payload(tmp_path, capsys):
    code = _run_scan(tmp_path, _CLEAN)
    report = json.loads(capsys.readouterr().out)
    jsonschema.validate(report, _REPORT_SCHEMA)
    expected = hashlib.sha256(_CLEAN.encode("utf-8")).hexdigest()
    assert report["bodySha256"] == expected
    assert report["scannedByteLength"] == len(_CLEAN.encode("utf-8"))
    assert report["coverageStatement"]["releaseProfileId"] == "cn-release-v42"
    assert "receipt" not in json.dumps(report)
    if report["status"] == "model_missing":
        assert code == 2
        pytest.skip("NER stack unavailable: model_missing")
    assert report["status"] == "complete"
    assert code == 0


def test_scan_bytes_counts_alerts_but_stays_exit_complete(tmp_path, capsys):
    _requires_ner()
    code = _run_scan(tmp_path, _WITH_PII)
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "complete"   # coverage complete…
    assert report["alertCount"] >= 2        # …but the PII is reported
    assert code == 0


def test_scan_bytes_writes_report_to_out(tmp_path, capsys):
    _requires_ner()
    infile = tmp_path / "p.json"
    infile.write_text(_CLEAN, encoding="utf-8")
    out = tmp_path / "report.json"
    code = main(["scan-bytes", str(infile), "-o", str(out),
                 "--request-id", "cli-test-1"])
    report = json.loads(out.read_text("utf-8"))
    assert report["requestId"] == "cli-test-1"
    assert code == 0
    assert capsys.readouterr().out == ""    # stdout stays clean when -o given


def test_scan_bytes_reads_stdin(tmp_path, capsys, monkeypatch):
    import io

    class _FakeStdin:
        def __init__(self, data: bytes):
            self.buffer = io.BytesIO(data)

    monkeypatch.setattr("sys.stdin", _FakeStdin(_CLEAN.encode("utf-8")))
    code = main(["scan-bytes", "-"])
    report = json.loads(capsys.readouterr().out)
    assert report["scannedByteLength"] == len(_CLEAN.encode("utf-8"))
    assert code in (0, 2)
