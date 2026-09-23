"""pii.scan service — bridge-facing file-set payload scan (card 05-3, U-PII).

FROZEN contract (jusbench plan-v4.2: methods-core.json + ifc-2.schema.json +
types-ifc2.json, read-only over there):

    input   {request: PiiScanRequest{payloadRoot, expectedFiles,
                                     expectedPayloadDigest}}
    output  PiiScanReport{tool, toolVersion, ruleVersion, status,
                          expectedFiles, actualScannedFiles, payloadDigest,
                          alertCount, alerts[{file, rule, detail}]}
            + PiiScanReportAddition{coverageStatement}
    digest  IF-03 authoritative formula, bare hex:
            sha256(concat over files sorted by rel of f"{rel}\n{sha256hex}\n")
    success = complete AND expected==actual AND digest matches AND
              alertCount == 0
    error envelopes (.code): payload_modified / scan_incomplete /
    unsupported_format / timeout (plus the wire-generic schema_invalid)

`pii.scan` scans the file SET under payloadRoot; `pii.scan_bytes` (B02) is
the separate final-byte method. Alerts report span offsets only — original
surfaces are NEVER echoed. This service never issues an egress receipt.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from .coverage_service import (
    RELEASE_PROFILE_ID,
    RELEASE_PROFILE_VERSION,
    build_coverage_statement,
)

_ERROR_ENVELOPES = ("payload_modified", "scan_incomplete",
                    "unsupported_format", "timeout")


class PiiScanError(ValueError):
    """Bridge-visible error; ``.code`` is one of the frozen envelopes."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    if code not in _ERROR_ENVELOPES:
        raise AssertionError(f"internal error code {code!r} outside the frozen set")
    raise PiiScanError(code, message)


def payload_digest(entries: list[tuple[str, bytes]]) -> str:
    """IF-03 authoritative set digest: over files sorted by rel, concat
    f"{rel}\\n{sha256hex}\\n", sha256 of the whole, bare lowercase hex."""
    joined = "".join(
        f"{rel}\n{hashlib.sha256(data).hexdigest()}\n"
        for rel, data in sorted(entries, key=lambda e: e[0])
    )
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _alert_spans(text: str, registry, rel: str) -> list[dict]:
    """One alert per detection, span offsets only — never the surface."""
    alerts = []
    for det in registry.detect(text):
        if det.entity_type.startswith(("MONEY", "LEGAL_DATE")):
            continue
        alerts.append({
            "file": rel,
            "rule": det.entity_type,
            "detail": f"chars {det.start}-{det.end}",
        })
    return alerts


def scan_release_payload(request, timeout_seconds=None, registry=None) -> dict:
    if not isinstance(request, dict):
        raise PiiScanError("schema_invalid", "request must be a JSON object")
    allowed = ("payloadRoot", "expectedFiles", "expectedPayloadDigest")
    unknown = sorted(set(request) - set(allowed))
    if unknown:
        raise PiiScanError("schema_invalid",
                           f"PiiScanRequest carries unknown fields: {unknown}")
    payload_root = request.get("payloadRoot")
    expected_files = request.get("expectedFiles")
    expected_digest = request.get("expectedPayloadDigest")
    if not isinstance(payload_root, str) or not payload_root.strip():
        raise PiiScanError("schema_invalid", "payloadRoot must be a path string")
    if not isinstance(expected_files, list) or \
            not all(isinstance(f, str) and f.strip() for f in expected_files):
        raise PiiScanError("schema_invalid",
                           "expectedFiles must be a list of path strings")
    if not isinstance(expected_digest, str) or not expected_digest.strip():
        raise PiiScanError("schema_invalid",
                           "expectedPayloadDigest must be a digest string")
    if timeout_seconds is not None:
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError):
            raise PiiScanError("schema_invalid", "timeoutSeconds must be a number")
        if timeout < 0:
            raise PiiScanError("schema_invalid", "timeoutSeconds must be >= 0")

    root = Path(payload_root)
    if not root.is_dir():
        _fail("unsupported_format", f"payloadRoot is not a directory: {payload_root}")

    if registry is None:
        from ..adapters.recognizers.registry import RecognizerRegistry

        registry = RecognizerRegistry()
    if not registry.ner_available:
        _fail("scan_incomplete",
              "ner_model_unavailable: "
              + str(registry.status.get("reason") or "model assets missing"))
    coverage = build_coverage_statement(registry)

    deadline = None if timeout_seconds is None else time.monotonic() + float(timeout_seconds)
    entries: list[tuple[str, bytes]] = []
    alerts: list[dict] = []
    for rel in expected_files:
        path = root / rel
        if not path.is_file():
            _fail("scan_incomplete",
                  f"expected file missing from payload: {rel}")
        if deadline is not None and time.monotonic() > deadline:
            _fail("timeout", f"scan budget exhausted before {rel}")
        try:
            data = path.read_bytes()
        except OSError:
            _fail("scan_incomplete", f"expected file not readable: {rel}")
        entries.append((rel, data))
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            _fail("unsupported_format",
                  f"expected file is not valid UTF-8 text: {rel}")
        alerts.extend(_alert_spans(text, registry, rel))

    actual_digest = payload_digest(entries)
    if actual_digest != expected_digest:
        _fail("payload_modified",
              "payload digest does not match the caller's declared digest; "
              "the payload changed after the digest was pinned (rescan needed)")
    files = [rel for rel, _ in entries]
    return {
        "tool": "legal-cn-anonymizer",
        "toolVersion": _tool_version(),
        "ruleVersion": f"{RELEASE_PROFILE_ID}@{RELEASE_PROFILE_VERSION}",
        "status": "complete" if not alerts else "failed",
        "expectedFiles": list(expected_files),
        "actualScannedFiles": files,
        "payloadDigest": actual_digest,
        "alertCount": len(alerts),
        "alerts": alerts,
        "coverageStatement": coverage,
    }


def _tool_version() -> str:
    from .. import __version__

    return __version__
