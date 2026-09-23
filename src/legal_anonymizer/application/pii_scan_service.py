"""pii.scan service — bridge-facing release-payload scan (card 05 service track).

Bridge contract (jusbench_bridge/providers.py, read-only over there):

    scan_release_payload(request, timeout_seconds=None) -> dict

Every exception leaving this module carries a ``.code`` string attribute; the
bridge translates it verbatim into RpcError(code). Degradations that are part
of the scan outcome (unsupported release profile, model missing, timeout,
non-JSON payload) are REPORTED in the ``status`` field of a
scan-bytes-report-v1-shaped result — never silent, never a fabricated clean
bill. ``pii.scan_bytes`` stays the final-byte gate; this service scans the
in-memory payload the caller intends to release. Neither ever issues an
egress receipt — that gate is owned by the main-process broker.
"""

from __future__ import annotations

import hashlib
import json
import time

from .coverage_service import (
    RELEASE_PROFILE_ID,
    RELEASE_PROFILE_VERSION,
    build_coverage_statement,
)
from .scan_bytes_service import _MAX_DEPTH, SCAN_PROFILE, _scan_strings


class PiiScanError(ValueError):
    """Bridge-visible error; ``.code`` is a plain string code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _report(request_id: str, status: str, body_sha: str | None, scanned_len: int,
            unscanned: int, alerts: int, coverage: dict) -> dict:
    return {
        "requestId": request_id,
        "status": status,
        "bodySha256": body_sha,
        "scannedByteLength": scanned_len,
        "unscannedSegmentCount": unscanned,
        "alertCount": alerts,
        "coverageStatement": coverage,
    }


class _ScanDeadline(Exception):
    pass


def _scan_value(node, registry, deadline: float | None, depth: int = 0) -> tuple[int, int]:
    """Recursive keys-and-strings scan with a wall-clock deadline.

    Mirrors scan_bytes_service._scan_json_value coverage; the timeout is an
    additional caller constraint, and hitting it leaves the remainder
    UNscanned (fail closed via status='timeout', never a clean claim)."""
    if deadline is not None and time.monotonic() > deadline:
        raise _ScanDeadline
    if depth > _MAX_DEPTH:
        return 0, 1
    if isinstance(node, str):
        return _scan_strings(node, registry), 0
    if isinstance(node, dict):
        alerts = unscanned = 0
        for k, v in node.items():
            alerts += _scan_strings(str(k), registry)
            a, u = _scan_value(v, registry, deadline, depth + 1)
            alerts += a
            unscanned += u
        return alerts, unscanned
    if isinstance(node, list):
        alerts = unscanned = 0
        for item in node:
            a, u = _scan_value(item, registry, deadline, depth + 1)
            alerts += a
            unscanned += u
        return alerts, unscanned
    if node is None or isinstance(node, (bool, int, float)):
        return 0, 0
    return 0, 1


def scan_release_payload(request, timeout_seconds=None, registry=None) -> dict:
    if not isinstance(request, dict):
        raise PiiScanError("schema_invalid", "request must be a JSON object")
    request_id = str(request.get("requestId") or "")
    if not request_id:
        raise PiiScanError("schema_invalid", "requestId is required")
    if "payload" not in request:
        raise PiiScanError("schema_invalid", "payload is required")
    payload = request["payload"]
    if timeout_seconds is not None:
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError):
            raise PiiScanError("schema_invalid", "timeoutSeconds must be a number")
        if timeout < 0:
            raise PiiScanError("schema_invalid", "timeoutSeconds must be >= 0")

    if registry is None:
        from ..adapters.recognizers.registry import RecognizerRegistry

        registry = RecognizerRegistry()
    coverage = build_coverage_statement(registry)

    if (request.get("releaseProfileId") != RELEASE_PROFILE_ID
            or request.get("profileVersion") != RELEASE_PROFILE_VERSION
            or request.get("scanProfile") != SCAN_PROFILE):
        # the caller believes it is releasing under a different profile; this
        # scanner cannot attest a payload for a profile it does not run
        return _report(request_id, "unsupported_format", None, 0, 1, 0, coverage)
    if not registry.ner_available:
        return _report(request_id, "model_missing", None, 0, 1, 0, coverage)

    try:
        body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        # not strictly JSON-expressible: byte digest would be a lie
        return _report(request_id, "unsupported_format", None, 0, 1, 0, coverage)

    deadline = None if timeout_seconds is None else time.monotonic() + float(timeout_seconds)
    try:
        alerts, unscanned = _scan_value(payload, registry, deadline)
    except _ScanDeadline:
        return _report(request_id, "timeout", hashlib.sha256(body).hexdigest(),
                       len(body), 1, 0, coverage)
    status = "complete" if (unscanned == 0) else "failed"
    return _report(request_id, status, hashlib.sha256(body).hexdigest(),
                   len(body), unscanned, alerts, coverage)
