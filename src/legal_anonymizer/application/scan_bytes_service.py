"""pii.scan_bytes — final-byte scanning (plan-v4.2 card 05-3, B02 side A).

Scans the EXACT serialized JSON bytes a consumer intends to send: strict
base64/UTF-8/JSON decoding, recursive coverage of every key and string value,
digests recomputed from the actual bytes (never echoing the caller's claimed
values back as proof). This service produces a ScanBytesReport only — the
egress receipt is issued by the main-process broker after its own trusted
config check (scannerMayIssueReceipt = false).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json

from .coverage_service import build_coverage_statement

SCAN_PROFILE = "json-recursive-keys-and-strings/v1"
_MAX_DEPTH = 64


def _report(request_id, status, body_sha, scanned_len, unscanned, alerts,
            coverage):
    return {
        "requestId": request_id,
        "status": status,
        "bodySha256": body_sha,
        "scannedByteLength": scanned_len,
        "unscannedSegmentCount": unscanned,
        "alertCount": alerts,
        "coverageStatement": coverage,
    }


def scan_bytes(request: dict, registry=None, verifier=None) -> dict:
    request_id = str(request.get("requestId", "")) or "unidentified"
    from ..adapters.recognizers.registry import RecognizerRegistry

    registry = registry or RecognizerRegistry()
    coverage = build_coverage_statement(registry, verifier=verifier)
    from .coverage_service import RELEASE_PROFILE_ID, RELEASE_PROFILE_VERSION

    if (request.get("releaseProfileId") != RELEASE_PROFILE_ID
            or request.get("profileVersion") != RELEASE_PROFILE_VERSION):
        # the caller believes it is sending under a different release profile;
        # this scanner cannot attest bytes for a profile it does not run
        return _report(request_id, "unsupported_format", None, 0, 1, 0, coverage)
    if request.get("scanProfile") != SCAN_PROFILE:
        return _report(request_id, "unsupported_format", None, 0, 1, 0, coverage)
    if not registry.ner_available:
        return _report(request_id, "model_missing", None, 0, 1, 0, coverage)

    try:
        body = base64.b64decode(request.get("bodyBase64", ""), validate=True)
    except (binascii.Error, ValueError):
        return _report(request_id, "failed", None, 0, 1, 0, coverage)

    actual_sha = hashlib.sha256(body).hexdigest()
    if (request.get("bodySha256") != actual_sha
            or request.get("byteLength") != len(body)):
        # declared digest/length must match the ACTUAL bytes; a mismatch means
        # the caller's copy is not the copy we would certify — refuse, never
        # echo the claimed values
        return _report(request_id, "failed", actual_sha, len(body), 1, 0, coverage)

    try:
        text = body.decode("utf-8")  # strict: any invalid sequence fails
        payload = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _report(request_id, "unsupported_format", actual_sha, len(body),
                       1, 0, coverage)

    alerts, unscanned = _scan_json_value(payload, registry, depth=0)
    return _report(
        request_id,
        "complete" if (alerts == 0 and unscanned == 0) else
        ("failed" if unscanned else "complete"),
        actual_sha, len(body), unscanned, alerts, coverage,
    )


def _scan_strings(container: str, registry) -> int:
    return len([d for d in registry.detect(container)
                if not d.entity_type.startswith(("MONEY", "LEGAL_DATE"))])


def _scan_json_value(node, registry, depth: int) -> tuple[int, int]:
    """Returns (alert_count, unscanned_segment_count) over keys AND strings."""
    alerts = unscanned = 0
    if depth > _MAX_DEPTH:
        return 0, 1  # pathological nesting: refuse to claim full coverage
    if isinstance(node, str):
        alerts += _scan_strings(node, registry)
    elif isinstance(node, dict):
        for k, v in node.items():
            alerts += _scan_strings(str(k), registry)
            a, u = _scan_json_value(v, registry, depth + 1)
            alerts += a
            unscanned += u
    elif isinstance(node, list):
        for item in node:
            a, u = _scan_json_value(item, registry, depth + 1)
            alerts += a
            unscanned += u
    elif node is None or isinstance(node, (bool, int, float)):
        pass  # JSON scalars carry no strings; numbers scanned by rules? they
        # are not text spans — treated as scanned (not unscanned) segments
    else:
        unscanned += 1
    return alerts, unscanned
