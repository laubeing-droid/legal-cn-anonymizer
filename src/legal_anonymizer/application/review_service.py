"""Human review: decisions files, signed review receipts, READY_BY_HUMAN.

A review receipt binds: matter, report hash, sanitized bundle hash, reviewer
subject/role, decisions hash, issued time, single-use flag. A REVIEW_REQUIRED
matter becomes READY_BY_HUMAN only when machine gates pass AND a valid signed
receipt covers the current artifact set. Any artifact change invalidates the
receipt (verify recomputes artifact hashes)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..contracts.canonical import canonical_hash, canonical_json
from ..contracts.models import SanitizationStatus
from ..security.receipt_identity import ReceiptIdentity
from .state import MatterState

REVIEWER_ROLES = ("UPLOADING_LAWYER", "MATTER_LEAD", "DESIGNATED_REVIEWER")


class ReviewError(ValueError):
    error_code = "human_review_receipt_invalid"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_decisions(path: Path) -> dict:
    """Load review decisions from JSON (or YAML when PyYAML is available)."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml

            payload = yaml.safe_load(text)
        except ImportError as exc:
            raise ReviewError("YAML requires PyYAML; use JSON decisions") from exc
    else:
        payload = json.loads(text)
    if not isinstance(payload, dict) or "matter_id" not in payload:
        raise ReviewError("decisions file must be an object with matter_id")
    return payload


def compute_decisions_hash(decisions: dict) -> str:
    return canonical_hash(decisions, schema_version="1.0")


def artifact_set_hash(out_dir: Path) -> str:
    """Hash over the current sanitized artifact set (name -> sha256)."""
    import hashlib

    sanitized_dir = Path(out_dir) / "sanitized"
    hashes = {}
    for f in sorted(sanitized_dir.glob("*")):
        if f.is_file():
            hashes[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
    return canonical_hash(hashes, schema_version="1.0")


def issue_review_receipt(
    state_root: Path,
    matter_id: str,
    out_dir: Path,
    decisions: dict,
    reviewer_subject: str,
    reviewer_role: str,
) -> dict:
    if reviewer_role not in REVIEWER_ROLES:
        raise ReviewError(f"unknown reviewer role: {reviewer_role}")
    state = MatterState.load(state_root, matter_id)
    receipt_path = Path(out_dir) / "receipts" / "sanitization-receipt.json"
    if not receipt_path.exists():
        raise ReviewError("sanitization receipt missing; nothing to review")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt["artifact_hashes"] and receipt["sanitized_bundle_hash"] != canonical_hash(
        receipt["artifact_hashes"], schema_version="1.0"
    ):
        raise ReviewError("sanitization receipt does not bind its own artifacts")

    body = {
        "schema_version": "1.0",
        "matter_id": matter_id,
        "report_hash": canonical_hash(receipt.get("invariants", {}), schema_version="1.0"),
        "sanitized_bundle_hash": artifact_set_hash(out_dir),
        "reviewer_subject": reviewer_subject,
        "reviewer_role": reviewer_role,
        "decisions_hash": compute_decisions_hash(decisions),
        "issued_at": _now(),
        "single_use": True,
        "revision": 1,
    }
    identity = ReceiptIdentity(Path(state_root) / "identity").ensure()
    signed = dict(body)
    signed["signature"] = identity.sign(body)
    out = Path(out_dir) / "receipts" / "human-review-receipt.json"
    out.write_text(
        json.dumps(signed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    # the sanitization receipt is re-issued at READY_BY_HUMAN with the review
    # receipt embedded, so bundles bind the full accountability chain
    src_receipt_path = Path(out_dir) / "receipts" / "sanitization-receipt.json"
    if src_receipt_path.exists():
        src_receipt = json.loads(src_receipt_path.read_text(encoding="utf-8"))
        src_receipt["status"] = SanitizationStatus.READY_BY_HUMAN.value
        src_receipt["review"] = signed
        src_receipt["signature"] = identity.sign(
            {k: v for k, v in src_receipt.items() if k != "signature"}
        )
        src_receipt_path.write_text(
            json.dumps(src_receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    # decisions persist into private state (DPAPI), not into public artifacts
    private = state.read_private()
    private.setdefault("decisions", []).append(
        {"decisions_hash": body["decisions_hash"], "issued_at": body["issued_at"],
         "receipt_hash": canonical_hash(signed, schema_version="1.0")}
    )
    state.write_private(private)
    return signed


def check_review(state_root: Path, matter_id: str, out_dir: Path,
                 gates: dict) -> str:
    """Return the final status considering machine gates and review receipts."""
    if SanitizationStatus.CLOSED_BLOCK.value in gates.get("status", ""):
        return gates["status"]
    if gates["privacy"] == "FAIL" or gates["completeness"] == "FAIL" or gates["utility"] == "FAIL":
        return SanitizationStatus.CLOSED_BLOCK.value
    public = MatterState.load(state_root, matter_id).read_public()
    if public.get("status") != SanitizationStatus.REVIEW_REQUIRED.value:
        return public.get("status", SanitizationStatus.AUTO_READY.value)
    receipt_path = Path(out_dir) / "receipts" / "human-review-receipt.json"
    if not receipt_path.exists():
        return SanitizationStatus.REVIEW_REQUIRED.value
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        identity = ReceiptIdentity(Path(state_root) / "identity").ensure()
        body = {k: v for k, v in receipt.items() if k != "signature"}
        identity.verify(body, receipt["signature"])
    except Exception as exc:  # noqa: BLE001 - any invalid receipt stays blocked
        raise ReviewError(f"review receipt invalid: {exc}") from exc
    if receipt["matter_id"] != matter_id:
        raise ReviewError("review receipt binds another matter")
    if receipt["sanitized_bundle_hash"] != artifact_set_hash(out_dir):
        raise ReviewError("review receipt does not bind current artifacts (stale receipt)")
    return SanitizationStatus.READY_BY_HUMAN.value
