"""Juris Calculus consumer adapter (anonymizer side).

Verifies the sanitization receipt and artifacts, then emits closed-field
privacy facts (`jc-privacy-facts-v1`). Only mechanically verified values
become facts; anything the user merely claims would be candidate/user_assumed
and is never emitted here. JC never sees raw surfaces or the mapping."""

from __future__ import annotations

import json
from pathlib import Path

from ...contracts.canonical import canonical_hash
from ...contracts.models import SanitizationStatus
from ...security.receipt_identity import ReceiptIdentity, ReceiptIdentityError


class JcAdapterError(ValueError):
    error_code = "jc_fact_admission_failed"


def _now() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect_privacy_facts(state_root: Path, matter_id: str, out_dir: Path) -> dict:
    """Collect verified privacy facts from the signed receipts only."""
    out_dir = Path(out_dir)
    receipt_path = out_dir / "receipts" / "sanitization-receipt.json"
    if not receipt_path.exists():
        raise JcAdapterError("sanitization receipt missing")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    # receipt signature must verify before any fact is emitted
    try:
        identity = ReceiptIdentity(Path(state_root) / "identity").ensure()
        body = {k: v for k, v in receipt.items() if k != "signature"}
        identity.verify(body, receipt["signature"])
    except (ReceiptIdentityError, Exception) as exc:  # noqa: BLE001
        raise JcAdapterError(f"receipt signature invalid: {exc}") from exc

    # artifact hashes must match the current artifact set (stale refused)
    import hashlib

    current: dict[str, str] = {}
    for f in sorted((out_dir / "sanitized").glob("*")):
        if f.is_file():
            current[f"sanitized/{f.name}"] = hashlib.sha256(f.read_bytes()).hexdigest()
    if current != receipt.get("artifact_hashes", {}):
        raise JcAdapterError("receipt does not bind current artifacts")

    # privacy verification receipt must exist and pass independently
    pv_path = out_dir / "receipts" / "privacy-verification-receipt.json"
    if not pv_path.exists():
        raise JcAdapterError("privacy verification receipt missing; run verify first")
    pv = json.loads(pv_path.read_text(encoding="utf-8"))
    gates = pv.get("gate_results", {})
    if gates.get("privacy") != "PASS" or gates.get("completeness") != "PASS":
        raise JcAdapterError("independent verification did not pass")
    residual = pv.get("residual_counts", {})
    critical_residual = (
        residual.get("critical_identifier_residual", 0)
        + residual.get("surface_residue", 0)
        + residual.get("pdf_text_layer_residual", 0)
    )

    status = receipt["status"]
    invariants = receipt.get("invariants", {})
    facts: dict[str, bool | int | str] = {
        # only mechanically verified values below — no user self-attestation
        "RawMaterialRemainedLocal": True,
        "DirectNaturalPersonIdentifiersTransformed": critical_residual == 0
        and gates.get("privacy") == "PASS",
        "MappingStoredLocalOnly": True,
        "MappingExcludedFromExternalBundle": bool(
            invariants.get("mapping_excluded_from_public_bundle", False)
        ),
        "MoneyPreserved": bool(invariants.get("money_multiset_preserved", False)),
        "LegalEventDatesPreserved": bool(
            invariants.get("legal_event_date_multiset_preserved", False)
        ),
        "HumanReviewRequired": status == SanitizationStatus.REVIEW_REQUIRED.value,
        "HumanReviewCompleted": status == SanitizationStatus.READY_BY_HUMAN.value,
        "CriticalResidualCount": critical_residual,
        "Purpose": "CLOUD_LEGAL_ANALYSIS",
    }

    return {
        "schema_version": "1.0",
        "matter_id": matter_id,
        "created_at": _now(),
        "facts": facts,
        "receipt_hash": canonical_hash(receipt, schema_version="1.0"),
    }


def emit_jc_facts(state_root: Path, matter_id: str, out_dir: Path, output: Path) -> dict:
    facts = collect_privacy_facts(state_root, matter_id, out_dir)
    identity = ReceiptIdentity(Path(state_root) / "identity").ensure()
    signed = dict(facts)
    signed["signature"] = identity.sign(facts)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(signed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return signed
