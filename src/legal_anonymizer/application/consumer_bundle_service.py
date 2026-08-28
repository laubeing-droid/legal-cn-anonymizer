"""Legal Harness handoff export (anonymizer side only).

This adapter produces a signed, hash-bound handoff package. It NEVER touches
Harness MatterStore/CAS/Agents/Broker, never writes a Harness state root, and
never fabricates ProviderReceipt/HostEvidence/QC/activation evidence. What
Harness does with the package is governed by a separate construction plan."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..contracts.canonical import canonical_hash
from ..contracts.models import SanitizationStatus
from ..contracts.signatures import SignatureError
from .review_service import ReviewError
from .state import MatterState, MatterStateError
from ..security.receipt_identity import ReceiptIdentity

_FORBIDDEN_MARKERS = ("canonical_surface", '"surface"', "matter_secret", "original_filename")

STRUCTURED_OBJECT_TYPES = ("Party", "MatterProfile", "RepresentationProfile",
                           "ProceduralContext", "ProceduralEvent")


class HandoffError(ValueError):
    error_code = "harness_bundle_invalid"


def _now() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def structured_objects(state: MatterState) -> list[dict]:
    """Build sanitized structured business objects from the SAME entity vault
    used for the document text: display aliases and internal ids only."""
    private = state.read_private()
    objects: list[dict] = []
    party_index = 0
    for entity in private.get("entities", []):
        if entity["entity_type"] in ("PERSON", "LEGAL_PERSON", "UNINCORPORATED_ORG"):
            party_index += 1
            objects.append(
                {
                    "object_type": "Party",
                    "party_id": f"party-{party_index:03d}",
                    "name": entity["display_alias"],
                    "entity_id": entity["entity_id"],
                    "party_type": (
                        "individual"
                        if entity["entity_type"] == "PERSON"
                        else "organization"
                    ),
                    "procedural_role": list(entity.get("roles", [])),
                }
            )
    for entity in private.get("entities", []):
        if entity["entity_type"] == "PROJECT":
            objects.append(
                {
                    "object_type": "MatterProfile",
                    "title": entity["display_alias"],
                    "entity_id": entity["entity_id"],
                    "matters": "single-matter",
                }
            )
    return objects


def build_harness_handoff(state_root: Path, matter_id: str, out_dir: Path,
                          source_dir: Path | None = None) -> dict:
    state = MatterState.load(state_root, matter_id)
    public = state.read_public()
    out_dir = Path(out_dir)
    (out_dir / "sanitized").mkdir(parents=True, exist_ok=True)

    # find the source output receipts: require a signed sanitization receipt
    source_dir = Path(source_dir) if source_dir is not None else out_dir
    src_receipt = None
    receipts_dir = None
    for candidate in (Path(source_dir) / "receipts", Path(out_dir) / "receipts",
                      Path(out_dir).parent / "receipts"):
        p = candidate / "sanitization-receipt.json"
        if p.exists():
            src_receipt = json.loads(p.read_text(encoding="utf-8"))
            receipts_dir = candidate
            break
    if src_receipt is None:
        raise HandoffError("no signed sanitization receipt found; run sanitize first")

    status = src_receipt.get("status")
    if status not in (SanitizationStatus.AUTO_READY.value,
                      SanitizationStatus.READY_BY_HUMAN.value):
        raise HandoffError(
            f"matter status is {status}; handoff is only allowed for AUTO_READY/READY_BY_HUMAN"
        )
    human_receipt = None
    hr_path = receipts_dir / "human-review-receipt.json" if receipts_dir else None
    if hr_path and hr_path.exists():
        human_receipt = json.loads(hr_path.read_text(encoding="utf-8"))
    elif status == SanitizationStatus.READY_BY_HUMAN.value:
        raise HandoffError("READY_BY_HUMAN requires a human review receipt")

    # copy sanitized artifacts (stable doc-xxx names only)
    artifacts = []
    src_dir = Path(source_dir) / "sanitized"
    dst_dir = out_dir / "sanitized"
    dst_dir.mkdir(parents=True, exist_ok=True)
    for f in sorted(src_dir.glob("doc-*")):
        if f.is_file() and not f.name.startswith("~$"):
            data = f.read_bytes()
            (dst_dir / f.name).write_bytes(data)
            artifacts.append(
                {
                    "name": f.name,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                }
            )
    if not artifacts:
        raise HandoffError("no sanitized artifacts to hand off")

    # private-data exclusion check (fail closed)
    for f in dst_dir.iterdir():
        text = f.read_text(encoding="utf-8", errors="ignore")
        for marker in _FORBIDDEN_MARKERS:
            if marker in text:
                raise HandoffError(f"private field marker {marker!r} found in {f.name}")

    objects = structured_objects(state)
    bundle = {
        "schema_version": "1.0",
        "matter_id": matter_id,
        "profile_id": public["profile_id"],
        "created_at": _now(),
        "status": status,
        "artifacts": artifacts,
        "receipt_hash": canonical_hash(src_receipt, schema_version="1.0"),
        "structured_objects": objects,
    }
    identity = ReceiptIdentity(Path(state_root) / "identity").ensure()
    bundle_sig = identity.sign(bundle)
    bundle_signed = dict(bundle)
    bundle_signed["signature"] = bundle_sig

    (out_dir / "sanitized-bundle.json").write_text(
        json.dumps(bundle_signed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "sanitization-receipt.json").write_text(
        json.dumps(src_receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if human_receipt is not None:
        (out_dir / "human-review-receipt.json").write_text(
            json.dumps(human_receipt, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    material_input = {
        "schema_version": "1.0",
        "matter_id": matter_id,
        "documents": [
            {"document_id": a["name"].split(".")[0], "artifact": a["name"],
             "sha256": a["sha256"]}
            for a in artifacts
        ],
        "note": "sanitized materials only; original files never leave the machine",
    }
    (out_dir / "material-input.json").write_text(
        json.dumps(material_input, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "bundle_dir": str(out_dir),
        "artifact_count": len(artifacts),
        "structured_objects": len(objects),
        "bundle_hash": canonical_hash(bundle, schema_version="1.0"),
    }
