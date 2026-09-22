"""W15c-A disposal service — the nine-step disposal contract (card 05-4).

Public entries (signatures pinned by the jusbench bridge):
    execute_disposal(state_root, scope, key, authorization_ref) -> receipt
    read_disposal(state_root, scope, request_id) -> receipt

Nine implementation steps:
 1. read the Harness-registered disposal authorization reference;
 2. verify matter / archive version / target object versions / policy /
    reason / decision — anything missing or mismatched fails closed;
 3. only Anonymizer-registered managed objects may be disposed;
 4. external input originals are NEVER auto-registered by scanning and can
    never be disposed through this path;
 5. per-object state journal: pending -> deleted | failed;
 6. receipts and idempotency live in a separate disposal ledger, never inside
    the mapping store that is being deleted;
 7. a restarted process resumes pending objects from the journal;
 8. once the mapping is disposed, no startup path recreates an empty mapping
    pretending the original mapping still exists (MatterState fails closed);
 9. deletion is a logical unlink; nothing claims media-level erasure.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from ..contracts.consumer_manifest import verify_signature_with_public
from ..contracts.signatures import SignatureError

LEDGER_DIR = "disposal-ledger"
AUTH_DIR = "authorizations"
TRUSTED_KEYS_DIR = "trusted-keys"
MANIFEST_NAME = "managed-objects.json"

# kinds that may legitimately be managed here; input originals are excluded
_MANAGED_KINDS = {"private-mapping", "matter-manifest", "sealed-cache"}


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ledger_root(state_root: Path) -> Path:
    return Path(state_root) / LEDGER_DIR


class DisposalError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _matter_dir(state_root: Path, matter_id: str) -> Path:
    return Path(state_root) / matter_id


def _objects_manifest_path(state_root: Path, matter_id: str) -> Path:
    return _matter_dir(state_root, matter_id) / MANIFEST_NAME


def _load_objects(state_root: Path, matter_id: str) -> dict:
    p = _objects_manifest_path(state_root, matter_id)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def register_managed_object(state_root: Path, matter_id: str, object_id: str,
                            kind: str, rel_path: str) -> str:
    """Register an Anonymizer-owned object for future disposal and return its
    pinned version (sha256 digest of current content). Refuses external input
    originals and non-registered kinds (steps 3 and 4)."""
    if kind not in _MANAGED_KINDS:
        raise DisposalError(
            "verification_failed",
            f"object kind {kind!r} is not a managed anonymizer object",
        )
    md = _matter_dir(state_root, matter_id)
    path = md / rel_path
    if not path.is_file():
        raise DisposalError("ref_not_found", f"managed object file missing: {rel_path}")
    version = hashlib.sha256(path.read_bytes()).hexdigest()
    objs = _load_objects(state_root, matter_id)
    objs[object_id] = {"kind": kind, "rel_path": rel_path, "version": version,
                       "registered_at": _now()}
    _objects_manifest_path(state_root, matter_id).write_text(
        json.dumps(objs, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return version


def _load_authorization(state_root: Path, ref: dict) -> dict:
    ref_id = str((ref or {}).get("id", ""))
    if not ref_id:
        raise DisposalError("ref_not_found", "authorizationRef.id missing")
    p = Path(state_root) / AUTH_DIR / f"{ref_id}.json"
    if not p.exists():
        raise DisposalError("ref_not_found", f"authorization {ref_id} not registered")
    record = json.loads(p.read_text(encoding="utf-8"))
    if record.get("authorizationRef", {}).get("version") != (ref or {}).get("version"):
        raise DisposalError("verification_failed",
                            "authorizationRef version mismatch with registered record")
    key_path = Path(state_root) / TRUSTED_KEYS_DIR / f"{record['signature']['key_id']}.json"
    if not key_path.exists():
        raise DisposalError("verification_failed",
                            "authorization signer key is not trusted on this machine")
    public = json.loads(key_path.read_text(encoding="utf-8"))["public_key_b64"]
    body = {k: v for k, v in record.items() if k != "signature"}
    try:
        verify_signature_with_public(public, body, record["signature"])
    except SignatureError as exc:
        raise DisposalError("verification_failed", f"authorization signature invalid: {exc}")
    return record


def execute_disposal(state_root, scope, key, authorization_ref) -> dict:
    state_root = Path(state_root)
    matter_id = str((scope or {}).get("matterId") or "")
    request_id = str((key or {}).get("requestId") or (key or {}).get("operationId") or "")
    if not matter_id or not request_id:
        raise DisposalError("schema_invalid", "scope.matterId and key.requestId are required")

    ledger = _ledger_root(state_root) / f"{request_id}.json"
    if ledger.exists():
        prior = json.loads(ledger.read_text(encoding="utf-8"))
        if prior.get("authorization_ref_id") != (authorization_ref or {}).get("id"):
            raise DisposalError(
                "verification_failed",
                f"requestId {request_id} already bound to a different authorization",
            )
        # idempotent resume (steps 5+7): finish pending, never redo deleted
        return _process(state_root, matter_id, prior, request_id)

    # step 1+2: authorization chain, versions, policy/reason/decision
    record = _load_authorization(state_root, authorization_ref)
    if record.get("matter_id") != matter_id:
        raise DisposalError("scope_mismatch",
                            "authorization matter does not match requested scope")
    for field in ("policy", "reason", "decision"):
        if not record.get(field):
            raise DisposalError("verification_failed",
                                f"authorization {field} missing (fail closed)")
    public_path = _matter_dir(state_root, matter_id) / "project.public.json"
    if not public_path.exists():
        raise DisposalError("ref_not_found", "matter not initialized")
    public = json.loads(public_path.read_text(encoding="utf-8"))
    archive_ref = record.get("archiveRef") or {}
    if not archive_ref.get("version") or public.get("archive_version") != archive_ref["version"]:
        raise DisposalError("verification_failed",
                            "archive version mismatch or unrecorded (fail closed)")

    objs = _load_objects(state_root, matter_id)
    entries = []
    for target in record.get("targetRefs", []):
        obj = objs.get(str(target.get("id")))
        if obj is None:  # step 3/4: never touch unregistered or external objects
            raise DisposalError("ref_not_found",
                                f"target {target.get('id')} is not a managed object")
        if obj.get("version") != target.get("version"):
            raise DisposalError("verification_failed",
                                f"target {target.get('id')} version mismatch")
        entries.append({"object_id": target["id"], "kind": obj["kind"],
                        "rel_path": obj["rel_path"], "state": "pending"})

    entry = {
        "request_id": request_id,
        "matter_id": matter_id,
        "authorization_ref_id": (authorization_ref or {}).get("id"),
        "authorization_ref_version": (authorization_ref or {}).get("version"),
        "policy": record.get("policy"),
        "reason": record.get("reason"),
        "decision": record.get("decision"),
        "created_at": _now(),
        "objects": entries,
    }
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(json.dumps(entry, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")
    return _process(state_root, matter_id, entry, request_id)


def _process(state_root: Path, matter_id: str, entry: dict, request_id: str) -> dict:
    ledger = _ledger_root(state_root) / f"{request_id}.json"
    for obj in entry["objects"]:
        if obj["state"] != "pending":
            continue
        path = _matter_dir(state_root, matter_id) / obj["rel_path"]
        try:
            if path.is_file():
                path.unlink()  # step 9: logical delete only
            obj["state"] = "deleted"
            obj["at"] = _now()
        except OSError as exc:
            obj["state"] = "failed"
            obj["error"] = str(exc)
        ledger.write_text(json.dumps(entry, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
    return _receipt(entry)


def _receipt(entry: dict) -> dict:
    completed = [{"id": o["object_id"], "kind": o["kind"]}
                 for o in entry["objects"] if o["state"] == "deleted"]
    failed = [{"id": o["object_id"], "kind": o["kind"], "error": o.get("error", "")}
              for o in entry["objects"] if o["state"] != "deleted"]
    return {
        "schema_version": "1.0",
        "request_id": entry["request_id"],
        "matter_id": entry["matter_id"],
        "authorization_ref": {"id": entry["authorization_ref_id"],
                              "version": entry.get("authorization_ref_version")},
        "status": "completed" if not failed else "partial",
        "completedRefs": completed,
        "failedRefs": failed,
        "deletion_mode": ("logical-unlink; no media-level-erasure claim "
                          "(step 9: physical wipe is NOT asserted)"),
        "created_at": entry.get("created_at"),
        "updated_at": _now(),
    }


def read_disposal(state_root, scope, request_id) -> dict:
    state_root = Path(state_root)
    matter_id = str((scope or {}).get("matterId") or "")
    ledger = _ledger_root(state_root) / f"{request_id}.json"
    if not ledger.exists():
        raise DisposalError("ref_not_found", f"no disposal request {request_id}")
    entry = json.loads(ledger.read_text(encoding="utf-8"))
    if entry.get("matter_id") != matter_id:
        raise DisposalError("scope_mismatch", "disposal request belongs to another matter")
    return _receipt(entry)
