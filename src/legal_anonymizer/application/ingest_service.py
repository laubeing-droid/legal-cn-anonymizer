"""Ingest track — bridge-facing source snapshot jobs (W20, card 05 ingest track).

FROZEN contract (jusbench plan-v4.2: methods-core.json + ifc-2/common schemas,
read-only over there):

    ingest.submit   input {sourceRefs: raw-input[], parserProfileRef}
                    output {jobId: Id}
                    errors [unsupported_format, ref_not_found]
    ingest.status   input {jobId: Id}
                    output {state: queued|running|waiting_review|done|error|
                                  cancelled,
                            stage: string, completedUnits: integer,
                            totalUnits: integer|null, resultRefs: Ref[],
                            error: RpcErrorBody|null}
                    errors [ref_not_found]
    ingest.cancel   input {jobId: Id}, output Saved, errors [ref_not_found]
    ingest.resume   input {jobId: Id}, output Saved, errors [ref_not_found]
                    ($comment INGEST.restart_each_stage)

An ingest job takes read-only snapshots (sha256 / size / format) of the
caller-supplied source files into a per-job ledger under
``<state_root>/ingest-jobs/``. File CONTENTS never enter the ledger; the
originals are never copied, moved or modified. Parsing stays in the sanitize
pipelines; this track only establishes the hash-locked snapshot chain.
``queued``/``waiting_review`` are never produced (submit runs synchronously);
a resumed job re-verifies every snapshot and fails closed (hash_mismatch)
when a source drifted. Cancel is idempotent on terminal jobs (Saved).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

from ..security.safe_storage import atomic_write_bytes
from .scan_service import _SUPPORTED

LEDGER_DIR = "ingest-jobs"

# wire ingest.status state enum (ifc-2); queued/waiting_review never occur
_STATE_RUNNING = "running"
_STATE_DONE = "done"
_STATE_ERROR = "error"
_STATE_CANCELLED = "cancelled"


class IngestError(ValueError):
    """Bridge-visible error; ``.code`` stays inside the method's frozen set."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _job_ref(job_id: str) -> dict:
    return {"owner": "anonymizer", "kind": "ingest-job", "id": job_id,
            "version": "1", "matterId": None, "digest": None}


def _scope() -> dict:
    return {"kind": "workspace", "workspaceId": "anonymizer-state-root"}


def _ledger_path(state_root: Path, job_id: str) -> Path:
    return Path(state_root) / LEDGER_DIR / f"{job_id}.json"


def _load_job(state_root: Path, job_id: str) -> dict:
    p = _ledger_path(state_root, job_id)
    if not p.exists():
        raise IngestError("ref_not_found", f"no ingest job {job_id}")
    return json.loads(p.read_text(encoding="utf-8"))


def _save_job(state_root: Path, entry: dict) -> None:
    entry["revision"] = int(entry.get("revision", 0)) + 1
    entry["change_seq"] = int(entry.get("change_seq", 0)) + 1
    entry["updated_at"] = _now()
    p = _ledger_path(state_root, entry["job_id"])
    p.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(
        p,
        json.dumps(entry, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"),
    )


def _resolve_ref(ref) -> str:
    """Normalize one wire sourceRef into a path string. Absolute paths are
    taken as-is; relative paths resolve against the state root at snapshot
    time. Never prints or embeds content."""
    if isinstance(ref, dict):
        ref = ref.get("path") or ref.get("uri") or ref.get("ref")
    if not isinstance(ref, str) or not ref.strip():
        raise IngestError("unsupported_format",
                          "each sourceRef must be a path string "
                          "(or an object with path/uri/ref)")
    return ref


def _snapshot_file(entry_file: dict, state_root: Path) -> None:
    """Snapshot one source file in place (read-only): digest, size, format."""
    path = Path(entry_file["ref"])
    if not path.is_absolute():
        path = Path(state_root) / path
    if not path.exists():
        entry_file.update(state="failed", errorCode="ref_not_found",
                          error="source file missing")
        return
    if not path.is_file():
        entry_file.update(state="failed", errorCode="source_unreadable",
                          error="source is not a regular file")
        return
    try:
        data = path.read_bytes()
    except OSError:
        entry_file.update(state="failed", errorCode="source_unreadable",
                          error="source file could not be read")
        return
    entry_file.update(
        state="snapshotted",
        sha256=hashlib.sha256(data).hexdigest(),
        bytes=len(data),
        format=_SUPPORTED.get(path.suffix.lower(), "unknown"),
        errorCode=None,
        error=None,
    )


def _finalize(entry: dict) -> None:
    files = entry["files"]
    snapshotted = sum(1 for f in files if f["state"] == "snapshotted")
    failed = sum(1 for f in files if f["state"] == "failed")
    if entry["state"] == _STATE_CANCELLED:
        pass
    elif files and failed == 0 and snapshotted == len(files):
        entry["state"] = _STATE_DONE
    elif files:
        entry["state"] = _STATE_ERROR
    else:
        entry["state"] = _STATE_ERROR
    entry["counts"] = {"total": len(files), "snapshotted": snapshotted,
                       "failed": failed}


def _saved(entry: dict) -> dict:
    receipt = {
        "ref": _job_ref(entry["job_id"]),
        "scope": _scope(),
        "inputRefs": [_job_ref(entry["job_id"])],
        "outputRefs": [_job_ref(entry["job_id"])],
        "issuedAt": _now(),
    }
    return {
        "ref": _job_ref(entry["job_id"]),
        "revision": entry.get("revision", 1),
        "changeSeq": entry.get("change_seq", 1),
        "receipt": receipt,
    }


def _error_body(entry: dict) -> dict | None:
    if entry["state"] != _STATE_ERROR:
        return None
    first = next((f for f in entry["files"] if f["state"] == "failed"), None)
    code = (first or {}).get("errorCode") or "ingest_failed"
    detail = "; ".join(
        f"{f['ref']}:{f.get('errorCode')}" for f in entry["files"]
        if f["state"] == "failed")
    return {
        "code": code,
        "retryable": False,
        "requestId": entry["job_id"],
        "stage": f"snapshot failed units: {detail}"[:200],
        "currentRevision": entry.get("revision"),
        "obligations": [],
    }


def ingest_submit(state_root, source_refs, parser_profile_ref=None) -> dict:
    state_root = Path(state_root)
    if not state_root.is_dir():
        raise IngestError("ref_not_found", "state_root does not exist")
    if not isinstance(source_refs, (list, tuple)) or not source_refs:
        raise IngestError("unsupported_format",
                          "sourceRefs must be a non-empty list")
    refs = [_resolve_ref(r) for r in source_refs]
    if parser_profile_ref is not None and not isinstance(parser_profile_ref, (str, dict)):
        raise IngestError("unsupported_format",
                          "parserProfileRef must be a string or object")
    profile_ref = (parser_profile_ref.get("id") or parser_profile_ref.get("path")
                   if isinstance(parser_profile_ref, dict) else parser_profile_ref)

    entry = {
        "job_id": f"ingest-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
                  f"-{secrets.token_hex(2)}",
        "state": _STATE_RUNNING,
        "parser_profile_ref": profile_ref,
        "created_at": _now(),
        "revision": 0,
        "change_seq": 0,
        "files": [{"ref": r, "state": "pending"} for r in refs],
    }
    for f in entry["files"]:
        _snapshot_file(f, state_root)
    _finalize(entry)
    _save_job(state_root, entry)
    return {"jobId": entry["job_id"]}


def ingest_status(state_root, job_id: str) -> dict:
    entry = _load_job(Path(state_root), str(job_id))
    counts = entry.get("counts") or {}
    return {
        "state": entry["state"],
        "stage": "snapshot",
        "completedUnits": int(counts.get("snapshotted", 0)),
        "totalUnits": int(counts.get("total", len(entry["files"]))),
        "resultRefs": [_job_ref(entry["job_id"])],
        "error": _error_body(entry),
    }


def ingest_cancel(state_root, job_id: str) -> dict:
    state_root = Path(state_root)
    entry = _load_job(state_root, str(job_id))
    if entry["state"] not in (_STATE_RUNNING,):
        # idempotent on terminal jobs — the method's only error is ref_not_found
        return _saved(entry)
    entry["state"] = _STATE_CANCELLED  # crash-residue running job
    _finalize(entry)
    _save_job(state_root, entry)
    return _saved(entry)


def ingest_resume(state_root, job_id: str) -> dict:
    state_root = Path(state_root)
    entry = _load_job(state_root, str(job_id))
    if entry["state"] == _STATE_CANCELLED:
        raise IngestError("ref_not_found",
                          f"job {job_id} was cancelled; resume refused")
    for f in entry["files"]:
        if f["state"] in ("failed", "pending"):
            _snapshot_file(f, state_root)
        elif f["state"] == "snapshotted":
            # re-verify: a snapshot that no longer matches its source is a
            # broken snapshot chain — fail closed, never silently re-use
            path = Path(f["ref"])
            if not path.is_absolute():
                path = state_root / path
            current = None
            if path.is_file():
                try:
                    current = hashlib.sha256(path.read_bytes()).hexdigest()
                except OSError:
                    current = None
            if current != f.get("sha256"):
                # keep the original digest on record: it is the snapshot the
                # chain pinned, evidence of what drifted
                f.update(state="failed", errorCode="hash_mismatch",
                         error="snapshot no longer matches source")
    _finalize(entry)
    _save_job(state_root, entry)
    return _saved(entry)
