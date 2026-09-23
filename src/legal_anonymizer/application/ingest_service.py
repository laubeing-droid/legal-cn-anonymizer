"""Ingest track — bridge-facing source snapshot jobs (card 05 ingest track).

Bridge contract (jusbench_bridge/providers.py, read-only over there):

    ingest_submit(state_root, source_refs, parser_profile_ref) -> job view
    ingest_status(state_root, job_id) / ingest_cancel(...) / ingest_resume(...)

An ingest job takes read-only snapshots (sha256 / size / format) of
caller-supplied source files into a per-job ledger under
``<state_root>/ingest-jobs/``. File CONTENTS never enter the ledger — only
refs, digests, sizes and format labels; originals are never copied, moved or
modified. Parsing itself stays in the sanitize pipelines; this track only
establishes the hash-locked snapshot chain the pipelines consume.

All failures are typed ``.code`` errors (schema_invalid / ref_not_found /
conflict / source_unreadable / hash_mismatch). A snapshot that no longer
matches the original on resume fails closed (hash_mismatch), never a silent
pass. Job ids are random; ledger writes are atomic.
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

_TERMINAL = ("completed", "partial", "failed", "cancelled")


class IngestError(ValueError):
    """Bridge-visible error; ``.code`` is a plain string code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ledger_path(state_root: Path, job_id: str) -> Path:
    return Path(state_root) / LEDGER_DIR / f"{job_id}.json"


def _load_job(state_root: Path, job_id: str) -> dict:
    p = _ledger_path(state_root, job_id)
    if not p.exists():
        raise IngestError("ref_not_found", f"no ingest job {job_id}")
    return json.loads(p.read_text(encoding="utf-8"))


def _save_job(state_root: Path, entry: dict) -> None:
    p = _ledger_path(state_root, entry["job_id"])
    p.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(
        p,
        json.dumps(entry, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"),
    )


def _resolve_ref(ref) -> str:
    """Normalize one wire sourceRef into a path string. Absolute paths are
    taken as-is; relative paths resolve against the state root at snapshot
    time (stable across bridge workers). Never prints or embeds content."""
    if isinstance(ref, dict):
        ref = ref.get("path") or ref.get("uri") or ref.get("ref")
    if not isinstance(ref, str) or not ref.strip():
        raise IngestError("schema_invalid", "each sourceRef must be a path string "
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


def _job_view(entry: dict) -> dict:
    files = entry["files"]
    snapshotted = sum(1 for f in files if f["state"] == "snapshotted")
    failed = sum(1 for f in files if f["state"] == "failed")
    if entry["state"] in ("cancelled",):
        state = entry["state"]
    elif not files:
        state = "failed"
    elif failed == 0 and snapshotted == len(files):
        state = "completed"
    elif snapshotted == 0:
        state = "failed"
    else:
        state = "partial"
    entry["state"] = state
    entry["counts"] = {"total": len(files), "snapshotted": snapshotted,
                       "failed": failed}
    entry["updatedAt"] = _now()
    return {
        "jobId": entry["job_id"],
        "state": entry["state"],
        "parserProfileRef": entry.get("parser_profile_ref"),
        "createdAt": entry["created_at"],
        "updatedAt": entry["updatedAt"],
        "counts": entry["counts"],
        "files": [
            {k: f.get(k) for k in
             ("ref", "state", "sha256", "bytes", "format", "errorCode", "error")}
            for f in files
        ],
    }


def ingest_submit(state_root, source_refs, parser_profile_ref=None) -> dict:
    state_root = Path(state_root)
    if not state_root.is_dir():
        raise IngestError("schema_invalid", "state_root does not exist")
    if not isinstance(source_refs, (list, tuple)) or not source_refs:
        raise IngestError("schema_invalid", "sourceRefs must be a non-empty list")
    refs = [_resolve_ref(r) for r in source_refs]
    if parser_profile_ref is not None and not isinstance(parser_profile_ref, (str, dict)):
        raise IngestError("schema_invalid", "parserProfileRef must be a string or object")
    profile_ref = (parser_profile_ref.get("id") or parser_profile_ref.get("path")
                   if isinstance(parser_profile_ref, dict) else parser_profile_ref)

    entry = {
        "job_id": f"ingest-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
                  f"-{secrets.token_hex(2)}",
        "state": "running",
        "parser_profile_ref": profile_ref,
        "created_at": _now(),
        "files": [{"ref": str(r), "state": "pending"} for r in refs],
    }
    for f in entry["files"]:
        _snapshot_file(f, state_root)
    view = _job_view(entry)
    _save_job(state_root, entry)
    return view


def ingest_status(state_root, job_id: str) -> dict:
    entry = _load_job(Path(state_root), str(job_id))
    return _job_view(entry)


def ingest_cancel(state_root, job_id: str) -> dict:
    state_root = Path(state_root)
    entry = _load_job(state_root, str(job_id))
    if entry["state"] in _TERMINAL:
        raise IngestError("conflict",
                          f"job {job_id} is already in terminal state {entry['state']}")
    # only a crash-residue running job is cancellable; snapshotted files keep
    # their digests, the rest are abandoned
    entry["state"] = "cancelled"
    view = _job_view(entry)
    _save_job(state_root, entry)
    return view


def ingest_resume(state_root, job_id: str) -> dict:
    state_root = Path(state_root)
    entry = _load_job(state_root, str(job_id))
    if entry["state"] == "cancelled":
        raise IngestError("conflict", f"job {job_id} was cancelled; resume refused")
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
    view = _job_view(entry)
    _save_job(state_root, entry)
    return view
