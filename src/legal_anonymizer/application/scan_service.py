"""Scan service: discover inputs, assign stable doc-xxx ids, snapshot hashes.
Original files are read-only and never copied out of the input directory."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

_SUPPORTED = {
    ".md": "markdown",
    ".markdown": "markdown",
    ".txt": "text",
}


class ScanError(ValueError):
    error_code = "input_unsupported_format"


@dataclass(frozen=True)
class ScannedDocument:
    document_id: str
    path: Path
    format: str
    sha256: str
    size: int


@dataclass(frozen=True)
class ScanReport:
    matter_id: str
    documents: tuple[ScannedDocument, ...]

    def to_payload(self) -> dict:
        return {
            "schema_version": "1.0",
            "matter_id": self.matter_id,
            "documents": [
                {
                    "document_id": d.document_id,
                    "format": d.format,
                    "sha256": d.sha256,
                    "size": d.size,
                    "state": "SNAPSHOTTED",
                }
                for d in self.documents
            ],
        }


def scan(input_dir: Path, matter_id: str) -> ScanReport:
    if not Path(input_dir).is_dir():
        raise ScanError(f"input directory not found: {input_dir}")
    found = []
    unsupported = []
    for p in sorted(Path(input_dir).rglob("*")):
        if p.is_file():
            fmt = _SUPPORTED.get(p.suffix.lower())
            if fmt is None:
                unsupported.append(p.name)
                continue
            data = p.read_bytes()
            found.append((p, fmt, hashlib.sha256(data).hexdigest(), len(data)))
    if unsupported and not found:
        raise ScanError(f"no supported documents; unsupported: {sorted(unsupported)}")
    documents = tuple(
        ScannedDocument(
            document_id=f"doc-{i:03d}",
            path=p,
            format=fmt,
            sha256=digest,
            size=size,
        )
        for i, (p, fmt, digest, size) in enumerate(found, start=1)
    )
    return ScanReport(matter_id=matter_id, documents=documents)


def read_text(doc: ScannedDocument) -> str:
    data = doc.path.read_bytes()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanError(f"{doc.document_id}: not valid UTF-8 (fail closed)") from exc
