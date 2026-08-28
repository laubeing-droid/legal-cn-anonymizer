"""Verify service: the independent verification pass (recognizers never grade
themselves). Uses a freshly compiled rule engine on sanitized output, alias
residue scan against the private surfaces, completeness accounting and the
money/legal-date utility multisets. Produces a signed privacy-verification
receipt; critical residuals force CLOSED_BLOCK."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from ..adapters.recognizers.cn_rules import CnRuleRecognizer
from ..contracts.canonical import canonical_hash, canonical_json
from ..contracts.models import SanitizationStatus
from ..security.receipt_identity import ReceiptIdentity
from .state import MatterState


def _now() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class VerifyResult:
    status: str
    gates: dict
    residual_counts: dict
    receipt_path: Path | None = None

    @property
    def exit_code(self) -> int:
        if self.status == SanitizationStatus.CLOSED_BLOCK.value:
            return 3
        if self.gates["utility"] == "REVIEW_REQUIRED":
            return 2
        return 0


class VerifyService:
    def __init__(self, state_root: Path):
        self.state_root = Path(state_root)

    def verify(self, matter_id: str, out_dir: Path) -> VerifyResult:
        out_dir = Path(out_dir)
        (out_dir / "receipts").mkdir(parents=True, exist_ok=True)
        state = MatterState.load(self.state_root, matter_id)
        private = state.read_private()

        surfaces = [e["canonical_surface"] for e in private.get("entities", [])]
        for e in private.get("entities", []):
            surfaces.extend(e.get("aliases", []))
        surfaces += [i["surface"] for i in private.get("identifier_aliases", [])]

        # Independent engine: a fresh instance of the *rule compiler* on the
        # verifier side, never shared mutable state with the detection pass.
        independent = CnRuleRecognizer()

        residual_counts = {
            "critical_identifier_residual": 0,
            "surface_residue": 0,
            "money_invariant_failures": 0,
            "legal_date_invariant_failures": 0,
            "documents_unaccounted": 0,
        }
        privacy = "PASS"
        completeness = "PASS"
        utility = "PASS"

        public = state.read_public()
        expected_docs = set(public.get("documents", []))
        seen_docs: set[str] = set()
        for sanitized_path in sorted((out_dir / "sanitized").glob("doc-*.ai.md")):
            doc_id = sanitized_path.stem.replace(".ai", "")
            seen_docs.add(doc_id)
            text = sanitized_path.read_text(encoding="utf-8")
            for det in independent.detect(text):
                if det.severity == "critical":
                    residual_counts["critical_identifier_residual"] += 1
            for surface in surfaces:
                if surface and surface in text:
                    residual_counts["surface_residue"] += 1

        # DOCX outputs: scan extracted text of every XML part inside the package
        import zipfile as _zf

        from ..adapters.documents.docx.text_extract import extract_part_text

        for docx_path in sorted((out_dir / "sanitized").glob("doc-*.sanitized.docx")):
            seen_docs.add(docx_path.name.replace(".sanitized.docx", ""))
            with _zf.ZipFile(docx_path) as zf:
                for name in zf.namelist():
                    if not name.endswith(".xml"):
                        continue
                    content = extract_part_text(zf.read(name))
                    if not content:
                        continue
                    for det in independent.detect(content):
                        if det.severity == "critical":
                            residual_counts["critical_identifier_residual"] += 1
                    for surface in surfaces:
                        if surface and surface in content:
                            residual_counts["surface_residue"] += 1
        # PDF review outputs: the rebuilt PDF must have no original text layer
        from ..adapters.documents.pdf import pdfium_parser

        for review_pdf in sorted((out_dir / "sanitized").glob("doc-*.review.pdf")):
            seen_docs.add(review_pdf.name.replace(".review.pdf", ""))
            try:
                out_info = pdfium_parser.load_pdf(review_pdf)
            except pdfium_parser.PdfInputError:
                residual_counts["documents_unaccounted"] += 1
                continue
            for page in out_info.pages:
                for det in independent.detect(page.text):
                    if det.severity == "critical":
                        residual_counts["critical_identifier_residual"] += 1
                for surface in surfaces:
                    if surface and surface in page.text:
                        residual_counts["surface_residue"] += 1

        if expected_docs - seen_docs:
            residual_counts["documents_unaccounted"] = len(expected_docs - seen_docs)

        # utility multisets from the original inputs vs sanitized outputs
        from .scan_service import read_text, scan

        from ..domain.utility_snapshot import (
            legal_date_multiset,
            money_multiset,
            multiset_difference,
        )

        scan_dir = out_dir / "input"  # optional: recorded inputs snapshot
        report_dir = out_dir / "reports"
        for report_path in sorted(report_dir.glob("doc-*.report.json")):
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            if not payload.get("money_multiset"):
                continue
            sanitized_path = (
                out_dir / "sanitized" / (payload["document_id"] + ".ai.md")
            )
            if not sanitized_path.exists():
                continue
            stext = sanitized_path.read_text(encoding="utf-8")
            smoney = money_multiset(stext)
            sdates = legal_date_multiset(stext)
            # report multiset recorded at sanitize time from the original
            if multiset_difference(payload["money_multiset"], smoney):
                residual_counts["money_invariant_failures"] += 1
            if multiset_difference(payload["legal_date_multiset"], sdates):
                residual_counts["legal_date_invariant_failures"] += 1

        if residual_counts["critical_identifier_residual"] or residual_counts["surface_residue"]:
            privacy = "FAIL"
        if residual_counts["documents_unaccounted"]:
            completeness = "FAIL"
        if residual_counts["money_invariant_failures"] or residual_counts["legal_date_invariant_failures"]:
            utility = "FAIL"

        gates = {
            "privacy": privacy,
            "completeness": completeness,
            "utility": utility,
            "physical_redaction": "NOT_APPLICABLE",
        }
        status = (
            SanitizationStatus.CLOSED_BLOCK
            if privacy == "FAIL" or completeness == "FAIL" or utility == "FAIL"
            else SanitizationStatus.AUTO_READY
        )

        receipt_body = {
            "schema_version": "1.0",
            "matter_id": matter_id,
            "created_at": _now(),
            "gate_results": gates,
            "verifier_build_digest": "sha256:" + hashlib.sha256(
                canonical_json({"verifier": "independent-rules-v1"})
            ).hexdigest(),
            "residual_counts": residual_counts,
            "invariant_results": {
                "money_multiset_preserved": residual_counts["money_invariant_failures"] == 0,
                "legal_event_date_multiset_preserved": residual_counts["legal_date_invariant_failures"] == 0,
                "document_count_accounted": residual_counts["documents_unaccounted"] == 0,
            },
        }
        identity = ReceiptIdentity(self.state_root / "identity").ensure()
        receipt = dict(receipt_body)
        receipt["signature"] = identity.sign(receipt_body)
        receipt_path = out_dir / "receipts" / "privacy-verification-receipt.json"
        receipt_path.write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        if status == SanitizationStatus.CLOSED_BLOCK:
            public["status"] = status.value
            state.write_public(public)
        return VerifyResult(
            status=status.value,
            gates=gates,
            residual_counts=residual_counts,
            receipt_path=receipt_path,
        )
