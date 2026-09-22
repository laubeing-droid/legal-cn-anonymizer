"""Verify service: the independent verification pass (recognizers never grade
themselves). Plan-v4.2 (card 05-2) upgrades the verifier to a HETEROGENEOUS
engine: production detection uses rules + CLUENER transformers NER, the verify
pass re-scans the final sanitized deliverables with a different model family
and mechanism (zero-shot GLiNER). Two instances of the same model are NOT
heterogeneous and are rejected. A missing verifier yields REVIEW_REQUIRED —
never PASS/AUTO_READY. Residuals found by the verifier on delivered content
force privacy=FAIL with the named count ``ner_residual``. Also keeps the
fresh-compiled rule engine, alias residue scan, completeness and the
money/legal-date utility multisets, and issues a signed (v2) receipt."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from ..adapters.recognizers.cn_rules import CnRuleRecognizer
from ..contracts.canonical import canonical_json
from ..contracts.models import SanitizationStatus
from ..security.receipt_identity import ReceiptIdentity
from .state import MatterState

_VERIFIED_ENTITY_TYPES = ("PERSON",)
_VERIFIER_MIN_CONFIDENCE = 0.5


class VerifierHomogeneityError(ValueError):
    error_code = "recognizer_degraded"


def ensure_heterogeneous(detector_stack: list[dict], verifier_stack: list[dict]) -> None:
    """Reject verifier stacks that share model identity (modelId+modelVersion)
    with any production detector — different instances of the same model do not
    count as heterogeneous (card 05-2)."""
    prod_ids = {(d.get("modelId", "").lower(), d.get("modelVersion", "").lower())
                for d in detector_stack}
    for v in verifier_stack:
        if (v.get("modelId", "").lower(), v.get("modelVersion", "").lower()) in prod_ids:
            raise VerifierHomogeneityError(
                "verifier not heterogeneous: model "
                f"{v.get('modelId')}@{v.get('modelVersion')} also in detector stack"
            )


def _now() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class VerifyResult:
    status: str
    gates: dict
    residual_counts: dict
    receipt_path: Path | None = None
    coverage: dict = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        if self.status == SanitizationStatus.CLOSED_BLOCK.value:
            return 3
        if self.gates["utility"] == "REVIEW_REQUIRED":
            return 2
        return 0


class VerifyService:
    def __init__(self, state_root: Path, production_registry=None, verifier=None):
        self.state_root = Path(state_root)
        self._production_registry = production_registry
        self._verifier = verifier

    def verify(self, matter_id: str, out_dir: Path) -> VerifyResult:
        out_dir = Path(out_dir)
        (out_dir / "receipts").mkdir(parents=True, exist_ok=True)
        state = MatterState.load(self.state_root, matter_id)
        private = state.read_private()

        surfaces = [e["canonical_surface"] for e in private.get("entities", [])]
        for e in private.get("entities", []):
            surfaces.extend(e.get("aliases", []))
        surfaces += [i["surface"] for i in private.get("identifier_aliases", [])]
        alias_tokens = {e["display_alias"] for e in private.get("entities", [])}
        alias_tokens |= {i["alias"] for i in private.get("identifier_aliases", [])}

        # Independent engine: a fresh instance of the *rule compiler* on the
        # verifier side, never shared mutable state with the detection pass.
        independent = CnRuleRecognizer()

        # Heterogeneous verifier (card 05-2): production stack = rules +
        # CLUENER transformers NER; verify must re-scan final delivered content
        # with a different model AND mechanism, never a second instance of the
        # same model. Unavailable verifier => REVIEW_REQUIRED, never PASS.
        from ..adapters.recognizers.gliner_ner import CnGlinerVerifier
        from ..adapters.recognizers.registry import RecognizerRegistry

        registry = self._production_registry or RecognizerRegistry()
        detector_stack = registry.detector_stack()
        verifier = (self._verifier if self._verifier is not None
                    else CnGlinerVerifier())
        verifier_ok, verifier_reason = (
            verifier.availability() if hasattr(verifier, "availability")
            else (False, "custom verifier without availability check"))
        verifier_stack = [verifier.stack_descriptor()] if verifier_ok else []
        verifier_error: str | None = None
        if verifier_ok:
            try:
                ensure_heterogeneous(detector_stack, verifier_stack)
            except VerifierHomogeneityError as exc:
                verifier_ok = False
                verifier_reason = str(exc)
                verifier_error = exc.error_code
                verifier_stack = []

        residual_counts = {
            "critical_identifier_residual": 0,
            "surface_residue": 0,
            "ner_residual": 0,
            "money_invariant_failures": 0,
            "legal_date_invariant_failures": 0,
            "documents_unaccounted": 0,
            "output_hash_mismatch": 0,
            "pdf_text_layer_residual": 0,
        }
        privacy = "PASS"
        completeness = "PASS"
        utility = "PASS"
        coverage_reasons: list[str] = []
        delivered_texts: list[str] = []

        public = state.read_public()
        expected_docs = set(public.get("documents", []))
        seen_docs: set[str] = set()
        for sanitized_path in sorted((out_dir / "sanitized").glob("doc-*.ai.md")):
            doc_id = sanitized_path.stem.replace(".ai", "")
            seen_docs.add(doc_id)
            text = sanitized_path.read_text(encoding="utf-8")
            delivered_texts.append(text)
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
                    delivered_texts.append(content)
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
                delivered_texts.append(page.text)
                for det in independent.detect(page.text):
                    if det.severity == "critical":
                        residual_counts["critical_identifier_residual"] += 1
                for surface in surfaces:
                    if surface and surface in page.text:
                        residual_counts["surface_residue"] += 1

        if expected_docs - seen_docs:
            residual_counts["documents_unaccounted"] = len(expected_docs - seen_docs)

        # utility multisets from the original inputs vs sanitized outputs

        from ..domain.utility_snapshot import (
            legal_date_multiset,
            money_multiset,
            multiset_difference,
        )

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

        # Heterogeneous re-scan of the FINAL delivered content: anything the
        # verifier engine flags as a person surface that is neither a known
        # private surface (already counted) nor a released pseudonym is a
        # production miss — residual > 0 forces privacy=FAIL (card 05-2).
        if verifier_ok:
            for text in delivered_texts:
                for det in verifier.detect(text):
                    if det.entity_type not in _VERIFIED_ENTITY_TYPES:
                        continue
                    if det.confidence < _VERIFIER_MIN_CONFIDENCE:
                        continue
                    if det.surface in surfaces:
                        continue
                    if any(det.surface in tok or tok in det.surface
                           for tok in alias_tokens if tok):
                        continue
                    residual_counts["ner_residual"] += 1
        else:
            coverage_reasons.append(f"verifier_unavailable: {verifier_reason}")

        if residual_counts["critical_identifier_residual"] or residual_counts["surface_residue"] \
                or residual_counts["ner_residual"]:
            privacy = "FAIL"
        if residual_counts["documents_unaccounted"]:
            completeness = "FAIL"
        if residual_counts["money_invariant_failures"] or residual_counts["legal_date_invariant_failures"]:
            utility = "FAIL"

        # receipt binding: artifact set must match the signed sanitization
        # receipt exactly — a stale receipt can never bind new artifacts
        receipt_path = out_dir / "receipts" / "sanitization-receipt.json"
        if receipt_path.exists():
            import hashlib as _hl

            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            current: dict[str, str] = {}
            sanitized_dir = out_dir / "sanitized"
            for f in sorted(sanitized_dir.glob("*")):
                if f.is_file():
                    rel = f"sanitized/{f.name}"
                    current[rel] = _hl.sha256(f.read_bytes()).hexdigest()
            if current != receipt.get("artifact_hashes", {}):
                residual_counts["output_hash_mismatch"] = 1

        gates = {
            "privacy": privacy,
            "completeness": completeness,
            "utility": utility,
            "physical_redaction": "NOT_APPLICABLE",
        }
        if residual_counts["output_hash_mismatch"]:
            gates["completeness"] = "FAIL"
        if not verifier_ok and privacy == "PASS":
            # independent heterogeneous verification could not run at all:
            # never PASS/AUTO_READY on an unverified coverage claim
            gates["privacy"] = "REVIEW_REQUIRED"
            privacy = "REVIEW_REQUIRED"
        if not registry.ner_available:
            coverage_reasons.append(
                f"detector_degraded: {registry.status.get('reason')}")
        coverage = {
            "complete": bool(verifier_ok and registry.ner_available
                             and not coverage_reasons),
            "reasons": sorted(coverage_reasons),
        }
        if verifier_error or (
            privacy == "FAIL" or completeness == "FAIL" or utility == "FAIL"
        ):
            status = SanitizationStatus.CLOSED_BLOCK
        elif privacy == "REVIEW_REQUIRED" or not coverage["complete"]:
            status = SanitizationStatus.REVIEW_REQUIRED
        else:
            status = SanitizationStatus.AUTO_READY

        # human review: REVIEW_REQUIRED matters become READY_BY_HUMAN only with
        # a valid signed receipt binding the current artifact set
        if status == SanitizationStatus.AUTO_READY:
            from .review_service import ReviewError, check_review

            try:
                status_value = check_review(
                    self.state_root, matter_id, out_dir,
                    {"status": status.value, **gates},
                )
                status = SanitizationStatus(status_value)
            except ReviewError as exc:
                status = SanitizationStatus.CLOSED_BLOCK
                residual_counts["output_hash_mismatch"] = (
                    residual_counts["output_hash_mismatch"] or 1
                )
                receipt_path_out = out_dir / "receipts" / "privacy-verification-receipt.json"
                receipt_path_out.parent.mkdir(parents=True, exist_ok=True)
                receipt_path_out.write_text(
                    json.dumps({"status": "CLOSED_BLOCK",
                                "reason": str(exc)}, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                return VerifyResult(status=status.value, gates=gates,
                                    residual_counts=residual_counts,
                                    receipt_path=receipt_path_out)

        receipt_body = {
            "schema_version": "2.0",
            "matter_id": matter_id,
            "created_at": _now(),
            "gate_results": gates,
            "verifier_build_digest": "sha256:" + hashlib.sha256(
                canonical_json({"verifier": "heterogeneous-rules+gliner-v2",
                                "detector_stack": detector_stack,
                                "verifier_stack": verifier_stack})
            ).hexdigest(),
            "detector_stack": detector_stack,
            "verifier_stack": verifier_stack,
            "coverage": coverage,
            "residual_counts": residual_counts,
            "invariant_results": {
                "money_multiset_preserved": residual_counts["money_invariant_failures"] == 0,
                "legal_event_date_multiset_preserved": residual_counts["legal_date_invariant_failures"] == 0,
                "document_count_accounted": residual_counts["documents_unaccounted"] == 0,
                "independent_heterogeneous_verification": bool(verifier_ok),
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
            coverage=coverage,
        )
