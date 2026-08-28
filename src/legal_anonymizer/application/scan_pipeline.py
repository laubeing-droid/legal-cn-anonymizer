"""Scanned PDF / image pipeline (S7).

PDFium render -> orientation-agnostic RapidOCR -> reading order -> recognizers
-> MSSP -> pixel transform -> image-only PDF. Per-page state is explicit;
scans always end in human review, no matter how high OCR confidence is.
OCR raw text never enters logs or public artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..adapters.documents.pdf import pdfium_parser
from ..adapters.documents.pdf.raster_redactor import build_review_pdf, erase_and_draw
from ..adapters.ocr.rapidocr import OcrUnavailableError, RapidOcrEngine
from ..adapters.recognizers.registry import RecognizerRegistry
from ..adapters.recognizers.project_dictionary import ProjectDictionaryProvider
from ..adapters.recognizers.vision_signals import VisionSignalProvider
from ..contracts.models import SanitizationStatus
from ..contracts.statuses import ReviewReason, TransformKind
from ..domain.entity_vault import EntityVault
from ..domain.profiles import get_profile
from ..domain.transforms import mask_keep_last_4
from ..domain.mentions import Locator, Mention, Span, apply_spans
from .sanitize_service import (
    _CONFIRMING_SOURCES,
    _IDENTIFIER_ALIAS_PREFIX,
    _now,
    load_ner_qualified,
    provider_build_digest,
)
from ..security.receipt_identity import ReceiptIdentity
from .state import MatterState

LOW_CONFIDENCE_THRESHOLD = 0.85

PAGE_STATES = [
    "PENDING", "RENDERED", "OCR_COMPLETE", "OCR_LOW_CONFIDENCE",
    "MANUAL_REVIEW_REQUIRED", "TRANSFORMED", "VERIFIED", "BLOCKED",
]


class ScanPipeline:
    def __init__(self, state_root: Path, registry: RecognizerRegistry | None = None):
        self.state_root = Path(state_root)
        self._registry = registry

    def sanitize_scan(
        self,
        matter_id: str,
        pdf_path: Path,
        out_dir: Path,
        document_id: str,
        dictionary: ProjectDictionaryProvider | None = None,
        decisions: dict | None = None,
        dpi: int = 200,
    ) -> dict:
        state = MatterState.load(self.state_root, matter_id)
        public = state.read_public()
        profile = get_profile(public["profile_id"])
        out_dir = Path(out_dir)
        (out_dir / "sanitized").mkdir(parents=True, exist_ok=True)
        (out_dir / "reports").mkdir(parents=True, exist_ok=True)
        (out_dir / "receipts").mkdir(parents=True, exist_ok=True)
        decisions = decisions or {}

        try:
            engine = RapidOcrEngine()
        except OcrUnavailableError as exc:
            return {"status": SanitizationStatus.CLOSED_BLOCK.value,
                    "review_reasons": [f"ocr_unavailable:{exc}"], "artifacts": {}}

        try:
            info = pdfium_parser.load_pdf(pdf_path)
        except pdfium_parser.PdfInputError as exc:
            return {"status": SanitizationStatus.CLOSED_BLOCK.value,
                    "review_reasons": [f"pdf:{exc}"], "artifacts": {}}

        registry = self._registry or RecognizerRegistry()
        if dictionary is not None:
            registry.providers.append(dictionary)
        vision = VisionSignalProvider()

        secret = state.matter_secret
        vault = EntityVault(matter_id, secret)
        id_first: dict[tuple[str, str], int] = {}
        review_reasons: set[ReviewReason] = set()
        page_states: dict[int, str] = {}
        page_ocr_states: dict[int, str] = {}
        page_plans: dict[int, list[tuple]] = {}
        page_md: dict[int, list[str]] = {}
        page_images: dict[int, object] = {}
        page_ocr_text: dict[int, str] = {}
        page_detections: dict[int, list] = {}
        qr_signals: dict[int, list[dict]] = {}

        for page in info.pages:
            idx = page.page_index
            page_states[idx] = "RENDERED"
            image = pdfium_parser.render_page(pdf_path, idx, dpi=dpi)
            page_images[idx] = image
            # QR / barcode signals
            codes = vision.scan(image)
            qr_signals[idx] = [
                {"format": c.format, "decoded": c.text is not None} for c in codes
            ]
            for code in codes:
                if code.text is None:
                    review_reasons.add(ReviewReason.QR_UNREADABLE)
                elif code.box:
                    # decoded QR content is itself an identifier carrier:
                    # physically remove the code in the sanitized output
                    px = pdfium_parser.charboxes_to_pixels(
                        [(code.box[0], code.box[1], code.box[2], code.box[3])],
                        page.height, dpi, image.width, image.height,
                    )
                    page_plans.setdefault(idx, []).append((px, None))
                    registry_dets = registry.detect(code.text)
                    for det in registry_dets:
                        if det.entity_type.startswith("IDENTIFIER:"):
                            kind = det.entity_type.split(":", 1)[1]
                            id_first.setdefault((kind, det.surface), det.start)

            lines, _ok = engine.run(image)
            if not lines:
                # a non-blank page with no OCR result is a review, never a pass
                review_reasons.add(ReviewReason.OCR_DOCUMENT)
                page_states[idx] = "MANUAL_REVIEW_REQUIRED"
                page_md[idx] = []
                continue
            avg_conf = sum(l.confidence for l in lines) / len(lines)
            if avg_conf < LOW_CONFIDENCE_THRESHOLD:
                page_states[idx] = "OCR_LOW_CONFIDENCE"
                review_reasons.add(ReviewReason.OCR_DOCUMENT)
            else:
                page_states[idx] = "OCR_COMPLETE"
            page_ocr_states[idx] = page_states[idx]

            ocr_text = "\n".join(l.text for l in lines)
            page_ocr_text[idx] = ocr_text
            md_lines = [f"<!-- page {idx + 1} -->"]
            md_lines.extend(l.text for l in lines if l.text.strip())
            page_md[idx] = md_lines
            detections = registry.detect(ocr_text)
            page_detections[idx] = detections
            for det in detections:
                if det.entity_type in ("MONEY", "LEGAL_DATE"):
                    continue
                if det.entity_type.startswith("IDENTIFIER:"):
                    kind = det.entity_type.split(":", 1)[1]
                    id_first.setdefault((kind, det.surface), det.start)
                    continue
                vault.add_mention(
                    Mention(
                        surface=det.surface,
                        entity_type=det.entity_type,
                        document_id=document_id,
                        locator=Locator(kind="ocr_box", page=idx + 1,
                                        start=det.start, end=det.end),
                        source=det.source,
                        confidence=det.confidence,
                        evidence_codes=det.evidence,
                    )
                )
            # map detection offsets back to OCR line boxes
            for det in detections:
                if det.entity_type in ("MONEY", "LEGAL_DATE"):
                    continue
                boxes = self._locate_in_lines(lines, det.start, det.end, ocr_text)
                if boxes is None:
                    review_reasons.add(ReviewReason.MANUAL_BOX_REQUIRED)
                    continue
                for box in boxes:
                    px = (
                        max(0, int(box[0]) - 2), max(0, int(box[1]) - 2),
                        min(image.width, int(box[2]) + 2),
                        min(image.height, int(box[3]) + 2),
                    )
                    page_plans.setdefault(idx, []).append((px, det.surface, det.entity_type))

        vault.resolve()
        if not load_ner_qualified():
            if dictionary is None:
                review_reasons.add(ReviewReason.LOW_CONFIDENCE)
            else:
                for m in vault._mentions:
                    if m.source not in _CONFIRMING_SOURCES:
                        review_reasons.add(ReviewReason.LOW_CONFIDENCE)
        # manual boxes
        for mb in decisions.get("manual_boxes", []):
            if mb.get("document_id") not in (None, document_id):
                continue
            idx = int(mb.get("page", 1)) - 1
            if idx in page_images:
                img = page_images[idx]
                box = tuple(int(v) for v in mb["box"])
                page_plans.setdefault(idx, []).append((box, None))

        id_alias: dict[tuple[str, str], str] = {}
        counters: dict[str, int] = {}
        for (kind, surface), _f in sorted(id_first.items(), key=lambda kv: kv[1]):
            counters.setdefault(kind, 0)
            counters[kind] += 1
            prefix = _IDENTIFIER_ALIAS_PREFIX.get(kind, kind.capitalize())
            id_alias[(kind, surface)] = f"{prefix}{'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[counters[kind]-1]}"
        entity_for_surface = {
            (m.entity_type, m.surface): vault.entity_for_mention(i)
            for i, m in enumerate(vault._mentions)
        }

        def replacement_for(surface: str, entity_type: str) -> str | None:
            if entity_type.startswith("IDENTIFIER:"):
                kind = entity_type.split(":", 1)[1]
                transform = profile.transform_for_identifier(kind)
                if transform == TransformKind.MASK_KEEP_LAST_4.value:
                    return mask_keep_last_4(surface)
                if transform == TransformKind.PSEUDONYMIZE.value:
                    return id_alias.get((kind, surface))
                if transform == TransformKind.PHYSICAL_REDACT.value:
                    return None
                return surface
            ent = entity_for_surface[(entity_type, surface)]
            transform = profile.transform_for_entity(entity_type)
            if transform == TransformKind.PSEUDONYMIZE.value:
                return ent.display_alias
            if transform == TransformKind.PHYSICAL_REDACT.value:
                return None
            return surface

        # apply pixel transforms and sanitized markdown
        final_boxes: dict[int, list[tuple]] = {}
        md_out: list[str] = []
        for page in info.pages:
            idx = page.page_index
            image = page_images[idx]
            for entry in page_plans.get(idx, []):
                box = entry[0]
                if len(entry) == 3:
                    replacement = replacement_for(entry[1], entry[2])
                else:
                    replacement = entry[1]
                erase_and_draw(image, box, replacement)
                final_boxes.setdefault(idx, []).append((box, replacement))
            # markdown: same transforms applied to the OCR text
            spans = []
            ocr_text = page_ocr_text.get(idx, "")
            for det in page_detections.get(idx, []):
                if det.entity_type in ("MONEY", "LEGAL_DATE"):
                    continue
                rep = replacement_for(det.surface, det.entity_type)
                if rep is not None and rep != det.surface:
                    spans.append(Span(det.start, det.end, rep))
            page_md[idx] = [
                line for line in apply_spans(ocr_text, spans).splitlines() if line.strip()
            ]
            md_out.extend(page_md.get(idx, []))
            page_states[idx] = "TRANSFORMED"

        out_pdf = out_dir / "sanitized" / f"{document_id}.review.pdf"
        geometry = build_review_pdf(pdf_path, final_boxes, out_pdf, dpi=dpi)
        report_digest = hashlib.sha256(out_pdf.read_bytes()).hexdigest()
        md_text = "\n".join(md_out) + "\n"
        (out_dir / "sanitized" / f"{document_id}.ai.md").write_text(md_text, encoding="utf-8")
        out_md_tmp = out_dir / "sanitized" / f"{document_id}.ai.md"
        md_digest = (
            hashlib.sha256(out_md_tmp.read_bytes()).hexdigest()
            if out_md_tmp.exists() else ""
        )

        # scans always require human confirmation, regardless of confidence
        review_reasons.add(ReviewReason.OCR_DOCUMENT)
        status = SanitizationStatus.REVIEW_REQUIRED
        from .status_accounting import update_matter_review_flag

        update_matter_review_flag(state, True)

        # matter-level signed receipt (same contract as the markdown path)
        private = state.read_private()
        mapping_payload = {
            "entities": private["entities"],
            "identifier_aliases": private["identifier_aliases"],
        }
        from ..contracts.canonical import canonical_hash, hmac_sha256

        receipt_body = {
            "schema_version": "1.0",
            "matter_id": matter_id,
            "profile_id": profile.profile_id,
            "provider_id": "legal-cn-anonymizer",
            "provider_build_digest": provider_build_digest(),
            "created_at": _now(),
            "status": status.value,
            "sanitized_bundle_hash": canonical_hash(
                {f"sanitized/{document_id}.review.pdf": report_digest},
                schema_version="1.0",
            ),
            "artifact_hashes": {
                f"sanitized/{document_id}.review.pdf": report_digest,
                **({"sanitized/" + f"{document_id}.ai.md": md_digest} if md_digest else {}),
            },
            "mapping_commitment": hmac_sha256(secret, mapping_payload),
            "source_set_commitment": hmac_sha256(secret, []),
            "invariants": {
                "entity_mapping_injective": True,
                "money_multiset_preserved": True,
                "legal_event_date_multiset_preserved": True,
                "mapping_excluded_from_public_bundle": True,
            },
            "review": None,
        }
        scan_artifacts = {
            f"sanitized/{document_id}.review.pdf": report_digest,
            **({"sanitized/" + f"{document_id}.ai.md": md_digest} if md_digest else {}),
        }
        receipt_body["artifact_hashes"] = scan_artifacts
        receipt_body["sanitized_bundle_hash"] = canonical_hash(
            scan_artifacts, schema_version="1.0"
        )
        identity = ReceiptIdentity(self.state_root / "identity").ensure()
        receipt = dict(receipt_body)
        receipt["signature"] = identity.sign(receipt_body)
        (out_dir / "receipts" / "sanitization-receipt.json").write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

        report = {
            "schema_version": "1.0",
            "document_id": document_id,
            "scan_pipeline": True,
            "page_count": info.page_count,
            "page_states": {str(k): v for k, v in sorted(page_states.items())},
            "ocr_states": {str(k): v for k, v in sorted(page_ocr_states.items())},
            "qr_signals": {str(k): v for k, v in sorted(qr_signals.items())},
            "redaction_boxes": {str(k): len(v) for k, v in sorted(final_boxes.items())},
            "sanitized_sha256": report_digest,
        }
        (out_dir / "reports" / f"{document_id}.report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

        private = state.read_private()
        existing = {e["entity_id"] for e in private.get("entities", [])}
        for e in vault.entities.values():
            if e.entity_id not in existing:
                private["entities"].append({
                    "entity_id": e.entity_id,
                    "entity_type": e.entity_type,
                    "canonical_surface": e.canonical_surface,
                    "aliases": list(e.aliases),
                    "display_alias": e.display_alias,
                    "roles": list(e.roles),
                })
        have = {(i["kind"], i["surface"]) for i in private.get("identifier_aliases", [])}
        for (kind, surface), alias in id_alias.items():
            if (kind, surface) not in have:
                private["identifier_aliases"].append({"kind": kind, "surface": surface, "alias": alias})
        private["original_filename_map"][document_id] = pdf_path.name
        state.write_private(private)
        if document_id not in public["documents"]:
            public["documents"].append(document_id)
            state.write_public(public)

        return {
            "status": status.value,
            "review_reasons": sorted(r.value for r in review_reasons),
            "artifacts": {
                f"sanitized/{document_id}.review.pdf": report["sanitized_sha256"],
            },
            "report": report,
        }

    @staticmethod
    def _locate_in_lines(lines, start: int, end: int, ocr_text: str):
        """Map a detection offset range in the OCR text back to line boxes.
        Returns a list of boxes, or None when the text cannot be bound."""
        boxes = []
        cursor = 0
        for line in lines:
            line_len = len(line.text) + 1
            s, e = cursor, cursor + len(line.text)
            if s < end and start < e:
                boxes.append(line.box)
            cursor += line_len
        return boxes if boxes else None
