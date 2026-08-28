"""Text-PDF sanitization application service (S6).

Text layer -> recognizers -> MSSP -> char-box pixel mapping -> rasterized
review PDF (no original text layer) + AI Markdown. Boxes that cannot be
stably bound to extraction text are REVIEW_REQUIRED/pdf_locator_ambiguous —
never silently skipped."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..adapters.documents.pdf import pdfium_parser
from ..adapters.documents.pdf.raster_redactor import build_review_pdf
from ..adapters.recognizers.registry import RecognizerRegistry
from ..adapters.recognizers.project_dictionary import ProjectDictionaryProvider
from ..contracts.models import SanitizationStatus
from ..contracts.statuses import EntityType, ReviewReason, TransformKind
from ..domain.entity_vault import EntityVault
from ..domain.profiles import get_profile
from ..domain.transforms import mask_keep_last_4
from ..domain.mentions import Locator, Mention
from .sanitize_service import (
    _CONFIRMING_SOURCES,
    _IDENTIFIER_ALIAS_PREFIX,
    load_ner_qualified,
)
from .state import MatterState


def _find_surface_boxes(text: str, surface: str, boxes) -> list[list]:
    """Locate every occurrence of surface in extraction text and union the char
    boxes. Returns [] when the text cannot be stably bound (ambiguous)."""
    results = []
    start = 0
    while True:
        idx = text.find(surface, start)
        if idx < 0:
            break
        end = idx + len(surface)
        # pdfium may inject \r\n or \x00 into extraction text; reject bindings
        # whose char count does not match
        if end > len(boxes) or any(b is None for b in boxes[idx:end]):
            return []
        results.append([list(boxes[i]) for i in range(idx, end)])
        start = end
    return results


class PdfSanitizeService:
    def __init__(self, state_root: Path, registry: RecognizerRegistry | None = None):
        self.state_root = Path(state_root)
        self._registry = registry

    def sanitize_pdf(
        self,
        matter_id: str,
        pdf_path: Path,
        out_dir: Path,
        document_id: str,
        dictionary: ProjectDictionaryProvider | None = None,
        dpi: int = 200,
    ) -> dict:
        state = MatterState.load(self.state_root, matter_id)
        public = state.read_public()
        profile = get_profile(public["profile_id"])
        out_dir = Path(out_dir)
        (out_dir / "sanitized").mkdir(parents=True, exist_ok=True)
        (out_dir / "reports").mkdir(parents=True, exist_ok=True)

        try:
            info = pdfium_parser.load_pdf(pdf_path)
        except pdfium_parser.PdfInputError as exc:
            return {"status": SanitizationStatus.CLOSED_BLOCK.value,
                    "review_reasons": [f"pdf:{exc}"], "artifacts": {}}

        review_reasons: set[ReviewReason] = set()
        if not info.has_text_layer:
            # scanned PDF: S7 owns this path; never claim "nothing sensitive"
            return {"status": SanitizationStatus.REVIEW_REQUIRED.value,
                    "review_reasons": ["no_text_layer:scan_pipeline_required"],
                    "artifacts": {}}

        registry = self._registry or RecognizerRegistry()
        if dictionary is not None:
            registry.providers.append(dictionary)
        secret = state.matter_secret
        vault = EntityVault(matter_id, secret)
        id_first: dict[tuple[str, str], int] = {}

        page_plans: dict[int, list[tuple[str, str, str | None]]] = {}
        md_lines: list[str] = []
        ambiguous = 0
        page_detections: dict[int, list] = {}
        for page in info.pages:
            detections = registry.detect(page.text)
            page_detections[page.page_index] = detections
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
                        locator=Locator(kind="pdf_box", page=page.page_index + 1,
                                        start=det.start, end=det.end),
                        source=det.source,
                        confidence=det.confidence,
                        evidence_codes=det.evidence,
                    )
                )
            for det in detections:
                if det.entity_type in ("MONEY", "LEGAL_DATE"):
                    continue
                boxes_per_occ = _find_surface_boxes(page.text, det.surface, page.char_boxes)
                if not boxes_per_occ and det.surface in page.text:
                    ambiguous += 1
                    review_reasons.add(ReviewReason.LOW_CONFIDENCE)
                    continue
                for occ in boxes_per_occ:
                    pixel_box = pdfium_parser.charboxes_to_pixels(
                        occ, page.height, dpi,
                        int(page.width * dpi / 72), int(page.height * dpi / 72),
                    )
                    page_plans.setdefault(page.page_index, []).append(
                        (pixel_box, det.surface, det.entity_type)
                    )

        vault.resolve()
        if not load_ner_qualified():
            if dictionary is None:
                review_reasons.add(ReviewReason.LOW_CONFIDENCE)
            else:
                for m in vault._mentions:
                    if m.source not in _CONFIRMING_SOURCES:
                        review_reasons.add(ReviewReason.LOW_CONFIDENCE)

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

        # build pixel plan with replacements
        final_boxes: dict[int, list[tuple]] = {}
        for page_no, entries in page_plans.items():
            for pixel_box, surface, entity_type in entries:
                if entity_type.startswith("IDENTIFIER:"):
                    kind = entity_type.split(":", 1)[1]
                    transform = profile.transform_for_identifier(kind)
                    replacement = (
                        mask_keep_last_4(surface)
                        if transform == TransformKind.MASK_KEEP_LAST_4.value
                        else id_alias.get((kind, surface))
                        if transform == TransformKind.PSEUDONYMIZE.value
                        else None
                        if transform == TransformKind.PHYSICAL_REDACT.value
                        else surface
                    )
                else:
                    ent = entity_for_surface[(entity_type, surface)]
                    transform = profile.transform_for_entity(entity_type)
                    if transform == TransformKind.PSEUDONYMIZE.value:
                        replacement = ent.display_alias
                    elif transform == TransformKind.PHYSICAL_REDACT.value:
                        replacement = None
                    else:
                        replacement = surface
                final_boxes.setdefault(page_no, []).append((pixel_box, replacement))

        # markdown: same spans applied to the extraction text, built AFTER
        # resolution so aliases/masks are consistent with the raster PDF
        from ..domain.mentions import Span, apply_spans as apply_text_spans

        md_lines: list[str] = []
        for page in info.pages:
            md_lines.append(f"<!-- page {page.page_index + 1} -->")
            spans = []
            for det in page_detections.get(page.page_index, []):
                if det.entity_type in ("MONEY", "LEGAL_DATE"):
                    continue
                if det.entity_type.startswith("IDENTIFIER:"):
                    kind = det.entity_type.split(":", 1)[1]
                    transform = profile.transform_for_identifier(kind)
                    if transform == TransformKind.MASK_KEEP_LAST_4.value:
                        replacement = mask_keep_last_4(det.surface)
                    elif transform == TransformKind.PSEUDONYMIZE.value:
                        replacement = id_alias[(kind, det.surface)]
                    elif transform == TransformKind.PHYSICAL_REDACT.value:
                        replacement = "█" * len(det.surface)
                    else:
                        replacement = det.surface
                else:
                    ent = entity_for_surface[(det.entity_type, det.surface)]
                    transform = profile.transform_for_entity(det.entity_type)
                    replacement = (
                        ent.display_alias
                        if transform == TransformKind.PSEUDONYMIZE.value
                        else det.surface
                    )
                if replacement != det.surface:
                    spans.append(Span(det.start, det.end, replacement))
            md_lines.extend(
                line for line in apply_text_spans(page.text, spans).splitlines()
                if line.strip()
            )

        out_pdf = out_dir / "sanitized" / f"{document_id}.review.pdf"
        geometry = build_review_pdf(pdf_path, final_boxes, out_pdf, dpi=dpi)
        out_md = out_dir / "sanitized" / f"{document_id}.ai.md"
        md_text = "\n".join(md_lines) + "\n"
        out_md.write_text(md_text, encoding="utf-8")

        report = {
            "schema_version": "1.0",
            "document_id": document_id,
            "page_count": info.page_count,
            "page_sizes": geometry["page_sizes"],
            "dpi": dpi,
            "redaction_boxes": {str(k): len(v) for k, v in sorted(final_boxes.items())},
            "ambiguous_bindings": ambiguous,
            "metadata_cleared": True,
            "sanitized_sha256": hashlib.sha256(out_pdf.read_bytes()).hexdigest(),
        }
        (out_dir / "reports" / f"{document_id}.report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

        # persist entities/identifier aliases
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

        status = (
            SanitizationStatus.AUTO_READY
            if not review_reasons
            else SanitizationStatus.REVIEW_REQUIRED
        )
        return {
            "status": status.value,
            "review_reasons": sorted(r.value for r in review_reasons),
            "artifacts": {
                f"sanitized/{document_id}.review.pdf": report["sanitized_sha256"],
                f"sanitized/{document_id}.ai.md": hashlib.sha256(md_text.encode()).hexdigest(),
            },
            "report": report,
        }
