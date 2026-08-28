"""DOCX sanitization application service (S5).

Full part inventory, hidden-content policy decisions, cross-run replacement,
metadata cleanup, sanitized DOCX + AI Markdown outputs and a part inventory
that explains every part's disposition. The output ZIP is rescanned
independently by the verify service."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from lxml import etree

from ..adapters.documents.docx.md_convert import docx_tree_to_markdown
from ..adapters.documents.docx.parser import NS, inventory
from ..adapters.documents.docx.sanitizer import (
    DocxPolicyError,
    apply_hidden_policy,
    clear_metadata,
    refresh_tape,
    replace_in_tree,
    write_docx,
)
from ..adapters.recognizers.registry import RecognizerRegistry
from ..adapters.recognizers.project_dictionary import ProjectDictionaryProvider
from ..contracts.canonical import canonical_hash, canonical_json, hmac_sha256
from ..contracts.models import SanitizationStatus
from ..contracts.statuses import EntityType, ReviewReason, TransformKind
from ..domain.entity_vault import EntityVault
from ..domain.profiles import get_profile
from ..domain.transforms import generalize_personal_address, mask_keep_last_4
from ..domain.mentions import Locator, Mention, Span, apply_spans
from .sanitize_service import (
    _IDENTIFIER_ALIAS_PREFIX,
    _CONFIRMING_SOURCES,
    _now,
    load_ner_qualified,
    provider_build_digest,
)
from .state import MatterState
from ..security.receipt_identity import ReceiptIdentity

SIGNAL_TO_PART_PREFIX = {
    "comments": "word/comments.xml",
    "macros": "word/vbaProject.bin",
    "custom_xml": "word/customXml/",
    "embeddings": "word/embeddings/",
    "tracked_changes": "*tree*",
}


@dataclass
class DocxResult:
    status: str
    review_reasons: list[str] = field(default_factory=list)
    parts_inventory: dict = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)


class DocxSanitizeService:
    def __init__(self, state_root: Path, registry: RecognizerRegistry | None = None):
        self.state_root = Path(state_root)
        self._registry = registry

    def sanitize_docx(
        self,
        matter_id: str,
        docx_path: Path,
        out_dir: Path,
        document_id: str,
        decisions: dict | None = None,
        dictionary: ProjectDictionaryProvider | None = None,
    ) -> DocxResult:
        state = MatterState.load(self.state_root, matter_id)
        public = state.read_public()
        profile = get_profile(public["profile_id"])
        out_dir = Path(out_dir)
        (out_dir / "sanitized").mkdir(parents=True, exist_ok=True)
        (out_dir / "reports").mkdir(parents=True, exist_ok=True)
        decisions = decisions or {}

        inv = inventory(docx_path)
        review_reasons: set[ReviewReason] = set()
        dropped_parts: set[str] = set()
        part_disposition: dict[str, str] = {}

        # -- hidden content policy: nothing passes silently -------------------
        for signal in inv.hidden_signals:
            action = decisions.get(signal, "REVIEW")
            if action == "REVIEW":
                review_reasons.add(ReviewReason.HIDDEN_CONTENT)
                continue
            if action == "BLOCK":
                return DocxResult(
                    status=SanitizationStatus.CLOSED_BLOCK.value,
                    review_reasons=[f"hidden_content:{signal}:BLOCK"],
                )
            if action == "DROP_WITH_RECEIPT":
                if signal == "comments":
                    dropped_parts.add("word/comments.xml")
                    part_disposition["word/comments.xml"] = "DROPPED_WITH_RECEIPT"
                elif signal == "custom_xml":
                    dropped_parts.update(
                        p for p in inv.parts if p.startswith("word/customXml/")
                    )
                    part_disposition["word/customXml/*"] = "DROPPED_WITH_RECEIPT"
                elif signal == "embeddings":
                    dropped_parts.update(
                        p for p in inv.parts if p.startswith("word/embeddings/")
                    )
                    part_disposition["word/embeddings/*"] = "DROPPED_WITH_RECEIPT"
            # KEEP_AND_SANITIZE / FLATTEN_CURRENT_VIEW handled below per part

        registry = self._registry or RecognizerRegistry()
        if dictionary is not None:
            registry.providers.append(dictionary)

        secret = state.matter_secret
        vault = EntityVault(matter_id, secret)
        id_first: dict[tuple[str, str], int] = {}
        per_part: list[tuple[object, str]] = []

        for part in inv.text_parts:
            tape = inv.part_tapes[part]
            if part in dropped_parts or not tape.logical_text:
                continue
            action_comments = decisions.get("comments", "REVIEW")
            if part == "word/comments.xml" and action_comments == "FLATTEN_CURRENT_VIEW":
                continue  # part will be dropped below
            if part == "word/comments.xml" and action_comments == "KEEP_AND_SANITIZE":
                apply_hidden_policy(tape, "KEEP_AND_SANITIZE")
            if "tracked_changes" in inv.hidden_signals and decisions.get(
                "tracked_changes", "REVIEW"
            ) == "FLATTEN_CURRENT_VIEW":
                apply_hidden_policy(tape, "FLATTEN_CURRENT_VIEW")
                tape = refresh_tape(tape)
            detections = registry.detect(tape.logical_text)
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
                        locator=Locator(kind="docx_xml", part=part,
                                        start=det.start, end=det.end),
                        source=det.source,
                        confidence=det.confidence,
                        evidence_codes=det.evidence,
                    )
                )
            per_part.append((tape, part))

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
        for (kind, surface), _first in sorted(id_first.items(), key=lambda kv: kv[1]):
            counters.setdefault(kind, 0)
            counters[kind] += 1
            prefix = _IDENTIFIER_ALIAS_PREFIX.get(kind, kind.capitalize())
            id_alias[(kind, surface)] = (
                f"{prefix}{'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[counters[kind]-1]}"
            )

        entity_for_surface = {
            (m.entity_type, m.surface): vault.entity_for_mention(i)
            for i, m in enumerate(vault._mentions)
        }

        # -- build spans per part and apply -------------------------------------
        modified: dict[str, bytes] = {}
        markdown_parts: list[str] = []
        plan_counts: dict[str, int] = {}
        for tape, part in per_part:
            spans = []
            fresh = refresh_tape(tape)
            for det in registry.detect(fresh.logical_text):
                if det.entity_type in ("MONEY", "LEGAL_DATE"):
                    continue
                if det.entity_type.startswith("IDENTIFIER:"):
                    kind = det.entity_type.split(":", 1)[1]
                    transform = profile.transform_for_identifier(kind)
                    if transform == TransformKind.MASK_KEEP_LAST_4.value:
                        replacement = mask_keep_last_4(det.surface)
                    elif transform == TransformKind.PSEUDONYMIZE.value:
                        replacement = id_alias[(kind, det.surface)]
                    else:
                        replacement = det.surface
                else:
                    ent = entity_for_surface[(det.entity_type, det.surface)]
                    transform = profile.transform_for_entity(det.entity_type)
                    if transform == TransformKind.PSEUDONYMIZE.value:
                        replacement = ent.display_alias
                    elif transform == TransformKind.GENERALIZE_ADMIN_DIVISION.value:
                        replacement = generalize_personal_address(det.surface)
                        if replacement == "REVIEW":
                            review_reasons.add(ReviewReason.LOW_CONFIDENCE)
                            replacement = det.surface
                    else:
                        replacement = det.surface
                if replacement != det.surface:
                    spans.append((det.start, det.end, replacement, transform))
                    plan_counts[transform] = plan_counts.get(transform, 0) + 1
            for start, end, replacement, _kind in sorted(spans, key=lambda s: s[0], reverse=True):
                replace_in_tree(fresh, start, end, replacement)
            xml_bytes = etree.tostring(
                fresh.tree, xml_declaration=True, encoding="UTF-8", standalone=True
            )
            modified[part] = xml_bytes
            if part == "word/document.xml":
                markdown_parts.append(docx_tree_to_markdown(fresh.tree))

        # comments FLATTEN drops the part entirely
        if "comments" in [s for s in inv.hidden_signals] and decisions.get(
            "comments"
        ) == "FLATTEN_CURRENT_VIEW":
            dropped_parts.add("word/comments.xml")
            part_disposition["word/comments.xml"] = "FLATTENED"

        # metadata cleanup
        src_zip = docx_path
        import zipfile as _zf

        with _zf.ZipFile(src_zip) as zin:
            for meta in ("docProps/core.xml", "docProps/app.xml"):
                if meta in zin.namelist():
                    modified[meta] = clear_metadata(zin.read(meta))
                    part_disposition[meta] = "METADATA_CLEANED"

        out_docx = out_dir / "sanitized" / f"{document_id}.sanitized.docx"
        write_docx(docx_path, out_docx, modified, dropped_parts)
        out_md_path = out_dir / "sanitized" / f"{document_id}.ai.md"
        out_md_path.write_text(
            "\n".join(p for p in markdown_parts), encoding="utf-8"
        )

        out_hash = hashlib.sha256(out_docx.read_bytes()).hexdigest()
        md_hash = hashlib.sha256(out_md_path.read_bytes()).hexdigest()
        report_payload = {
            "schema_version": "1.0",
            "document_id": document_id,
            "input_sha256": hashlib.sha256(docx_path.read_bytes()).hexdigest(),
            "sanitized_sha256": out_hash,
            "markdown_sha256": md_hash,
            "hidden_signals": inv.hidden_signals,
            "external_links": inv.external_links,
            "transform_counts": dict(sorted(plan_counts.items())),
            "part_disposition": part_disposition,
            "part_inventory": {
                "total_parts": len(inv.parts),
                "text_parts": inv.text_parts,
                "dropped": sorted(dropped_parts),
                "modified": sorted(modified.keys()),
                "unmodified": sorted(
                    set(inv.parts) - set(modified.keys()) - dropped_parts
                ),
            },
        }
        (out_dir / "reports" / f"{document_id}.report.json").write_text(
            json.dumps(report_payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

        # persist entity + identifier aliases into matter private state
        private = state.read_private()
        existing = {e["entity_id"] for e in private.get("entities", [])}
        for e in vault.entities.values():
            if e.entity_id not in existing:
                private["entities"].append(
                    {
                        "entity_id": e.entity_id,
                        "entity_type": e.entity_type,
                        "canonical_surface": e.canonical_surface,
                        "aliases": list(e.aliases),
                        "display_alias": e.display_alias,
                        "roles": list(e.roles),
                    }
                )
        existing_aliases = {
            (i["kind"], i["surface"]) for i in private.get("identifier_aliases", [])
        }
        for (kind, surface), alias in id_alias.items():
            if (kind, surface) not in existing_aliases:
                private["identifier_aliases"].append(
                    {"kind": kind, "surface": surface, "alias": alias}
                )
        private["original_filename_map"][document_id] = docx_path.name
        state.write_private(private)

        status = (
            SanitizationStatus.AUTO_READY
            if not review_reasons
            else SanitizationStatus.REVIEW_REQUIRED
        )
        if public["documents"] is not None and document_id not in public["documents"]:
            public["documents"].append(document_id)
            state.write_public(public)

        return DocxResult(
            status=status.value,
            review_reasons=sorted(r.value for r in review_reasons),
            parts_inventory=report_payload["part_inventory"],
            artifacts={
                f"sanitized/{document_id}.sanitized.docx": out_hash,
                f"sanitized/{document_id}.ai.md": md_hash,
            },
        )
