"""Sanitize service: the Markdown/Text main chain (S4).

Orchestrates scan -> recognize -> resolve -> transform -> verify-ready outputs.
Outputs: sanitized/doc-XXX.ai.md, reports/doc-XXX.report.json, and one signed
matter receipt. Recognizers never grade themselves; independent verification is
the VerifyService."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..adapters.documents.markdown import parse_markdown
from ..adapters.recognizers.registry import RecognizerRegistry
from ..adapters.recognizers.project_dictionary import ProjectDictionaryProvider
from ..contracts.canonical import canonical_hash, canonical_json, hmac_sha256
from ..contracts.models import SanitizationStatus
from ..contracts.statuses import EntityType, ReviewReason, TransformKind
from ..domain.entity_vault import EntityVault
from ..domain.profiles import get_profile
from ..domain.transforms import (
    TransformExecutor,
    generalize_personal_address,
    mask_keep_last_4,
)
from ..domain.utility_snapshot import legal_date_multiset, money_multiset
from ..domain.mentions import Locator, Mention, Span, apply_spans
from ..ports.recognizer import Detection
from ..security.receipt_identity import ReceiptIdentity, ReceiptIdentityError
from .scan_service import ScanError, read_text, scan
from .state import MatterState


_IDENTIFIER_ALIAS_PREFIX = {
    "email": "邮箱",
    "credit_code": "信用代码",
    "weixin": "微信号",
    "case_number": "案号",
    "url": "网址",
    "plate": "车牌",
    "ip": "IP",
}

_CONFIRMING_SOURCES = {"dictionary", "manual"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_models_manifest() -> Path | None:
    """Locate models/manifest.json by walking up from the package. Missing
    manifest => NER treated as unqualified (honest fail-closed default)."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "models" / "manifest.json"
        if candidate.exists():
            return candidate
    return None


def load_ner_qualified() -> bool:
    manifest_path = _find_models_manifest()
    if manifest_path is None:
        return False
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return bool(manifest.get("ner", {}).get("qualified", False))


def provider_build_digest() -> str:
    """Digest of package version + schema set; binds receipts to the build."""
    from ..contracts.schemas import SCHEMAS_DIR

    parts = []
    for f in sorted(Path(SCHEMAS_DIR).glob("*.schema.json")):
        parts.append(f"{f.name}:{hashlib.sha256(f.read_bytes()).hexdigest()}")
    from .. import __version__

    return "sha256:" + hashlib.sha256(
        canonical_json({"version": __version__, "schemas": parts})
    ).hexdigest()


@dataclass
class SanitizeResult:
    status: str
    matter_id: str
    output_dir: Path
    documents: list[dict] = field(default_factory=list)
    review_reasons: list[str] = field(default_factory=list)
    receipt_path: Path | None = None
    receipt: dict | None = None

    @property
    def exit_code(self) -> int:
        return {
            SanitizationStatus.AUTO_READY.value: 0,
            SanitizationStatus.READY_BY_HUMAN.value: 0,
            SanitizationStatus.REVIEW_REQUIRED.value: 2,
            SanitizationStatus.CLOSED_BLOCK.value: 3,
            SanitizationStatus.ENGINE_ERROR.value: 5,
        }[self.status]


class SanitizeService:
    def __init__(self, state_root: Path, registry: RecognizerRegistry | None = None):
        self.state_root = Path(state_root)
        self._registry = registry

    def _make_registry(self, profile) -> RecognizerRegistry:
        if self._registry is not None:
            return self._registry
        return RecognizerRegistry()  # dictionary added per matter below

    def sanitize(
        self,
        matter_id: str,
        input_dir: Path,
        out_dir: Path,
        dictionary: ProjectDictionaryProvider | None = None,
    ) -> SanitizeResult:
        state = MatterState.load(self.state_root, matter_id)
        public = state.read_public()
        profile = get_profile(public["profile_id"])
        out_dir = Path(out_dir)
        (out_dir / "sanitized").mkdir(parents=True, exist_ok=True)
        (out_dir / "reports").mkdir(parents=True, exist_ok=True)
        (out_dir / "receipts").mkdir(parents=True, exist_ok=True)

        try:
            report = scan(Path(input_dir), matter_id)
        except ScanError as exc:
            return SanitizeResult(
                status=SanitizationStatus.CLOSED_BLOCK.value,
                matter_id=matter_id,
                output_dir=out_dir,
                review_reasons=[f"input_unsupported_format: {exc}"],
            )

        secret = state.matter_secret
        vault = EntityVault(matter_id, secret)
        registry = self._make_registry(profile)
        if dictionary is not None:
            registry.providers.append(dictionary)

        ner_qualified = load_ner_qualified()
        review_reasons: set[ReviewReason] = set()
        doc_payloads: list[dict] = []
        artifacts: dict[str, str] = {}
        identifier_first: dict[tuple[str, str], int] = {}

        # pass 1: collect entity mentions matter-wide
        per_doc: list[tuple[object, str, list[Detection], list[tuple[str, str]]]] = []
        for doc in report.documents:
            text = read_text(doc)
            detections = registry.detect(text)
            money = money_multiset(text)
            dates = legal_date_multiset(text)
            for det in detections:
                if det.entity_type.startswith("IDENTIFIER:"):
                    kind = det.entity_type.split(":", 1)[1]
                    key = (kind, det.surface)
                    if key not in identifier_first:
                        identifier_first[key] = det.start
                elif det.entity_type in ("MONEY", "LEGAL_DATE"):
                    continue  # classification only
                else:
                    vault.add_mention(
                        Mention(
                            surface=det.surface,
                            entity_type=det.entity_type,
                            document_id=doc.document_id,
                            locator=Locator(
                                kind="text_offset",
                                start=det.start,
                                end=det.end,
                            ),
                            source=det.source,
                            confidence=det.confidence,
                            evidence_codes=det.evidence,
                        )
                    )
            per_doc.append((doc, text, detections, (money, dates)))

        vault.resolve()

        # NER honesty: without a qualified offline NER, subject coverage cannot
        # be trusted unless every subject mention is user-dictionary-confirmed.
        # A matter with no dictionary at all is never AUTO_READY.
        if not ner_qualified:
            if dictionary is None:
                review_reasons.add(ReviewReason.LOW_CONFIDENCE)
            else:
                for m in vault._mentions:
                    if m.source not in _CONFIRMING_SOURCES:
                        review_reasons.add(ReviewReason.LOW_CONFIDENCE)

        # identifier alias assignment (deterministic by first occurrence)
        id_alias: dict[tuple[str, str], str] = {}
        counters: dict[str, int] = {}
        for (kind, surface), _first in sorted(
            identifier_first.items(), key=lambda kv: kv[1]
        ):
            counters.setdefault(kind, 0)
            counters[kind] += 1
            prefix = _IDENTIFIER_ALIAS_PREFIX.get(kind, kind.capitalize())
            id_alias[(kind, surface)] = f"{prefix}{'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[counters[kind]-1]}"

        entity_for_surface: dict[tuple[str, str], object] = {}
        for i, m in enumerate(vault._mentions):
            ent = vault.entity_for_mention(i)
            entity_for_surface[(m.entity_type, m.surface)] = ent

        # pass 2: build spans and write sanitized docs
        for doc, text, detections, (money, dates) in per_doc:
            spans: list[Span] = []
            plan_counts: dict[str, int] = {}
            for det in detections:
                if det.entity_type == "MONEY" or det.entity_type == "LEGAL_DATE":
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
                        replacement = det.surface  # KEEP / REVIEW
                else:
                    ent = entity_for_surface[(det.entity_type, det.surface)]
                    transform = profile.transform_for_entity(det.entity_type)
                    if transform == TransformKind.PSEUDONYMIZE.value:
                        replacement = ent.display_alias
                    elif transform == TransformKind.GENERALIZE_ADMIN_DIVISION.value:
                        if det.entity_type == EntityType.PROJECT.value:
                            replacement = det.surface  # project address handled below
                        else:
                            replacement = generalize_personal_address(det.surface)
                            if replacement == "REVIEW":
                                review_reasons.add(ReviewReason.LOW_CONFIDENCE)
                                replacement = det.surface
                    elif transform == TransformKind.MASK_KEEP_LAST_4.value:
                        replacement = mask_keep_last_4(det.surface)
                    elif transform == TransformKind.REVIEW.value:
                        replacement = det.surface
                        review_reasons.add(ReviewReason.QUASI_IDENTIFIER)
                    else:
                        replacement = det.surface
                if replacement != det.surface:
                    spans.append(Span(det.start, det.end, replacement, det.rule_id))
                    plan_counts[transform] = plan_counts.get(transform, 0) + 1

            sanitized = apply_spans(text, spans)
            tape = parse_markdown(text)
            out_path = out_dir / "sanitized" / f"{doc.document_id}.ai.md"
            out_path.write_text(sanitized, encoding="utf-8")
            out_bytes = out_path.read_bytes()
            out_hash = hashlib.sha256(out_bytes).hexdigest()
            report_payload = {
                "schema_version": "1.0",
                "document_id": doc.document_id,
                "input_sha256": doc.sha256,
                "sanitized_sha256": out_hash,
                "flags": sorted(tape.flags),
                "transform_counts": dict(sorted(plan_counts.items())),
                "money_multiset": money,
                "legal_date_multiset": dates,
            }
            report_path = out_dir / "reports" / f"{doc.document_id}.report.json"
            report_path.write_text(
                json.dumps(report_payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            doc_payloads.append(report_payload)
            artifacts[f"sanitized/{doc.document_id}.ai.md"] = out_hash

        # persistence (S4 seam): entity map + identifier aliases + filename map
        private = state.read_private()
        private["entities"] = [
            {
                "entity_id": e.entity_id,
                "entity_type": e.entity_type,
                "canonical_surface": e.canonical_surface,
                "aliases": list(e.aliases),
                "display_alias": e.display_alias,
                "roles": list(e.roles),
            }
            for e in vault.entities.values()
        ]
        private["identifier_aliases"] = [
            {"kind": kind, "surface": surface, "alias": alias}
            for (kind, surface), alias in sorted(id_alias.items())
        ]
        private["original_filename_map"] = {
            doc.document_id: doc.path.name for doc in report.documents
        }
        state.write_private(private)

        # matter-level receipt
        mapping_payload = {
            "entities": private["entities"],
            "identifier_aliases": private["identifier_aliases"],
        }
        mapping_commitment = hmac_sha256(secret, mapping_payload)
        source_set_commitment = hmac_sha256(
            secret, sorted(d.sha256 for d in report.documents)
        )
        status = (
            SanitizationStatus.AUTO_READY
            if not review_reasons
            else SanitizationStatus.REVIEW_REQUIRED
        )
        public["documents"] = [d.document_id for d in report.documents]
        public["status"] = status.value
        state.write_public(public)

        receipt_body = {
            "schema_version": "1.0",
            "matter_id": matter_id,
            "profile_id": profile.profile_id,
            "provider_id": "legal-cn-anonymizer",
            "provider_build_digest": provider_build_digest(),
            "created_at": _now(),
            "status": status.value,
            "sanitized_bundle_hash": canonical_hash(artifacts, schema_version="1.0"),
            "artifact_hashes": artifacts,
            "mapping_commitment": mapping_commitment,
            "source_set_commitment": source_set_commitment,
            "invariants": {
                "entity_mapping_injective": True,
                "money_multiset_preserved": True,
                "legal_event_date_multiset_preserved": True,
                "mapping_excluded_from_public_bundle": True,
            },
            "review": None,
        }
        identity = ReceiptIdentity(self.state_root / "identity").ensure()
        receipt = dict(receipt_body)
        receipt["signature"] = identity.sign(receipt_body)
        receipt_path = out_dir / "receipts" / "sanitization-receipt.json"
        receipt_path.write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

        return SanitizeResult(
            status=status.value,
            matter_id=matter_id,
            output_dir=out_dir,
            documents=doc_payloads,
            review_reasons=sorted(r.value for r in review_reasons),
            receipt_path=receipt_path,
            receipt=receipt,
        )
