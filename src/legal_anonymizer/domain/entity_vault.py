"""MSSP entity vault: matter-scoped entity resolution, deterministic ID
assignment and display alias rendering.

ID assignment is independent of detector return order: entities are numbered by
(entity_type, first document stable id, page/offset, surface HMAC) ordering.
Display aliases are separate from internal IDs (法人A / 自然人A / ...); roles are
kept per entity, never baked into the ID. X/Y/Z are reserved for formal rule
variables and are never machine entity IDs."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from ..contracts.statuses import EntityType, ReviewReason
from .entities import Entity
from .equivalence import ConstraintUnionFind
from .mentions import Mention
from .normalization import (
    normalize_id,
    normalize_org_surface,
    normalize_person_surface,
    normalize_phone,
    surfaces_match_ocr,
)

_TYPE_SLUG = {
    EntityType.PERSON.value: "person",
    EntityType.LEGAL_PERSON.value: "legal-person",
    EntityType.UNINCORPORATED_ORG.value: "unincorporated-org",
    EntityType.PUBLIC_AUTHORITY.value: "public-authority",
    EntityType.COURT.value: "court",
    EntityType.LAW_FIRM.value: "law-firm",
    EntityType.PROJECT_DEPARTMENT.value: "project-department",
    EntityType.PROJECT.value: "project",
    EntityType.LOCATION.value: "location",
    EntityType.ACCOUNT.value: "account",
    EntityType.DOCUMENT.value: "document",
    EntityType.OTHER_PROTECTED.value: "other-protected",
}

_ALIAS_PREFIX = {
    EntityType.PERSON.value: "自然人",
    EntityType.LEGAL_PERSON.value: "法人",
    EntityType.UNINCORPORATED_ORG.value: "非法人组织",
    EntityType.PUBLIC_AUTHORITY.value: "机关",
    EntityType.COURT.value: "法院",
    EntityType.LAW_FIRM.value: "律师事务所",
    EntityType.PROJECT_DEPARTMENT.value: "项目部",
    EntityType.PROJECT.value: "项目",
    EntityType.LOCATION.value: "某地",
    EntityType.ACCOUNT.value: "账户",
    EntityType.DOCUMENT.value: "文件",
    EntityType.OTHER_PROTECTED.value: "主体",
}

_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _letter(index: int) -> str:
    out = ""
    while True:
        out = _LETTERS[index % 26] + out
        index = index // 26 - 1
        if index < 0:
            return out


@dataclass
class ResolutionReport:
    review_reasons: tuple[ReviewReason, ...] = ()
    ambiguous_pairs: tuple[tuple[str, str], ...] = ()


class EntityVault:
    """One vault per matter. Cross-matter isolation is structural: a fresh vault
    gets a fresh matter secret, so commitments and aliases cannot correlate."""

    def __init__(self, matter_id: str, matter_secret: bytes | None = None):
        self.matter_id = matter_id
        self.matter_secret = matter_secret or secrets.token_bytes(32)
        self._mentions: list[Mention] = []
        self._entities: dict[str, Entity] = {}
        self._mention_entity: dict[int, str] = {}
        self._review_reasons: set[ReviewReason] = set()

    # -- ingestion -----------------------------------------------------------

    def add_mention(self, mention: Mention) -> int:
        idx = len(self._mentions)
        mention.hmac_for(self.matter_secret)
        self._mentions.append(mention)
        return idx

    # -- resolution ------------------------------------------------------------

    def _normalize(self, mention: Mention) -> str:
        if mention.entity_type == EntityType.PERSON.value:
            return normalize_person_surface(mention.surface)
        if mention.entity_type in (
            EntityType.LEGAL_PERSON.value,
            EntityType.UNINCORPORATED_ORG.value,
            EntityType.LAW_FIRM.value,
        ):
            return normalize_org_surface(mention.surface)
        if mention.entity_type in (EntityType.ACCOUNT.value, EntityType.DOCUMENT.value):
            return normalize_id(mention.surface)
        return mention.surface.strip()

    def _strong_key(self, mention: Mention) -> str | None:
        """Strong identifier key from evidence codes (never the value itself)."""
        for code in mention.evidence_codes:
            if code.startswith("strong-id:"):
                return code.split("strong-id:", 1)[1]
        return None

    def resolve(self) -> ResolutionReport:
        uf = ConstraintUnionFind(len(self._mentions))
        by_norm: dict[tuple[str, str], int] = {}
        by_strong: dict[str, int] = {}
        for i, m in enumerate(self._mentions):
            norm = self._normalize(m)
            key = (m.entity_type, norm)
            if key in by_norm:
                uf.union(by_norm[key], i, evidence="same-normalized-surface")
            else:
                by_norm[key] = i
            strong = self._strong_key(m)
            if strong:
                if strong in by_strong:
                    uf.union(by_strong[strong], i, evidence="strong-identifier")
                else:
                    by_strong[strong] = i
        # weak OCR-approximation candidates: review only, never auto-union
        review_pairs: list[tuple[int, int]] = []
        norm_list = [self._normalize(m) for m in self._mentions]
        for i in range(len(self._mentions)):
            for j in range(i + 1, len(self._mentions)):
                a, b = self._mentions[i], self._mentions[j]
                if a.entity_type != b.entity_type:
                    continue
                if uf.find(i) == uf.find(j):
                    continue
                if surfaces_match_ocr(a.surface, b.surface) and norm_list[i] != norm_list[j]:
                    review_pairs.append((i, j))
                    self._review_reasons.add(ReviewReason.ENTITY_RESOLUTION_AMBIGUOUS)
                elif self._is_weak_alias(a, b):
                    review_pairs.append((i, j))
                    self._review_reasons.add(ReviewReason.ENTITY_RESOLUTION_AMBIGUOUS)
        groups = uf.groups()
        self._assign(groups)
        return ResolutionReport(
            review_reasons=tuple(sorted(self._review_reasons, key=lambda r: r.value)),
            ambiguous_pairs=tuple(
                (self._mentions[i].surface_hmac, self._mentions[j].surface_hmac)
                for i, j in review_pairs
            ),
        )

    def _is_weak_alias(self, a: Mention, b: Mention) -> bool:
        """Full-name/short-name candidate: one normalized surface is a suffix of
        the other with length >= 2 (e.g. 中建三局 vs 中国建筑第三工程局)."""
        na, nb = self._normalize(a), self._normalize(b)
        if not na or not nb or na == nb:
            return False
        short, full = (na, nb) if len(na) < len(nb) else (nb, na)
        return len(short) >= 2 and full.endswith(short)

    # -- deterministic assignment ---------------------------------------------

    def _assign(self, groups: list[list[int]]) -> None:
        keyed = []
        for group in groups:
            members = [self._mentions[i] for i in group]
            first = min(m.sort_key() for m in members)
            canonical = min(members, key=lambda m: (m.sort_key(), m.surface)).surface
            keyed.append((members[0].entity_type, first, min(m.surface_hmac for m in members), group, canonical))
        keyed.sort(key=lambda item: (item[0], item[1], item[2]))
        counters: dict[str, int] = {}
        used_aliases: set[str] = set()
        for entity_type, _first, _hmac, group, canonical in keyed:
            counters[entity_type] = counters.get(entity_type, 0) + 1
            n = counters[entity_type]
            entity_id = f"ent:{_TYPE_SLUG[entity_type]}:{n:04d}"
            prefix = _ALIAS_PREFIX[entity_type]
            letter_index = n - 1
            while True:
                display_alias = f"{prefix}{_letter(letter_index)}"
                if display_alias not in used_aliases:
                    break
                letter_index += 1
            used_aliases.add(display_alias)
            aliases = tuple(sorted({m.surface for m in (self._mentions[i] for i in group)}))
            entity = Entity(
                entity_id=entity_id,
                entity_type=entity_type,
                canonical_surface=canonical,
                aliases=aliases,
                display_alias=display_alias,
            )
            self._entities[entity_id] = entity
            for i in group:
                self._mention_entity[i] = entity_id

    # -- accessors --------------------------------------------------------------

    @property
    def entities(self) -> dict[str, Entity]:
        return self._entities

    def entity_for_mention(self, mention_index: int) -> Entity:
        return self._entities[self._mention_entity[mention_index]]

    def entity_id_for_mention(self, mention_index: int) -> str:
        return self._mention_entity[mention_index]

    def resolve_with_cannot_links(self, cannot_pairs: list[tuple[int, int]]) -> ResolutionReport:
        """Re-resolve honoring user cannot-link decisions (同名不同人拆分).
        Cannot-links are registered first and block the surface-equality merge
        (a user split overrides the same-name heuristic; conflicting strong
        evidence still raises CannotLinkConflict)."""
        uf = ConstraintUnionFind(len(self._mentions))
        for a, b in cannot_pairs:
            uf.cannot_link(a, b)
        by_norm: dict[tuple[str, str], int] = {}
        for i, m in enumerate(self._mentions):
            key = (m.entity_type, self._normalize(m))
            if key in by_norm and not uf.has_cannot_link(by_norm[key], i):
                uf.union(by_norm[key], i, evidence="same-normalized-surface")
            elif key not in by_norm:
                by_norm[key] = i
        groups = uf.groups()
        self._assign(groups)
        return ResolutionReport()

    def mapping_commitment(self) -> str:
        """HMAC commitment over the canonical private map (keyed by matter secret)."""
        from ..contracts.canonical import hmac_sha256

        payload = {
            e.entity_id: {
                "display_alias": e.display_alias,
                "canonical_surface": e.canonical_surface,
                "aliases": list(e.aliases),
            }
            for e in self._entities.values()
        }
        return hmac_sha256(self.matter_secret, payload)
