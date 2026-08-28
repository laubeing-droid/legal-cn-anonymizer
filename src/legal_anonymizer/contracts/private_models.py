"""Private (case-bearing) contract models. These types may NEVER cross the public
surface: the public serializer raises on them. Raw entity surfaces, mapping
entries, original file names and OCR text live only here (and in DPAPI state)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .statuses import EntityType, ReviewReason, TransformKind


class PrivateBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PrivateMention(PrivateBase):
    """A concrete occurrence of a protected surface in one document."""

    schema_version: str = "1.0"
    mention_id: str
    document_id: str
    locator: dict  # closed at the schema level: kind/page/start/end/part/node_path/box
    surface: str  # RAW original value - private only
    surface_hmac: str
    entity_type: EntityType
    source: str  # regex | ner | dictionary | structure | manual | vision
    confidence: float
    evidence_codes: tuple[str, ...] = ()
    candidate_entity_ids: tuple[str, ...] = ()
    review_state: str = "AUTO_ACCEPT"
    review_reasons: tuple[ReviewReason, ...] = ()


class PrivateEntity(PrivateBase):
    """Case-level entity: canonical surface, aliases, display alias and mapping."""

    schema_version: str = "1.0"
    entity_id: str  # e.g. ent:legal-person:0001
    entity_type: EntityType
    canonical_surface: str  # RAW - private only
    aliases: tuple[str, ...] = ()  # RAW - private only
    display_alias: str  # public-safe, e.g. 法人A
    roles: tuple[str, ...] = ()
    transform: TransformKind = TransformKind.PSEUDONYMIZE
    matter_secret_hmac: str  # commitment, not the secret itself


class PrivateMappingEntry(PrivateBase):
    entity_id: str
    display_alias: str
    canonical_surface: str  # RAW - private only
    aliases: tuple[str, ...] = ()


class PrivateMapping(PrivateBase):
    """The full case mapping. Serialized only into DPAPI or portable envelopes."""

    schema_version: str = "1.0"
    matter_id: str
    entries: tuple[PrivateMappingEntry, ...] = ()
    original_filename_map: dict[str, str] = Field(default_factory=dict)  # doc-id -> raw name
    ocr_corrections: tuple[dict, ...] = ()  # private OCR correction records
