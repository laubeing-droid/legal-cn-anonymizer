"""Sanitization profiles. A profile maps entity types and identifier kinds to
explicit transforms; missing configuration is an error, never a guess."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..contracts.statuses import ReviewReason, TransformKind


@dataclass(frozen=True)
class Profile:
    profile_id: str
    scope: str
    entity_transforms: dict[str, str]
    identifier_transforms: dict[str, str]
    utility_keeps: tuple[str, ...]
    review_required: tuple[ReviewReason, ...]
    requires_human_receipt: bool = False

    def transform_for_entity(self, entity_type: str) -> str:
        if entity_type not in self.entity_transforms:
            raise KeyError(
                f"profile {self.profile_id} has no transform for entity type {entity_type}; "
                "refusing to guess"
            )
        return self.entity_transforms[entity_type]

    def transform_for_identifier(self, identifier: str) -> str:
        if identifier not in self.identifier_transforms:
            raise KeyError(
                f"profile {self.profile_id} has no transform for identifier {identifier}; "
                "refusing to guess"
            )
        return self.identifier_transforms[identifier]


AI_SAFE_V1 = Profile(
    profile_id="cn-ai-safe-v1",
    scope="EXTERNAL_MODEL_INPUT",
    entity_transforms={
        "PERSON": TransformKind.PSEUDONYMIZE.value,
        "LEGAL_PERSON": TransformKind.PSEUDONYMIZE.value,
        "UNINCORPORATED_ORG": TransformKind.PSEUDONYMIZE.value,
        "PUBLIC_AUTHORITY": TransformKind.PSEUDONYMIZE.value,
        "COURT": TransformKind.PSEUDONYMIZE.value,
        "LAW_FIRM": TransformKind.PSEUDONYMIZE.value,
        "PROJECT_DEPARTMENT": TransformKind.PSEUDONYMIZE.value,
        "PROJECT": TransformKind.PSEUDONYMIZE.value,
        "LOCATION": TransformKind.GENERALIZE_ADMIN_DIVISION.value,
        "ACCOUNT": TransformKind.MASK_KEEP_LAST_4.value,
        "DOCUMENT": TransformKind.PSEUDONYMIZE.value,
        "OTHER_PROTECTED": TransformKind.PSEUDONYMIZE.value,
    },
    identifier_transforms={
        "id_card": TransformKind.MASK_KEEP_LAST_4.value,
        "phone": TransformKind.MASK_KEEP_LAST_4.value,
        "email": TransformKind.PSEUDONYMIZE.value,
        "bank_account": TransformKind.MASK_KEEP_LAST_4.value,
        "credit_code": TransformKind.PSEUDONYMIZE.value,
        "case_number": TransformKind.PSEUDONYMIZE.value,
        "plate": TransformKind.MASK_KEEP_LAST_4.value,
        "weixin": TransformKind.PSEUDONYMIZE.value,
        "url": TransformKind.PSEUDONYMIZE.value,
        "ip": TransformKind.MASK_KEEP_LAST_4.value,
        "birth_date": TransformKind.GENERALIZE_YEAR.value,
        "personal_address": TransformKind.GENERALIZE_ADMIN_DIVISION.value,
        "project_address": TransformKind.GENERALIZE_ADMIN_DIVISION.value,
        "qr_code": TransformKind.REVIEW.value,
    },
    utility_keeps=("money", "percentage", "interest_rate", "legal_event_date",
                   "evidence_number", "page_number"),
    review_required=(
        ReviewReason.LOW_CONFIDENCE,
        ReviewReason.OCR_DOCUMENT,
        ReviewReason.QUASI_IDENTIFIER,
        ReviewReason.HIDDEN_CONTENT,
        ReviewReason.QR_UNREADABLE,
    ),
)

PUBLISH_V1 = Profile(
    profile_id="cn-publish-v1",
    scope="PUBLIC_RELEASE",
    entity_transforms={
        "PERSON": TransformKind.PSEUDONYMIZE.value,
        "LEGAL_PERSON": TransformKind.PSEUDONYMIZE.value,
        "UNINCORPORATED_ORG": TransformKind.PSEUDONYMIZE.value,
        "PUBLIC_AUTHORITY": TransformKind.KEEP.value,
        "COURT": TransformKind.KEEP.value,
        "LAW_FIRM": TransformKind.PSEUDONYMIZE.value,
        "PROJECT_DEPARTMENT": TransformKind.PSEUDONYMIZE.value,
        "PROJECT": TransformKind.PSEUDONYMIZE.value,
        "LOCATION": TransformKind.GENERALIZE_ADMIN_DIVISION.value,
        "ACCOUNT": TransformKind.MASK_KEEP_LAST_4.value,
        "DOCUMENT": TransformKind.PSEUDONYMIZE.value,
        "OTHER_PROTECTED": TransformKind.PHYSICAL_REDACT.value,
    },
    identifier_transforms={
        "id_card": TransformKind.PHYSICAL_REDACT.value,
        "phone": TransformKind.PHYSICAL_REDACT.value,
        "email": TransformKind.PHYSICAL_REDACT.value,
        "bank_account": TransformKind.PHYSICAL_REDACT.value,
        "credit_code": TransformKind.PHYSICAL_REDACT.value,
        "case_number": TransformKind.PSEUDONYMIZE.value,
        "plate": TransformKind.PHYSICAL_REDACT.value,
        "weixin": TransformKind.PHYSICAL_REDACT.value,
        "url": TransformKind.PHYSICAL_REDACT.value,
        "ip": TransformKind.PHYSICAL_REDACT.value,
        "birth_date": TransformKind.GENERALIZE_YEAR.value,
        "personal_address": TransformKind.GENERALIZE_ADMIN_DIVISION.value,
        "project_address": TransformKind.GENERALIZE_ADMIN_DIVISION.value,
        "qr_code": TransformKind.PHYSICAL_REDACT.value,
    },
    utility_keeps=("money", "percentage", "legal_event_date"),
    review_required=(ReviewReason.PUBLISH_MODE,),
    requires_human_receipt=True,
)

PROFILES = {p.profile_id: p for p in (AI_SAFE_V1, PUBLISH_V1)}


def get_profile(profile_id: str) -> Profile:
    if profile_id not in PROFILES:
        raise KeyError(f"unknown profile: {profile_id}")
    return PROFILES[profile_id]
