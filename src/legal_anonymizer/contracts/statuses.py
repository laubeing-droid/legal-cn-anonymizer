"""Closed enumeration vocabulary for the whole system. X/Y/Z are reserved for
formal rule variables and are never machine entity IDs."""

from __future__ import annotations

from enum import Enum


class SanitizationStatus(str, Enum):
    AUTO_READY = "AUTO_READY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    READY_BY_HUMAN = "READY_BY_HUMAN"
    CLOSED_BLOCK = "CLOSED_BLOCK"
    ENGINE_ERROR = "ENGINE_ERROR"


class DocumentState(str, Enum):
    DISCOVERED = "DISCOVERED"
    SNAPSHOTTED = "SNAPSHOTTED"
    PARSED = "PARSED"
    OCR_REQUIRED = "OCR_REQUIRED"
    OCR_COMPLETE = "OCR_COMPLETE"
    TRANSFORMED = "TRANSFORMED"
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"


class EntityType(str, Enum):
    PERSON = "PERSON"
    LEGAL_PERSON = "LEGAL_PERSON"
    UNINCORPORATED_ORG = "UNINCORPORATED_ORG"
    PUBLIC_AUTHORITY = "PUBLIC_AUTHORITY"
    COURT = "COURT"
    LAW_FIRM = "LAW_FIRM"
    PROJECT_DEPARTMENT = "PROJECT_DEPARTMENT"
    PROJECT = "PROJECT"
    LOCATION = "LOCATION"
    ACCOUNT = "ACCOUNT"
    DOCUMENT = "DOCUMENT"
    OTHER_PROTECTED = "OTHER_PROTECTED"


class TransformKind(str, Enum):
    KEEP = "KEEP"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    MASK_KEEP_LAST_4 = "MASK_KEEP_LAST_4"
    MASK_KEEP_FIRST_1 = "MASK_KEEP_FIRST_1"
    GENERALIZE_YEAR = "GENERALIZE_YEAR"
    GENERALIZE_ADMIN_DIVISION = "GENERALIZE_ADMIN_DIVISION"
    PHYSICAL_REDACT = "PHYSICAL_REDACT"
    DROP_WITH_RECEIPT = "DROP_WITH_RECEIPT"
    REVIEW = "REVIEW"


class ReviewReason(str, Enum):
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    OCR_DOCUMENT = "OCR_DOCUMENT"
    QUASI_IDENTIFIER = "QUASI_IDENTIFIER"
    ENTITY_RESOLUTION_AMBIGUOUS = "ENTITY_RESOLUTION_AMBIGUOUS"
    HIDDEN_CONTENT = "HIDDEN_CONTENT"
    UNKNOWN_ATTACHMENT = "UNKNOWN_ATTACHMENT"
    QR_UNREADABLE = "QR_UNREADABLE"
    MANUAL_BOX_REQUIRED = "MANUAL_BOX_REQUIRED"
    PUBLISH_MODE = "PUBLISH_MODE"


# Closed error-code vocabulary (appendix B of the construction plan).
ERROR_CODES = frozenset(
    {
        "input_unsupported_format",
        "input_changed_during_read",
        "parser_failed",
        "document_part_unreadable",
        "pdf_page_render_failed",
        "ocr_model_unavailable",
        "ocr_page_missing",
        "ocr_confidence_below_threshold",
        "ner_model_unavailable",
        "recognizer_degraded",
        "entity_resolution_ambiguous",
        "entity_cannot_link_conflict",
        "mapping_collision",
        "mapping_vault_unavailable",
        "mapping_decryption_failed",
        "portable_project_authentication_failed",
        "critical_residual_found",
        "hidden_content_unresolved",
        "money_invariant_failed",
        "legal_date_invariant_failed",
        "entity_reference_invariant_failed",
        "document_count_mismatch",
        "page_count_mismatch",
        "output_hash_mismatch",
        "physical_redaction_unverified",
        "human_review_required",
        "human_review_receipt_invalid",
        "harness_bundle_invalid",
        "harness_sanitization_binding_missing",
        "jc_fact_admission_failed",
        "network_access_attempted",
        "engine_error",
    }
)

# Forbidden status words — they must never appear in outputs or CLI text.
FORBIDDEN_STATUS_WORDS = ("SAFE", "100% ANONYMIZED", "ZERO RISK")
