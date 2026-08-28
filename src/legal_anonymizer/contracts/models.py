"""Public (closed-field) contract models. ``additionalProperties=false`` semantics
are enforced by ``extra="forbid"`` and mirrored by the JSON Schemas in
``contracts/schemas/``. Money is a canonical decimal string (minor units kept by
the producer), times are RFC3339 UTC strings, paths and raw values are forbidden."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from .statuses import (
    EntityType,
    ReviewReason,
    SanitizationStatus,
    TransformKind,
)

PUBLIC_SCHEMA_VERSION = "1.0"


class PublicBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProjectManifest(PublicBase):
    schema_version: str = PUBLIC_SCHEMA_VERSION
    matter_id: str
    profile_id: str
    created_at: str  # RFC3339 UTC
    documents: tuple[str, ...] = ()  # stable doc-xxx ids, never raw names
    status: SanitizationStatus = SanitizationStatus.REVIEW_REQUIRED


class DocumentRecord(PublicBase):
    schema_version: str = PUBLIC_SCHEMA_VERSION
    document_id: str
    format: Literal["markdown", "text", "docx", "pdf_text", "pdf_scan", "image"]
    page_count: int = 1
    state: str  # DocumentState value
    sanitized_sha256: str | None = None
    report_sha256: str | None = None


class TransformPlanEntry(PublicBase):
    schema_version: str = PUBLIC_SCHEMA_VERSION
    entity_id: str
    entity_type: EntityType
    transform: TransformKind
    display_alias: str | None = None  # only for PSEUDONYMIZE
    locator_count: int = 0


class ReviewDecision(PublicBase):
    schema_version: str = PUBLIC_SCHEMA_VERSION
    decision_id: str
    target: str  # mention id / entity id pair / manual box key
    action: Literal["approve", "reject", "add", "merge", "split", "manual_box"]
    reviewer_subject: str
    reviewer_role: Literal["UPLOADING_LAWYER", "MATTER_LEAD", "DESIGNATED_REVIEWER"]


class HumanReviewReceipt(PublicBase):
    schema_version: str = PUBLIC_SCHEMA_VERSION
    matter_id: str
    report_hash: str
    sanitized_bundle_hash: str
    reviewer_subject: str
    reviewer_role: str
    decisions_hash: str
    issued_at: str
    single_use: bool = True
    revision: int = 1


class GateResult(PublicBase):
    privacy: Literal["PASS", "FAIL", "NOT_EVALUATED"] = "NOT_EVALUATED"
    completeness: Literal["PASS", "FAIL", "NOT_EVALUATED"] = "NOT_EVALUATED"
    utility: Literal["PASS", "FAIL", "REVIEW_REQUIRED", "NOT_EVALUATED"] = "NOT_EVALUATED"
    physical_redaction: Literal["PASS", "FAIL", "NOT_APPLICABLE", "NOT_EVALUATED"] = "NOT_EVALUATED"


class SanitizationReport(PublicBase):
    schema_version: str = PUBLIC_SCHEMA_VERSION
    matter_id: str
    profile_id: str
    status: SanitizationStatus
    gates: GateResult
    document_records: tuple[DocumentRecord, ...] = ()
    invariant_results: dict[str, bool] = {}
    open_review_reasons: tuple[ReviewReason, ...] = ()
    error_codes: tuple[str, ...] = ()
    report_hash: str | None = None  # set after signing/serialization


class SanitizationReceipt(PublicBase):
    schema_version: str = PUBLIC_SCHEMA_VERSION
    matter_id: str
    profile_id: str
    provider_id: str = "legal-cn-anonymizer"
    provider_build_digest: str
    created_at: str
    status: SanitizationStatus
    sanitized_bundle_hash: str
    artifact_hashes: dict[str, str]  # stable artifact name -> sha256
    mapping_commitment: str  # HMAC(K_C, canonical private map)
    source_set_commitment: str  # HMAC(K_C, sorted raw sha256s)
    invariants: dict[str, bool]
    review: dict | None = None  # human-review-receipt-v1 embedded or None
    signature: dict | None = None  # {algorithm,key_id,signature}; set at signing


class PrivacyVerificationReceipt(PublicBase):
    schema_version: str = PUBLIC_SCHEMA_VERSION
    matter_id: str
    created_at: str
    gate_results: GateResult
    verifier_build_digest: str
    residual_counts: dict[str, int]
    invariant_results: dict[str, bool]
    signature: dict | None = None


class SanitizedBundle(PublicBase):
    schema_version: str = PUBLIC_SCHEMA_VERSION
    matter_id: str
    profile_id: str
    created_at: str
    status: SanitizationStatus
    artifacts: tuple[dict, ...] = ()  # {name, sha256, bytes}
    receipt_hash: str
    structured_objects: tuple[dict, ...] = ()  # sanitized Party/MatterProfile/... closed dicts


class MappingEnvelope(PublicBase):
    """Public-visible *envelope* of the private mapping (no mapping content)."""

    schema_version: str = PUBLIC_SCHEMA_VERSION
    matter_id: str
    encryption: Literal["dpapi-current-user", "aes-256-gcm-scrypt"]
    entry_count: int
    mapping_commitment: str
    created_at: str


class PortableProject(PublicBase):
    schema_version: str = PUBLIC_SCHEMA_VERSION
    matter_id: str
    kdf: Literal["scrypt"]
    kdf_params: dict
    cipher: Literal["aes-256-gcm"]
    salt_b64: str
    nonce_b64: str
    ciphertext_b64: str
    created_at: str


class JcPrivacyFacts(PublicBase):
    schema_version: str = PUBLIC_SCHEMA_VERSION
    matter_id: str
    created_at: str
    facts: dict[str, bool | int | str]
    receipt_hash: str
    signature: dict | None = None


PRIVATE_TYPES = tuple()


def public_payload(model: PublicBase) -> dict:
    """Serialize a public model to a closed dict.

    Raises TypeError when handed a private (case-bearing) model, so private state
    can never be serialized onto the public surface by accident.
    """
    from .private_models import PrivateBase

    if isinstance(model, PrivateBase):
        raise TypeError(
            "private contract model cannot be serialized to the public surface: "
            f"{type(model).__name__}"
        )
    if not isinstance(model, PublicBase):
        raise TypeError(f"not a public contract model: {type(model).__name__}")
    import json

    return json.loads(model.model_dump_json())
