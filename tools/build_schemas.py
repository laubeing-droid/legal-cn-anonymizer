"""Generate the closed-field JSON Schemas into
src/legal_anonymizer/contracts/schemas/. Re-running must be byte-stable."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "src" / "legal_anonymizer" / "contracts" / "schemas"

HASH = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
HMAC = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
RFC3339 = {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"}
MONEY = {
    "type": "string",
    "pattern": "^(0|[1-9][0-9]*)(\\.[0-9]{1,4})?$",
    "description": "canonical decimal string; float is forbidden",
}
SHA256HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}

STATUSES = ["AUTO_READY", "REVIEW_REQUIRED", "READY_BY_HUMAN", "CLOSED_BLOCK", "ENGINE_ERROR"]
ENTITY_TYPES = [
    "PERSON", "LEGAL_PERSON", "UNINCORPORATED_ORG", "PUBLIC_AUTHORITY", "COURT",
    "LAW_FIRM", "PROJECT_DEPARTMENT", "PROJECT", "LOCATION", "ACCOUNT", "DOCUMENT",
    "OTHER_PROTECTED",
]
TRANSFORMS = [
    "KEEP", "PSEUDONYMIZE", "MASK_KEEP_LAST_4", "MASK_KEEP_FIRST_1", "GENERALIZE_YEAR",
    "GENERALIZE_ADMIN_DIVISION", "PHYSICAL_REDACT", "DROP_WITH_RECEIPT", "REVIEW",
]
REVIEW_REASONS = [
    "LOW_CONFIDENCE", "OCR_DOCUMENT", "QUASI_IDENTIFIER", "ENTITY_RESOLUTION_AMBIGUOUS",
    "HIDDEN_CONTENT", "UNKNOWN_ATTACHMENT", "QR_UNREADABLE", "MANUAL_BOX_REQUIRED",
    "PUBLISH_MODE",
]
ENTITY_ID = {"type": "string", "pattern": "^ent:[a-z-]+:[0-9]{4,}$"}


def obj(schema_id: str, properties: dict, required: list, description: str = "") -> dict:
    s = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://legal-cn-anonymizer.local/schemas/{schema_id}.schema.json",
        "title": schema_id,
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version"] + required,
        "properties": {
            "schema_version": {"const": "1.0"},
            **properties,
        },
    }
    if description:
        s["description"] = description
    return s


def sig_block() -> dict:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["algorithm", "key_id", "signature"],
        "properties": {
            "algorithm": {"const": "Ed25519"},
            "key_id": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
            "signature": {"type": "string", "pattern": "^[A-Za-z0-9+/]+=*$"},
        },
    }


SCHEMAS: dict[str, dict] = {}

SCHEMAS["project-manifest-v1"] = obj(
    "project-manifest-v1",
    {
        "matter_id": {"type": "string", "pattern": "^[a-z0-9-]{3,64}$"},
        "profile_id": {"type": "string", "pattern": "^[a-z0-9-]{3,64}$"},
        "created_at": RFC3339,
        "documents": {"type": "array", "items": {"type": "string", "pattern": "^doc-[0-9]{3,}$"}, "uniqueItems": True},
        "status": {"enum": STATUSES},
    },
    ["matter_id", "profile_id", "created_at"],
    "Public project manifest. Raw file names are forbidden here.",
)

SCHEMAS["document-record-v1"] = obj(
    "document-record-v1",
    {
        "document_id": {"type": "string", "pattern": "^doc-[0-9]{3,}$"},
        "format": {"enum": ["markdown", "text", "docx", "pdf_text", "pdf_scan", "image"]},
        "page_count": {"type": "integer", "minimum": 1},
        "state": {"enum": ["DISCOVERED", "SNAPSHOTTED", "PARSED", "OCR_REQUIRED", "OCR_COMPLETE", "TRANSFORMED", "VERIFIED", "BLOCKED"]},
        "sanitized_sha256": {**SHA256HEX, "type": ["string", "null"]},
        "report_sha256": {**SHA256HEX, "type": ["string", "null"]},
    },
    ["document_id", "format", "page_count", "state"],
)

LOCATOR = {
    "type": "object",
    "additionalProperties": False,
    "required": ["kind"],
    "properties": {
        "kind": {"enum": ["text_offset", "pdf_box", "ocr_box", "docx_xml"]},
        "page": {"type": "integer", "minimum": 1},
        "start": {"type": "integer", "minimum": 0},
        "end": {"type": "integer", "minimum": 0},
        "part": {"type": "string"},
        "node_path": {"type": "string"},
        "box": {"type": "array", "items": {"type": "number"}, "minItems": 4, "maxItems": 4},
    },
}

SCHEMAS["private-mention-v1"] = obj(
    "private-mention-v1",
    {
        "mention_id": {"type": "string"},
        "document_id": {"type": "string"},
        "locator": LOCATOR,
        "surface": {"type": "string", "description": "RAW original value; private only"},
        "surface_hmac": HMAC,
        "entity_type": {"enum": ENTITY_TYPES},
        "source": {"enum": ["regex", "ner", "dictionary", "structure", "manual", "vision"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "evidence_codes": {"type": "array", "items": {"type": "string"}},
        "candidate_entity_ids": {"type": "array", "items": ENTITY_ID},
        "review_state": {"enum": ["AUTO_ACCEPT", "REVIEW_REQUIRED", "ACCEPTED", "REJECTED"]},
        "review_reasons": {"type": "array", "items": {"enum": REVIEW_REASONS}},
    },
    ["mention_id", "document_id", "locator", "surface", "surface_hmac", "entity_type", "source", "confidence"],
    "PRIVATE schema - never leaves the machine except inside DPAPI/portable state.",
)

SCHEMAS["private-entity-v1"] = obj(
    "private-entity-v1",
    {
        "entity_id": ENTITY_ID,
        "entity_type": {"enum": ENTITY_TYPES},
        "canonical_surface": {"type": "string"},
        "aliases": {"type": "array", "items": {"type": "string"}},
        "display_alias": {"type": "string"},
        "roles": {"type": "array", "items": {"type": "string"}},
        "transform": {"enum": TRANSFORMS},
        "matter_secret_hmac": HMAC,
    },
    ["entity_id", "entity_type", "canonical_surface", "display_alias"],
    "PRIVATE schema.",
)

SCHEMAS["transform-plan-v1"] = obj(
    "transform-plan-v1",
    {
        "matter_id": {"type": "string"},
        "entries": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["entity_id", "entity_type", "transform", "locator_count"],
                "properties": {
                    "entity_id": ENTITY_ID,
                    "entity_type": {"enum": ENTITY_TYPES},
                    "transform": {"enum": TRANSFORMS},
                    "display_alias": {"type": ["string", "null"]},
                    "locator_count": {"type": "integer", "minimum": 0},
                },
            },
        },
    },
    ["matter_id", "entries"],
    "Public transform plan: entity ids, transforms and counts only - no surfaces.",
)

SCHEMAS["review-decisions-v1"] = obj(
    "review-decisions-v1",
    {
        "matter_id": {"type": "string"},
        "based_on_report_hash": {**HASH, "type": ["string", "null"]},
        "decisions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["decision_id", "target", "action"],
                "properties": {
                    "decision_id": {"type": "string"},
                    "target": {"type": "string"},
                    "action": {"enum": ["approve", "reject", "add", "merge", "split", "manual_box", "ocr_correction", "hidden_content_policy"]},
                    "detail": {"type": "object"},
                    "reviewer_subject": {"type": "string"},
                    "reviewer_role": {"enum": ["UPLOADING_LAWYER", "MATTER_LEAD", "DESIGNATED_REVIEWER"]},
                },
            },
        },
    },
    ["matter_id", "decisions"],
    "Human review decisions (YAML file form is converted to this structure).",
)

SCHEMAS["human-review-receipt-v1"] = obj(
    "human-review-receipt-v1",
    {
        "matter_id": {"type": "string"},
        "report_hash": HASH,
        "sanitized_bundle_hash": HASH,
        "reviewer_subject": {"type": "string", "minLength": 1},
        "reviewer_role": {"type": "string", "minLength": 1},
        "decisions_hash": HASH,
        "issued_at": RFC3339,
        "single_use": {"type": "boolean"},
        "revision": {"type": "integer", "minimum": 1},
        "signature": sig_block(),
    },
    ["matter_id", "report_hash", "sanitized_bundle_hash", "reviewer_subject", "reviewer_role", "decisions_hash", "issued_at"],
)

NER_COMPONENT = {
    "type": "object",
    "additionalProperties": False,
    "required": ["mechanism", "modelId", "modelVersion"],
    "properties": {
        "mechanism": {"type": "string", "minLength": 1},
        "modelId": {"type": "string", "minLength": 1},
        "modelVersion": {"type": "string", "minLength": 1},
    },
}
RECALL_METRIC = {
    "type": "object",
    "additionalProperties": False,
    "required": ["hitCount", "groundTruthCount", "value"],
    "properties": {
        "hitCount": {"type": "integer", "minimum": 0},
        "groundTruthCount": {"type": "integer", "minimum": 1},
        "value": {"type": "number", "minimum": 0, "maximum": 1},
    },
}
MASKING_METRIC = {
    "type": "object",
    "additionalProperties": False,
    "required": ["maskedNonSensitiveCharCount", "nonSensitiveCharCount", "value"],
    "properties": {
        "maskedNonSensitiveCharCount": {"type": "integer", "minimum": 0},
        "nonSensitiveCharCount": {"type": "integer", "minimum": 1},
        "value": {"type": "number", "minimum": 0, "maximum": 1},
    },
}
GATES = {
    "type": "object",
    "additionalProperties": False,
    "required": ["privacy", "completeness", "utility", "physical_redaction"],
    "properties": {
        "privacy": {"enum": ["PASS", "FAIL", "NOT_EVALUATED"]},
        "completeness": {"enum": ["PASS", "FAIL", "NOT_EVALUATED"]},
        "utility": {"enum": ["PASS", "FAIL", "REVIEW_REQUIRED", "NOT_EVALUATED"]},
        "physical_redaction": {"enum": ["PASS", "FAIL", "NOT_APPLICABLE", "NOT_EVALUATED"]},
    },
}

_docrec_nested = {
    k: v for k, v in SCHEMAS["document-record-v1"].items() if k not in ("$schema", "$id")
}
SCHEMAS["sanitization-report-v1"] = obj(
    "sanitization-report-v1",
    {
        "matter_id": {"type": "string"},
        "profile_id": {"type": "string"},
        "status": {"enum": STATUSES},
        "gates": GATES,
        "document_records": {"type": "array", "items": {"$ref": "#/$defs/docrec"}},
        "invariant_results": {"type": "object", "additionalProperties": {"type": "boolean"}},
        "open_review_reasons": {"type": "array", "items": {"enum": REVIEW_REASONS}},
        "error_codes": {"type": "array", "items": {"type": "string"}},
        "report_hash": {**HASH, "type": ["string", "null"]},
    },
    ["matter_id", "profile_id", "status", "gates"],
)
SCHEMAS["sanitization-report-v1"]["$defs"] = {"docrec": _docrec_nested}

_review_nested = {
    k: v for k, v in SCHEMAS["human-review-receipt-v1"].items() if k not in ("$schema", "$id")
}
SCHEMAS["sanitization-receipt-v1"] = obj(
    "sanitization-receipt-v1",
    {
        "matter_id": {"type": "string"},
        "profile_id": {"type": "string"},
        "provider_id": {"type": "string"},
        "provider_build_digest": {"type": "string"},
        "created_at": RFC3339,
        "status": {"enum": STATUSES},
        "sanitized_bundle_hash": HASH,
        "artifact_hashes": {
            "type": "object",
            "additionalProperties": SHA256HEX,
            "propertyNames": {"pattern": "^[A-Za-z0-9._-]+$"},
        },
        "mapping_commitment": HMAC,
        "source_set_commitment": HMAC,
        "invariants": {"type": "object", "additionalProperties": {"type": "boolean"}},
        "review": {**_review_nested, "type": ["object", "null"]},
        "signature": sig_block(),
    },
    ["matter_id", "profile_id", "provider_id", "provider_build_digest", "created_at", "status", "sanitized_bundle_hash", "artifact_hashes", "mapping_commitment", "source_set_commitment", "invariants"],
    "Signed public receipt. Raw values, paths and the mapping are forbidden.",
)

SCHEMAS["privacy-verification-receipt-v1"] = obj(
    "privacy-verification-receipt-v1",
    {
        "matter_id": {"type": "string"},
        "created_at": RFC3339,
        "gate_results": GATES,
        "verifier_build_digest": {"type": "string"},
        "residual_counts": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}},
        "invariant_results": {"type": "object", "additionalProperties": {"type": "boolean"}},
        "signature": sig_block(),
    },
    ["matter_id", "created_at", "gate_results", "verifier_build_digest", "residual_counts", "invariant_results"],
)

SCHEMAS["sanitized-bundle-v1"] = obj(
    "sanitized-bundle-v1",
    {
        "matter_id": {"type": "string"},
        "profile_id": {"type": "string"},
        "created_at": RFC3339,
        "status": {"enum": STATUSES},
        "artifacts": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "sha256", "bytes"],
                "properties": {
                    "name": {"type": "string", "pattern": "^[A-Za-z0-9._-]+$"},
                    "sha256": SHA256HEX,
                    "bytes": {"type": "integer", "minimum": 0},
                },
            },
        },
        "receipt_hash": HASH,
        "structured_objects": {"type": "array", "items": {"type": "object"}},
        "signature": sig_block(),
    },
    ["matter_id", "profile_id", "created_at", "status", "artifacts", "receipt_hash"],
    "Public sanitized bundle descriptor. Mapping and private fields are forbidden.",
)

SCHEMAS["consumer-contract-manifest-v1"] = obj(
    "consumer-contract-manifest-v1",
    {
        "source_repository": {"type": "string"},
        "source_commit_note": {"type": "string"},
        "package_version": {"type": "string"},
        "provider_id": {"type": "string"},
        "provider_build_digest": {"type": "string"},
        "signer": {
            "type": "object",
            "additionalProperties": False,
            "required": ["key_id", "fingerprint", "algorithm"],
            "properties": {
                "key_id": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
                "fingerprint": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "algorithm": {"const": "Ed25519"},
            },
        },
        "profile_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "canonical_serialization_profile": {"type": "object"},
        "required_invariants": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "schemas": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "additionalProperties": False,
                "required": ["sha256", "canonical_copy"],
                "properties": {
                    "sha256": SHA256HEX,
                    "canonical_copy": {"const": True},
                },
            },
        },
        "fixture_hashes": {"type": "object"},
        "signature": sig_block(),
    },
    ["source_repository", "provider_id", "provider_build_digest", "signer", "profile_ids",
     "canonical_serialization_profile", "required_invariants", "schemas"],
    "Binding contract between the anonymizer and its external consumers.",
)

SCHEMAS["mapping-envelope-v1"] = obj(
    "mapping-envelope-v1",
    {
        "matter_id": {"type": "string"},
        "encryption": {"enum": ["dpapi-current-user", "aes-256-gcm-scrypt"]},
        "entry_count": {"type": "integer", "minimum": 0},
        "mapping_commitment": HMAC,
        "created_at": RFC3339,
    },
    ["matter_id", "encryption", "entry_count", "mapping_commitment", "created_at"],
    "Public envelope of the private mapping; no mapping content.",
)

SCHEMAS["portable-project-v1"] = obj(
    "portable-project-v1",
    {
        "matter_id": {"type": "string"},
        "kdf": {"const": "scrypt"},
        "kdf_params": {
            "type": "object",
            "additionalProperties": False,
            "required": ["n", "r", "p"],
            "properties": {
                "n": {"type": "integer", "minimum": 16384},
                "r": {"type": "integer", "minimum": 8},
                "p": {"type": "integer", "minimum": 1},
            },
        },
        "cipher": {"const": "aes-256-gcm"},
        "salt_b64": {"type": "string"},
        "nonce_b64": {"type": "string"},
        "ciphertext_b64": {"type": "string"},
        "created_at": RFC3339,
    },
    ["matter_id", "kdf", "kdf_params", "cipher", "salt_b64", "nonce_b64", "ciphertext_b64", "created_at"],
)

JC_FACTS = [
    "RawMaterialRemainedLocal", "DirectNaturalPersonIdentifiersTransformed",
    "MappingStoredLocalOnly", "MappingExcludedFromExternalBundle",
    "MoneyPreserved", "LegalEventDatesPreserved", "HumanReviewRequired",
    "HumanReviewCompleted",
]
SCHEMAS["jc-privacy-facts-v1"] = obj(
    "jc-privacy-facts-v1",
    {
        "matter_id": {"type": "string"},
        "created_at": RFC3339,
        "facts": {
            "type": "object",
            "additionalProperties": {"type": ["boolean", "integer", "string"]},
        },
        "receipt_hash": HASH,
        "signature": sig_block(),
    },
    ["matter_id", "created_at", "facts", "receipt_hash"],
    "Closed-field privacy facts for juris-calculus consumption.",
)


SCHEMAS["privacy-verification-receipt-v2"] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://legal-cn-anonymizer.local/schemas/privacy-verification-receipt-v2.schema.json",
    "title": "privacy-verification-receipt-v2",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version", "matter_id", "created_at", "gate_results",
        "verifier_build_digest", "detector_stack", "verifier_stack", "coverage",
        "residual_counts", "invariant_results",
    ],
    "properties": {
        "schema_version": {"const": "2.0"},
        "matter_id": {"type": "string"},
        "created_at": RFC3339,
        "gate_results": {
            **GATES,
            "properties": {
                **GATES["properties"],
                "privacy": {"enum": ["PASS", "FAIL", "NOT_EVALUATED", "REVIEW_REQUIRED"]},
            },
        },
        "verifier_build_digest": {"type": "string"},
        "detector_stack": {"type": "array", "items": NER_COMPONENT},
        "verifier_stack": {"type": "array", "items": NER_COMPONENT},
        "coverage": {
            "type": "object",
            "additionalProperties": False,
            "required": ["complete", "reasons"],
            "properties": {
                "complete": {"type": "boolean"},
                "reasons": {"type": "array", "items": {"type": "string"}},
            },
        },
        "residual_counts": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0},
                            "description": "includes 'ner_residual': heterogeneous-verifier hits on final delivered content the production stack missed"},
        "invariant_results": {"type": "object", "additionalProperties": {"type": "boolean"}},
        "signature": sig_block(),
    },
    "description": "Heterogeneous independent verification receipt (plan-v4.2 card 05-2).",
}

COVERAGE_STATEMENT_DEF = {
    "type": "object",
    "additionalProperties": False,
    "required": ["releaseProfileId", "profileVersion", "detectorStack",
                 "verifierStack", "modelAssetsAvailable", "benchmark"],
    "properties": {
        "releaseProfileId": {"type": "string", "minLength": 1},
        "profileVersion": {"type": "string", "minLength": 1},
        "detectorStack": {"type": "array", "items": NER_COMPONENT, "minItems": 0},
        "verifierStack": {"type": "array", "items": NER_COMPONENT, "minItems": 0},
        "modelAssetsAvailable": {"type": "boolean"},
        "benchmark": {
            "anyOf": [
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["id", "revision", "sampleCount", "overallRecall",
                                 "personRecall", "falsePositiveRate", "evaluatedAt",
                                 "claimScope"],
                    "properties": {
                        "id": {"type": "string", "minLength": 1},
                        "revision": {"type": "string", "minLength": 1},
                        "sampleCount": {"type": "integer", "minimum": 1},
                        "overallRecall": RECALL_METRIC,
                        "personRecall": {"anyOf": [RECALL_METRIC, {"type": "null"}]},
                        "falsePositiveRate": MASKING_METRIC,
                        "evaluatedAt": {"type": "string", "minLength": 1},
                        "claimScope": {"const": "specified_benchmark_only"},
                    },
                },
                {"type": "null"},
            ]
        },
    },
    "description": "Verbatim shape of the frozen plan-v4.2 runtime contract $defs/CoverageStatement.",
}

SCHEMAS["coverage-statement-v1"] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://legal-cn-anonymizer.local/schemas/coverage-statement-v1.schema.json",
    "title": "coverage-statement-v1",
    **COVERAGE_STATEMENT_DEF,
}

SCHEMAS["scan-bytes-report-v1"] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://legal-cn-anonymizer.local/schemas/scan-bytes-report-v1.schema.json",
    "title": "scan-bytes-report-v1",
    "type": "object",
    "additionalProperties": False,
    "required": ["requestId", "status", "bodySha256", "scannedByteLength",
                 "unscannedSegmentCount", "alertCount", "coverageStatement"],
    "properties": {
        "requestId": {"type": "string", "minLength": 1},
        "status": {"enum": ["complete", "failed", "timeout", "unsupported_format", "model_missing"]},
        "bodySha256": {"anyOf": [SHA256HEX, {"type": "null"}]},
        "scannedByteLength": {"type": "integer", "minimum": 0},
        "unscannedSegmentCount": {"type": "integer", "minimum": 0},
        "alertCount": {"type": "integer", "minimum": 0},
        "coverageStatement": COVERAGE_STATEMENT_DEF,
    },
    "description": "A-side implementation of the frozen ScanBytesReport; never carries an egress receipt.",
}


SCHEMAS["scan-bytes-request-v1"] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://legal-cn-anonymizer.local/schemas/scan-bytes-request-v1.schema.json",
    "title": "scan-bytes-request-v1",
    "type": "object",
    "additionalProperties": False,
    "required": ["requestId", "encoding", "bodyBase64", "bodySha256", "byteLength",
                 "contentType", "releaseProfileId", "profileVersion", "scanProfile"],
    "properties": {
        "requestId": {"type": "string", "minLength": 1},
        "encoding": {"const": "base64"},
        "bodyBase64": {"type": "string", "minLength": 1},
        "bodySha256": SHA256HEX,
        "byteLength": {"type": "integer", "minimum": 0},
        "contentType": {"const": "application/json; charset=utf-8"},
        "releaseProfileId": {"type": "string", "minLength": 1},
        "profileVersion": {"type": "string", "minLength": 1},
        "scanProfile": {"const": "json-recursive-keys-and-strings/v1"},
    },
    "description": "Verbatim shape of the frozen plan-v4.2 ScanBytesRequest draft.",
}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name in sorted(SCHEMAS):
        path = OUT / f"{name}.schema.json"
        path.write_text(
            json.dumps(SCHEMAS[name], ensure_ascii=False, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    print(f"wrote {len(SCHEMAS)} schemas to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
