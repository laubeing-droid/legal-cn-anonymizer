# Security Policy

legal-cn-anonymizer is a privacy tool for Chinese legal materials, so we are
deliberately conservative about what it claims.

## What this tool protects

- Original identity surfaces never leave the machine in `ai-safe` mode; only typed
  display pseudonyms are emitted.
- The entity mapping, OCR private cache, original file names and review decisions are
  encrypted with Windows DPAPI bound to the current user, and never enter any public
  artifact, receipt, or consumer bundle.
- Public receipts carry HMAC commitments keyed by a per-matter random secret, not
  plain hashes of raw surfaces.

## What this tool does NOT protect

- A fully compromised machine (malware with user rights can read what the user reads).
- Screen recording, shoulder surfing, or the user voluntarily uploading the mapping.
- Re-identification through rare quasi-identifiers the user chose to keep; the tool
  flags these for human review instead of claiming they are safe.
- Physical recoverability of deleted temp files on SSDs.

## Reporting

Do not open a public issue for a security problem. Contact the maintainers directly
with a minimal repro and impact assessment.

## Design invariants enforced at runtime

Injective entity mapping per matter, matter-scoped isolation, idempotent transforms,
reversible left-inverse, money/legal-date multiset conservation, document/part/page
accounting, mapping exclusion from public bundles, and fail-closed behavior on every
parse, integrity or state gap.

## Threat-model red lines

- The mapping vault **is** the identity it hides. A leaked vault is a full
  disclosure of the underlying matter. Keep it local; never commit it; never send it
  anywhere.
- Parse failures, integrity gaps and unknown states must fail closed
  (`CLOSED_BLOCK`); the tool never reports "no sensitive data found" for content it
  could not read.
- Scanned documents always require a signed human review receipt before they may be
  marked READY_BY_HUMAN.
