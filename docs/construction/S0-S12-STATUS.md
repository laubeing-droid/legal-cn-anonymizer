# S0–S12 construction status

Status values: `PENDING`, `IN_PROGRESS`, `COMPLETED_LOCAL`, `CLOSED_BLOCK_EXTERNAL`,
`FAILED`, `SUPERSEDED`. Machine-readable state lives in `S0-S12-STATUS.json`.

| Wave | Status | Notes |
|---|---|---|
| S0 | COMPLETED_LOCAL | traceable workspace, upstream lock, license ledger, local-only boundary |
| S1 | COMPLETED_LOCAL | closed-field contracts, canonical JSON, 15 schemas, Ed25519 receipt identity |
| S2 | COMPLETED_LOCAL | MSSP entity core, deterministic IDs, typed transforms, property tests |
| S3 | COMPLETED_LOCAL | CN deterministic rules + checksums, dictionary, Presidio extra, NER honestly unqualified |
| S4 | COMPLETED_LOCAL | Markdown/Text main chain: scan→sanitize→verify→rehydrate, signed receipts |
| S5 | COMPLETED_LOCAL | DOCX OOXML full chain: inventory, cross-run replacement, hidden-content policy |
| S6 | COMPLETED_LOCAL | text PDF + raster review PDF (no original text layer) |
| S7 | COMPLETED_LOCAL | scan pipeline: RapidOCR (hash-locked), QR, manual boxes, forced human review |
| S8 | COMPLETED_LOCAL | DPAPI vault, owner-only DACL, atomic writes, portable .lapx |
| S9 | COMPLETED_LOCAL | independent gates, signed human review receipts, synthetic benchmark |
| S10 | COMPLETED_LOCAL | consumer protocol pack, Harness handoff export, mock conformance consumer |
| S11 | COMPLETED_LOCAL | JC privacy facts (anonymizer side); JC-side adapter in juris-calculus |
| S12 | COMPLETED_LOCAL | wheel/sdist, onedir, model pack, SBOM, provenance, SHA256SUMS, acceptance report |

Final: `LOCAL_RC_WITH_EXTERNAL_BLOCKERS` — every locally controllable gate passes;
all remaining blockers are genuinely external and are listed in the acceptance
report and STATUS.json with their real fail-closed paths.

Evidence: test suites under `tests/` (207 tests), `dist/acceptance-report.json`,
`dist/SHA256SUMS`, `dist/provenance.json`. `dist/` itself is local-only (gitignored).
