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
| V42-R1 | COMPLETED_LOCAL | plan-v4.2 卡05生产轨：Presidio transformers 中文NER上线、CLUENER/GLiNER2 实测竞速、异构复核v2收据、IF-07覆盖声明+scan_bytes、九步处置服务（详见下表与 STATUS.json） |

## V42-R1 (plan-v4.2 card 05) — 2026-09-23

Production NER: `adapters/recognizers/presidio_ner.py` (NlpEngineProvider
`transformers` engine: zh_core_web_sm tokenization + hash-locked
`uer/roberta-base-finetuned-cluener2020-chinese@cddd8fc2`). Real CLUENER BIOES
labels (B/I/S-name/address/company/government/organization) normalized and
mapped to PERSON/LOCATION/LEGAL_PERSON/PUBLIC_AUTHORITY; book/game/movie/
position/scene never masked; ASCII-only spans dropped as model noise.
`RecognizerRegistry()` default = rules+NER and is the single shared production
construction — enumerated default call sites: sanitize_service.py:141,
docx_pipeline.py:119, pdf_pipeline.py:86, scan_pipeline.py:81,
verify_service.py:100, scan_bytes_service.py:42, plus the cli.py command
dispatch that drives all chains through these services. Missing components =>
named
`ner_model_unavailable` + REVIEW_REQUIRED; a rules-only fallback is reported as
a degradation and never silently AUTO_READY.

Race (frozen synthetic set, 27 docs / 98 scored spans, rev `146cff21…`):
CLUENER person 21/34=61.8%, FP 10/870=1.2%, p95 124.8ms; GLiNER2
(`gliner2` package) person 9/34=26.5%, FP 6.0%. No engine meets the 0.90
person gate => production slot = rules+CLUENER (only FP-gate carrier),
`models/manifest.json ner.qualified` stays **false**, and matters whose
coverage depends on NER-only surfaces remain REVIEW_REQUIRED. Both the
pre-noise-filter (76.5%/4.9%) and post-filter numbers are recorded in
`eval/results/v42/competition.md`; no paper F1 is quoted as ours.

Heterogeneous verification (card 05-2): receipt v2 publishes
detector/verifier stacks + coverage; same-model verifier rejected
(`ensure_heterogeneous`); GLiNER medium-v2.1 counterexample (production-missed
王某/赵某 detected) forces `privacy=FAIL` with named `residual_counts.ner_residual`;
verifier unavailable => REVIEW_REQUIRED, never PASS.

Egress contract (card 05-3): `coverage-statement-v1`,
`scan-bytes-request-v1`, `scan-bytes-report-v1` schemas generated verbatim
from the frozen plan-v4.2 draft `$defs`; `pii.scan_bytes` implemented
(strict decode, every key/string scanned, digests recomputed from actual
bytes, no egress receipt ever emitted); the consumer-side
`trustedConfigCheck` refusals (wrong profile/benchmark/model version,
disguised homogeneity, self-declared non-recomputable values, null
measurement, zero denominator) are pinned in
`tests/contract/test_coverage_refusal_v42.py`.

Disposal (W15c-A): `application/disposal_service.py` implements the nine steps
with bridge-compatible signatures (`execute_disposal(state_root, scope, key,
authorizationRef)` / `read_disposal(state_root, scope, request_id)`), real
Ed25519 authorization verification against a local trust store, separate
disposal ledger, restart resume and no-empty-mapping recreation.

Evidence: `eval/results/v42/` (cluener/gliner/release-default/release-llm/
competition/legacy-baseline), `reports/v42/` (regression.xml 248 passed,
coverage.xml 31 passed, product-disposal.xml 10 passed).

Known card-vs-repo discrepancies (recorded, not papered over): the card's
"现有 W15c-A `tests/jusbench/test_disposal.py`（13例）" does not exist anywhere
in this repo or the product checkout — this wave ships the product nine-step
test directly; local Ollama is absent so the optional LLM track exits 4 with
`CLOSED_BLOCK/model_missing` and no default-config claim borrows LLM numbers.

Final: `LOCAL_RC_WITH_EXTERNAL_BLOCKERS` — every locally controllable gate passes;
all remaining blockers are genuinely external and are listed in the acceptance
report and STATUS.json with their real fail-closed paths.

Evidence: test suites under `tests/` (207 tests), `dist/acceptance-report.json`,
`dist/SHA256SUMS`, `dist/provenance.json`. `dist/` itself is local-only (gitignored).
