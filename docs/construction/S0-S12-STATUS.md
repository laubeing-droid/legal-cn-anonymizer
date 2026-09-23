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
| V42-R2 | COMPLETED_LOCAL | 桥契约三件（pii_scan/ingest/handoff-manifest）、发布工件重建（19 schema 进 wheel + 新 extras + 模型再分发记录）、离线装机脚本、CLI scan-bytes、1000 中文字符长文双口径 p95 基准（详见下节与 STATUS.json） |

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

## V42-R2 (HANDOFF debt ledger) — 2026-09-23

Baseline `cd7a811` (V42-R1 handoff), tree clean. All work against the frozen
bridge contract (`jusbench-repo/bridge/jusbench_bridge/providers.py`, read-only,
never modified). Wave commits, in order: `51d15e8` → `a50ac65` → `86a49ad` →
`a4da664` → `d9eb15e` → contract-correction commit.

**Contract correction (公开改口, after direct plan-v4.2 source check).** The
trio below was first built from the bridge code + handoff wording only. When
asked, the frozen sources were read directly (05-anonymizer卡.md,
`contracts/source/methods-core.json`, `contracts/schemas/ifc-2.schema.json`,
`common.schema.json`, `source/types-ifc2.json`) and three real deviations
were found and fixed:

- **pii.scan** had been implemented as an inline-payload variant of
  scan_bytes. The frozen contract is a FILE-SET scan:
  `PiiScanRequest{payloadRoot, expectedFiles, expectedPayloadDigest}` →
  `PiiScanReport{tool, toolVersion, ruleVersion, status, expectedFiles,
  actualScannedFiles, payloadDigest, alertCount, alerts[{file, rule,
  detail}]}` + `PiiScanReportAddition{coverageStatement}`; set digest = IF-03
  formula `sha256(sorted "rel\nsha256hex\n" concat)`, bare hex; success =
  complete ∧ expected==actual ∧ digest matches ∧ alertCount==0; error
  envelopes stay inside `payload_modified / scan_incomplete /
  unsupported_format / timeout` (model-missing now fails
  `scan_incomplete`, not a `model_missing` report status). Alerts carry
  span offsets only — surfaces never echoed.
- **ingest.*** had invented states/codes. Now: submit returns `{jobId}`
  exactly (wire output); status carries the frozen state enum
  `queued/running/waiting_review/done/error/cancelled` +
  `stage/completedUnits/totalUnits/resultRefs/error(RpcErrorBody)`;
  cancel/resume return `Saved{ref, revision, changeSeq, receipt}` and are
  idempotent on terminal jobs; error codes narrowed to the frozen
  `unsupported_format/ref_not_found`.
- **build_harness_handoff manifest=** had a resolver-derived whitelist with
  an invented `payloadDigest` field. Now validated against the frozen
  `HandoffManifest` closure (`manifestVersion` pinned `"1.1"`, 17 required
  fields, `additionalProperties=false`, sourceKind/coverage enums); result
  carries `receiptRef` (+`manifestRef` when a manifest was written) per the
  wire output closure `{bundleRef, receiptRef, manifestRef}`.

`tests/jusbench/test_bridge_contracts_v42.py` was rewritten against the
frozen shapes (25 cases incl. an IF-03 formula reference check).

1. **Bridge contract trio** (`51d15e8` + correction commit):
   `pii_scan_service.scan_release_payload(request, timeout_seconds=None)`
   per the frozen file-set contract above; `ingest_service`
   (`ingest_submit/_status/_cancel/_resume` over per-job ledgers; read-only
   snapshots — digests/sizes/formats only, contents never enter the ledger;
   `hash_mismatch` fail-closed on resume); `build_harness_handoff` accepts
   the bridge's `manifest=` kwarg per the frozen HandoffManifest closure
   (`manifest=None` keeps prior behavior). All in the exact bridge call
   shapes over real registry/ledger/signature chains.
2. **Release artifacts rebuilt** (`a50ac65`): the 19 generated contract
   schemas now ship in wheel+sdist (package-data; previously missing from
   wheels), SBOM covers the presidio/ner-race/markitdown extras (26
   components) and hash-locks all 19 schemas as dataAssets,
   THIRD_PARTY_NOTICES.md gains redistribution records for CLUENER RoBERTa
   (MIT), GLiNER medium-v2.1 / gliner2-base (Apache-2.0) and zh_core_web_sm
   (MIT). Rebuilt wheel/sdist/SBOM/provenance/SHA256SUMS/acceptance-report
   locally: 19 schemas verified in-wheel, zero weight files,
   `verify_no_private_artifacts` + `verify_distribution` PASS, final
   `LOCAL_RC_WITH_EXTERNAL_BLOCKERS`. `dist/` stays local (gitignored).
6. **Offline model install** (`86a49ad`): `scripts/install_offline_models.py`
   installs an offline pack (dir/zip, `models/` layout) and verifies the
   `models/manifest.json` hash locks in full (no short-circuit: every
   missing/hash_mismatch/size_mismatch named, exit 1). The repo's own
   manifest is the trust anchor — a pack cannot silently re-pin its own
   hashes (`--accept-manifest` required to re-pin). Zip-slip guarded. Zero
   network; wheels still carry no weights. Real-repo run: 3 locked assets,
   2.81 GB, PASS.
7. **CLI scan-bytes** (`a4da664`): `vault-engine scan-bytes INFILE|-` drives
   `scan_bytes_service` with strict request construction; report to stdout or
   `-o`; exit 0 only on complete coverage; never an egress receipt.
8. **Long-document latency** (`d9eb15e`): `eval/longdoc_benchmark.py`, exact
   1000-CJK synthetic contract, methodology identical to
   `eval/evaluate_release.py`. TWO readings recorded: raw single-shot p95
   88.3 ms is NOT the gate — `spacy_huggingface_pipelines` silently skips NER
   annotation beyond CLUENER's 512-token budget, so only rules run; chunked
   full coverage (3 × ≤450 CJK, serial sum) p50 221.3 / p95 310.5 ms with
   22 vs 20 detections confirming real NER contribution. Gate (1000 chars
   p95 ≤ 2 s): **PASS on the chunked basis**. The unmodified path's silent
   NER coverage loss on long docs is a named boundary; fixing it is an
   NER-behavior change requiring separate adjudication.

Items recorded as adjudication/other-repo evidence only (nothing touched):

- **Item 3 (person gate)**: personRecall 21/34 = 61.8% < 90% stands as
  measured in V42-R1; the three candidate routes (deterministic party rules /
  user-dictionary operations / fine-tune or swap) await user adjudication;
  the 0.90 threshold itself was NOT changed.
- **Item 4 (card discrepancy)**: plan-v4.2 card 05-4 cites a pre-existing
  W15c-A `tests/jusbench/test_disposal.py` (13 cases) that does not exist
  anywhere in this repo or the product checkout; V42-R1 shipped the product
  nine-step test directly. The card-side premise needs correction on the
  card owner's side.
- **Item 5 (egress gates in other repos)**: EgressReceipt issuance and
  `trustedConfigCheck` production enforcement belong to the 01 main process;
  consumer-side refusals (jobs.py/trust.py/pii.py) live outside this repo.
  The A side carries only the test reference implementation — deliberately
  not re-implemented here.

Full-suite regression: `python -B -m pytest -q -p no:cacheprovider tests` →
**289 passed / 0 failed** (`reports/v42/regression.xml`; 248 baseline + 41
new). `git diff --check` clean per wave.
