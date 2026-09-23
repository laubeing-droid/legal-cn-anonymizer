# Third-party notices

| Project | License | Usage |
|---|---|---|
| fishonbike/vault-engine | Apache-2.0 | Fork history; base skeleton (detection -> pseudonym -> local map -> report) |
| data-privacy-stack/presidio | Apache-2.0 | Recognizer registry / pattern / context / checksum / operator concepts (optional extra) |
| RapidAI/RapidOCR | Apache-2.0 | Local Chinese OCR (ONNX CPU). OCR model files are separately copyrighted; redistribution tracked in `models/manifest.json` |
| pypdfium2-team/pypdfium2 | Apache-2.0 / BSD-3-Clause | PDF rendering, text extraction, page/attachment inspection |
| microsoft/markitdown | MIT | Post-sanitization AI markdown auxiliary conversion only |
| zhendong/safe-redact | MIT | DOCX/PDF hidden-content cleanup checklist reference (checklist only, not its warn-and-continue behavior) |
| moyupeng0422/legal-doc-redactor | MIT | Chinese legal regex seeds, cross-run DOCX replacement and restore experience |
| rapidfuzz/RapidFuzz | MIT | Alias candidate similarity scoring |
| mhammond/pywin32 | PSF-2.0 | Windows DPAPI (CryptProtectData / CryptUnprotectData) |
| pyca/cryptography | Apache-2.0 / BSD-3-Clause | Ed25519 signatures, Scrypt, AES-256-GCM |
| zxing-cpp/zxing-cpp | Apache-2.0 | QR / DataMatrix / PDF417 decoding |
| Python Software Foundation | PSF-2.0 | Python runtime |

## Model redistribution records (card 05, V42-R1/R2)

No model weights are committed to git or shipped inside the wheel/sdist/onedir;
weights live under `models/ner/` (gitignored), hash-locked per file in
`models/manifest.json → ner.release_models` (revision + sha256). The records
below cover the weights this project redistributes in its offline model pack:

| Model / asset | License | Usage |
|---|---|---|
| uer/roberta-base-finetuned-cluener2020-chinese @ `cddd8fc2` (CLUENER-finetuned RoBERTa) | MIT (model weights by ydli-bgoc/UnionLab; verified on the HF model card) | Production Chinese NER (transformers token-classification engine) |
| urchade/gliner_medium-v2.1 @ `40ec4193` | Apache-2.0 | Heterogeneous independent verifier (zero-shot counterexample check) |
| fastino/gliner2-base-v1 @ `79c3a777` | Apache-2.0 | NER race candidate only (lost the race; kept hash-locked for reproduction, not loaded by production) |
| zh_core_web_sm 3.8.0 (spaCy Chinese pipeline) | MIT | Chinese tokenization for the transformers NER engine (via presidio `zh_core_web_sm` tokenizers) |

Governing packages loaded around these weights: `presidio-analyzer` 2.2.x
(MIT), `spacy` 3.8.x (MIT), `transformers` 4.x (Apache-2.0), `gliner` 0.2.x
(MIT), `gliner2` 2.x (Apache-2.0). The `gliner` and `gliner2` packages are
never interchangeable load targets: `gliner` loads only
`urchade/gliner_medium-v2.1`, `gliner2` loads only `fastino/gliner2-base-v1`.

Explicitly excluded from distribution dependencies: PyMuPDF (AGPL) — not vendored,
not bundled. If a future high-fidelity vector PDF engine is added it must go through
a separate license decision (user-installed, separate process adapter, AGPL release,
or commercial license).

Every ported file must keep its MIT/Apache notice and is registered with source
commit, license and modification summary in this ledger and in `upstream.lock.json`.
