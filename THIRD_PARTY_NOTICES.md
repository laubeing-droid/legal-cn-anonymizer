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

Explicitly excluded from distribution dependencies: PyMuPDF (AGPL) — not vendored,
not bundled. If a future high-fidelity vector PDF engine is added it must go through
a separate license decision (user-installed, separate process adapter, AGPL release,
or commercial license).

Every ported file must keep its MIT/Apache notice and is registered with source
commit, license and modification summary in this ledger and in `upstream.lock.json`.
