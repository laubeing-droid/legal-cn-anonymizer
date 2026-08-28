# Construction and safety discipline (S0-S12)

This repository is the authoritative repo for the legal-document anonymizer and its
public consumer protocol. `legal-harness-repo` is an EXTERNAL consumer: never clone,
modify, commit to, or test its internals from this repo. `juris-calculus` only ever
receives closed-field verified facts — never raw surfaces, never the mapping.

## Hard rules (non-negotiable)

1. No real case fixtures. All test data must be synthetic Chinese legal material.
2. Never print original sensitive values (entity surfaces, raw OCR text, mapping
   entries) to logs, exceptions, reports, receipts or consumer bundles.
3. No network. No runtime model download, no cloud OCR/NER/privacy API, no network
   providers. Missing model => fail closed (`CLOSED_BLOCK/model_unavailable`).
4. Never delete or overwrite original user files; inputs are read-only snapshots.
5. Never present test/fake signatures as production signing; no production private
   keys in the repo, in distributions, or in fixtures.
6. No new cloud providers, ever.
7. Do not modify legal-harness-repo internals (its five Agents, MatterStore, Broker,
   Host, QC, finalization, activation).
8. Do not weaken juris-calculus protected semantics (DecisionStatus, verified fact
   admission, Horn closure, attacks/exceptions/priority, checker acceptance,
   certificate semantics, fail-closed behavior).
9. Any parse gap, integrity gap or unknown state must fail closed, never "no
   sensitive data found".
10. Money amounts and legal event dates are never silently altered.
11. Never claim "fully anonymous", "zero risk", or use SAFE/100% ANONYMIZED statuses.
12. Recognizers never grade their own homework: the verification engine is an
    independent path.
13. Scanned documents, low-confidence detections, quasi-identifier risks and
    publish mode always require human review with a signed receipt.
14. Do not push, tag, release, or change repo visibility without explicit
    current-turn authorization.
15. No AGPL dependencies in the distribution (PyMuPDF is excluded).

## Wave discipline

Each wave S0..S12: targeted checks -> affected regression -> `git diff --check` ->
local commit. Update `docs/construction/S0-S12-STATUS.json` and `.md` every wave.
A FAILED wave blocks the next wave until fixed to COMPLETED_LOCAL. Only genuinely
external missing conditions may be recorded as CLOSED_BLOCK_EXTERNAL, together with
a real fail-closed path.
