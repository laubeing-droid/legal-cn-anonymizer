# Detection benchmark

| detector | person | org | location | project | contact | id | **overall** | over-redaction |
|---|---|---|---|---|---|---|---|---|
| vault-engine (regex only) | 0% | 0% | 0% | 0% | 69% | 33% | **13%** (10/77) | 0% |
| Microsoft Presidio | 30% | 12% | 33% | 0% | 8% | 33% | **21%** (16/77) | 5% |

_Recall = share of gold identities flagged for redaction (higher is better). Over-redaction = flagged spans matching no gold identity (lower is better). Dataset: 77 scored entities across 15 bilingual synthetic docs._
