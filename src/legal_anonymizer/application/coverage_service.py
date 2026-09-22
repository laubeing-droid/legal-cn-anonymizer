"""Coverage statement builder (plan-v4.2 card 05-3 / IF-07).

Shapes the frozen `CoverageStatement`: the three release ratios keep their
numerator/denominator structure; an unmeasured metric is null, never a
fabricated zero; model stacks are taken from the RUNTIME engines, not from
self-declared text. The consumer-side trusted-config check then compares this
statement item by item against its own trusted configuration (main process,
outside this repo).
"""

from __future__ import annotations

import json
from pathlib import Path

RELEASE_PROFILE_ID = "cn-release-v42"
RELEASE_PROFILE_VERSION = "1"

RELEASE_THRESHOLDS = {
    "overallRecall": 0.90,
    "personRecall": 0.90,
    "falsePositiveRate": 0.05,
}

_BENCHMARK_PATHS = (
    Path("eval/results/v42/release-default.json"),
)


def _ratio(metric: dict | None) -> dict | None:
    if not metric:
        return None
    return {
        "hitCount": int(metric["hitCount"]),
        "groundTruthCount": int(metric["groundTruthCount"]),
        "value": float(metric["value"]),
    }


def _masking(metric: dict | None) -> dict | None:
    if not metric:
        return None
    return {
        "maskedNonSensitiveCharCount": int(metric["maskedNonSensitiveCharCount"]),
        "nonSensitiveCharCount": int(metric["nonSensitiveCharCount"]),
        "value": float(metric["value"]),
    }


def load_benchmark(repo_root: Path, benchmark_id: str | None = None) -> dict | None:
    """Return the contract-shaped benchmark block from an actual measured
    report, or None when no valid measurement exists (never a zero guess)."""
    for rel in _BENCHMARK_PATHS:
        p = Path(repo_root) / rel
        if not p.exists():
            continue
        report = json.loads(p.read_text(encoding="utf-8"))
        if report.get("status") != "MEASURED":
            continue
        bm = report.get("benchmark") or {}
        if benchmark_id and bm.get("id") != benchmark_id:
            continue
        overall = _ratio(bm.get("overallRecall"))
        fpr = _masking(bm.get("falsePositiveRate"))
        if overall is None or fpr is None:
            return None
        return {
            "id": bm["id"],
            "revision": bm["revision"],
            "sampleCount": int(bm["sampleCount"]),
            "overallRecall": overall,
            "personRecall": _ratio(bm.get("personRecall")),
            "falsePositiveRate": fpr,
            "evaluatedAt": bm["evaluatedAt"],
            "claimScope": "specified_benchmark_only",
        }
    return None


def build_coverage_statement(registry, verifier=None, repo_root: Path | None = None,
                             benchmark_id: str | None = "v42-synthetic") -> dict:
    repo_root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[3]
    from ..adapters.recognizers import model_assets

    assets_ok = True
    for asset in model_assets.load_ner_assets():
        ok, _reason = asset.check(repo_root)
        assets_ok = assets_ok and ok
    detector_stack = registry.detector_stack()
    verifier_stack: list[dict] = []
    if verifier is not None:
        v_ok, _v_reason = verifier.availability()
        if v_ok:
            verifier_stack = [verifier.stack_descriptor()]
    return {
        "releaseProfileId": RELEASE_PROFILE_ID,
        "profileVersion": RELEASE_PROFILE_VERSION,
        "detectorStack": detector_stack,
        "verifierStack": verifier_stack,
        "modelAssetsAvailable": bool(assets_ok and registry.ner_available),
        "benchmark": load_benchmark(repo_root, benchmark_id),
    }


def meets_release_gates(coverage: dict) -> tuple[bool, list[str]]:
    """Threshold checks exactly as frozen: null personRecall fails the gate;
    self-declared values are recomputed from numerator/denominator first."""
    reasons: list[str] = []
    if not coverage.get("modelAssetsAvailable"):
        reasons.append("model_assets_unavailable")
    bm = coverage.get("benchmark")
    if bm is None:
        reasons.append("benchmark_missing")
        return False, reasons
    for key, field in (("overallRecall", "hitCount"), ("personRecall", "hitCount")):
        m = bm.get(key)
        if m is None:
            reasons.append(f"{key}_unmeasured")
            continue
        recomputed = m[field] / m["groundTruthCount"]
        if abs(recomputed - m["value"]) > 1e-4:
            reasons.append(f"{key}_value_not_recomputable")
        if recomputed < RELEASE_THRESHOLDS[key]:
            reasons.append(f"{key}_below_{RELEASE_THRESHOLDS[key]}")
    fpr = bm.get("falsePositiveRate")
    if fpr is None:
        reasons.append("falsePositiveRate_unmeasured")
    else:
        recomputed = (fpr["maskedNonSensitiveCharCount"]
                      / fpr["nonSensitiveCharCount"])
        if abs(recomputed - fpr["value"]) > 1e-4:
            reasons.append("falsePositiveRate_value_not_recomputable")
        if recomputed > RELEASE_THRESHOLDS["falsePositiveRate"]:
            reasons.append("falsePositiveRate_above_0.05")
    from .verify_service import ensure_heterogeneous

    try:
        ensure_heterogeneous(coverage["detectorStack"], coverage["verifierStack"])
    except ValueError as exc:
        reasons.append(f"verifier_not_heterogeneous: {exc}")
    if not coverage["verifierStack"]:
        reasons.append("independent_verifier_missing")
    return not reasons, reasons
