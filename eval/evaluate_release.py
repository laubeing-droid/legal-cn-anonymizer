#!/usr/bin/env python3
"""Release-configuration evaluator for plan-v4.2 card 05.

Runs one detector stack over the frozen synthetic benchmark and reports
numerator/denominator metrics exactly as the egress contract requires
(denominators >=1 or null-when-unmeasured; never a fabricated zero).

Usage:
  python eval/evaluate_release.py --config eval/fixtures/v42-release-default.json \
      --dataset eval/fixtures/v42-synthetic.jsonl --no-llm \
      --output eval/results/v42/release-default.json
  python eval/evaluate_release.py --competition \
      eval/results/v42/cluener.json eval/results/v42/gliner.json \
      --out eval/results/v42/competition.md

Exit codes: 0 gate evaluation recorded; 2 gates NOT met (report still written);
4 missing component / engine unavailable (no scores claimed); 5 internal error.
All materials are synthetic; leaked-surface listings are synthetic on purpose.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO))

SCORED = ("person", "org", "location", "project", "contact", "id")
ORG_TYPES = {"LEGAL_PERSON", "UNINCORPORATED_ORG", "PUBLIC_AUTHORITY", "COURT",
             "LAW_FIRM", "PROJECT_DEPARTMENT"}
CONTACT_KINDS = {"phone", "email", "weixin", "url"}
ID_KINDS = {"id_card", "bank_account", "credit_code", "case_number", "plate", "ip"}

WARMUP_DOCS = 5
CPU_THREADS = int(os.environ.get("V42_CPU_THREADS", "4"))


def _pin_cpu_threads() -> None:
    os.environ.setdefault("OMP_NUM_THREADS", str(CPU_THREADS))
    try:
        import torch

        torch.set_num_threads(CPU_THREADS)
        torch.set_num_interop_threads(1)
    except Exception:  # noqa: BLE001 - torch absent is itself reported elsewhere
        pass


def _peak_rss_mb() -> float | None:
    if platform.system() == "Windows":
        try:
            import ctypes.wintypes as wt

            class PMC(ctypes.Structure):
                _fields_ = [
                    ("cb", wt.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            kernel32 = ctypes.windll.kernel32
            kernel32.GetCurrentProcess.restype = wt.HANDLE
            h = kernel32.GetCurrentProcess()
            c = PMC()
            c.cb = ctypes.sizeof(c)
            fn = getattr(kernel32, "K32GetProcessMemoryInfo")
            fn.argtypes = [wt.HANDLE, ctypes.POINTER(PMC), wt.DWORD]
            if fn(h, ctypes.byref(c), c.cb):
                return round(c.PeakWorkingSetSize / 1048576.0, 1)
        except Exception:  # noqa: BLE001
            pass
    try:
        import resource

        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 1)
    except Exception:  # noqa: BLE001
        return None


def machine_info() -> dict:
    info = {
        "system": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "pinned_threads": CPU_THREADS,
    }
    try:
        import torch

        info["torch"] = torch.__version__
    except Exception:  # noqa: BLE001
        info["torch"] = None
    try:
        import transformers

        info["transformers"] = transformers.__version__
    except Exception:  # noqa: BLE001
        info["torch"] = info.get("torch")
        info["transformers"] = None
    try:
        import presidio_analyzer  # noqa: F401

        info["presidio_analyzer"] = "installed"
    except Exception:  # noqa: BLE001
        info["presidio_analyzer"] = None
    return info


def detection_category(det) -> str | None:
    et = det.entity_type
    if et == "PERSON":
        return "person"
    if et in ORG_TYPES:
        return "org"
    if et == "LOCATION":
        return "location"
    if et == "PROJECT":
        return "project"
    if et.startswith("IDENTIFIER:"):
        kind = et.split(":", 1)[1]
        if kind in CONTACT_KINDS:
            return "contact"
        if kind in ID_KINDS:
            return "id"
    return None


def all_occurrences(text: str, surface: str) -> list[tuple[int, int]]:
    spans = []
    i = text.find(surface)
    while i >= 0:
        spans.append((i, i + len(surface)))
        i = text.find(surface, i + 1)
    return spans


class Engine:
    def __init__(self, names: list[str], llm_cfg: dict):
        self.components: list = []
        self.missing: list[str] = []
        from legal_anonymizer.adapters.recognizers.cn_rules import CnRuleRecognizer

        for n in names:
            if n == "cn-rules":
                self.components.append(CnRuleRecognizer())
            elif n == "cluener-ner":
                from legal_anonymizer.adapters.recognizers.presidio_ner import (
                    PresidioCnNerRecognizer,
                )

                ner = PresidioCnNerRecognizer()
                ok, reason = ner.availability()
                if not ok:
                    self.missing.append(f"cluener-ner: {reason}")
                else:
                    self.components.append(ner)
            elif n == "gliner-ner":
                from legal_anonymizer.adapters.recognizers.gliner_ner import (
                    CnGliner2RaceRecognizer,
                )

                g = CnGliner2RaceRecognizer()
                ok, reason = g.availability()
                if not ok:
                    self.missing.append(f"gliner-ner: {reason}")
                else:
                    self.components.append(g)
            else:
                self.missing.append(f"{n}: unknown engine")
        if llm_cfg.get("enabled"):
            probe = self._probe_llm(llm_cfg)
            if probe:
                self.missing.append(f"llm: {probe}")
            else:
                self.components.append(_LlmRecognizer(llm_cfg))

    @staticmethod
    def _probe_llm(llm_cfg: dict) -> str | None:
        if llm_cfg.get("provider") != "ollama-local":
            return "unsupported provider (only local Ollama is permitted)"
        import urllib.request

        try:
            with urllib.request.urlopen(
                "http://localhost:11434/api/tags", timeout=3
            ) as r:
                models = json.load(r).get("models", [])
            names = [m.get("name", "") for m in models]
            want = llm_cfg.get("model", "")
            if not any(n.startswith(want.split(":")[0]) for n in names):
                return f"model {want!r} not present in local Ollama ({names})"
            return None
        except Exception as exc:  # noqa: BLE001
            return f"local Ollama not reachable/not started: {type(exc).__name__}"

    def stack(self) -> list[dict]:
        out = []
        for c in self.components:
            if hasattr(c, "stack_descriptor"):
                out.append(c.stack_descriptor())
            elif getattr(c, "name", "") == "llm-ollama-local":
                out.append(
                    {
                        "mechanism": "local-ollama-chat-detect",
                        "modelId": c.model,
                        "modelVersion": "ollama-local",
                    }
                )
            else:
                out.append(
                    {"mechanism": "deterministic-regex", "modelId": "cn-rules",
                     "modelVersion": "1.0"}
                )
        return out

    def detect(self, text: str):
        from legal_anonymizer.adapters.recognizers.cn_rules import resolve_overlaps

        dets = []
        for c in self.components:
            dets.extend(c.detect(text))
        return resolve_overlaps(dets)


class _LlmRecognizer:
    name = "llm-ollama-local"

    def __init__(self, cfg: dict):
        self.model = cfg.get("model", "qwen2.5:7b")

    def detect(self, text: str):
        import urllib.request

        from legal_anonymizer.ports.recognizer import Detection

        prompt = (
            "识别以下合成法律文本中的人名、机构名、地址，仅输出 JSON 数组"
            "，每项 {surface, category}，category 取 PERSON/LEGAL_PERSON/LOCATION:\n"
            + text
        )
        body = json.dumps(
            {"model": self.model, "messages": [{"role": "user", "content": prompt}],
             "stream": False}
        ).encode("utf-8")
        req = urllib.request.Request(
            "http://localhost:11434/api/chat", data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            content = json.load(r).get("message", {}).get("content", "")
        start = content.find("[")
        end = content.rfind("]")
        if start < 0 or end < 0:
            return []
        out = []
        for item in json.loads(content[start : end + 1]):
            s = item.get("surface", "")
            idx = text.find(s)
            if idx >= 0:
                out.append(
                    Detection(surface=s, entity_type=item.get("category", "OTHER_PROTECTED"),
                              start=idx, end=idx + len(s), source="ner",
                              rule_id="llm.ollama", confidence=0.6, severity="high")
                )
        return out


def score_doc(doc: dict, dets: list, scope: tuple[str, ...]) -> dict:
    text = doc["text"]
    gold: dict[str, list[tuple[int, int]]] = {}
    for ent in doc["entities"]:
        cat = ent["category"]
        if cat in SCORED and cat in scope:
            gold.setdefault(cat, []).extend(all_occurrences(text, ent["surface"]))
    pred_spans = [
        (detection_category(d), (d.start, d.end))
        for d in dets
        if detection_category(d) in scope
    ]
    per: dict[str, dict] = {}
    sensitive_chars = set()
    for cat, spans in gold.items():
        hit = 0
        for g in spans:
            sensitive_chars.update(range(g[0], g[1]))
            if any(p[0] < g[1] and g[0] < p[1] for _, p in pred_spans):
                hit += 1
        per[cat] = {"hit": hit, "total": len(spans)}
    masked_sensitive = 0
    masked_nonsensitive = 0
    for _, p in pred_spans:
        for i in range(p[0], p[1]):
            if i in sensitive_chars:
                masked_sensitive += 1
            else:
                masked_nonsensitive += 1
    nonsensitive_total = max(len(text) - len(sensitive_chars), 0)
    return {
        "per_cat": per,
        "masked_sensitive_chars": masked_sensitive,
        "masked_nonsensitive_chars": masked_nonsensitive,
        "nonsensitive_chars": nonsensitive_total,
        "misses": [
            {"doc": doc["id"], "category": cat,
             "surface": text[g[0] : g[1]]}
            for cat, spans in gold.items()
            for g in spans
            if not any(p[0] < g[1] and g[0] < p[1] for _, p in pred_spans)
        ],
    }


def ratio(hit: int, total: int) -> dict | None:
    if total <= 0:
        return None  # unmeasurable: null, never a fabricated 0-denominator
    return {"hitCount": hit, "groundTruthCount": total,
            "value": round(hit / total, 4)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config")
    ap.add_argument("--dataset", default="eval/fixtures/v42-synthetic.jsonl")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--output")
    ap.add_argument("--competition", nargs=2)
    ap.add_argument("--out")
    args = ap.parse_args()

    if args.competition:
        sys.exit(write_competition(args.competition[0], args.competition[1], args.out))
    if not args.config or not args.output:
        ap.error("--config and --output are required unless --competition is used")

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if args.no_llm:
        cfg.setdefault("llm", {})["enabled"] = False
    dataset_path = Path(args.dataset)
    raw = dataset_path.read_bytes()
    dataset_revision = hashlib.sha256(raw).hexdigest()
    docs = [json.loads(l) for l in raw.decode("utf-8").splitlines() if l.strip()]

    scope = tuple(cfg.get("race_scope") or SCORED)
    engine = Engine(cfg["detectors"], cfg.get("llm", {}))
    if engine.missing:
        report = {
            "status": "CLOSED_BLOCK/model_missing",
            "missing_components": engine.missing,
            "release_profile_id": cfg["release_profile_id"],
            "profile_version": cfg["profile_version"],
            "modelAssetsAvailable": False,
            "benchmark": None,
            "machine": machine_info(),
        }
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")
        print("missing components:", engine.missing, file=sys.stderr)
        return 4

    _pin_cpu_threads()
    # warm-up: first WARMUP_DOCS docs excluded from latency stats
    for d in docs[:WARMUP_DOCS]:
        engine.detect(d["text"])

    per_cat: dict[str, dict] = {}
    masked_ns = ns_total = masked_sens = 0
    lat: list[float] = []
    misses: list[dict] = []
    for i, doc in enumerate(docs):
        t0 = time.perf_counter()
        dets = engine.detect(doc["text"])
        if i >= WARMUP_DOCS:
            lat.append(time.perf_counter() - t0)
        r = score_doc(doc, dets, scope)
        for cat, m in r["per_cat"].items():
            agg = per_cat.setdefault(cat, {"hit": 0, "total": 0})
            agg["hit"] += m["hit"]
            agg["total"] += m["total"]
        masked_ns += r["masked_nonsensitive_chars"]
        masked_sens += r["masked_sensitive_chars"]
        ns_total += r["nonsensitive_chars"]
        misses.extend(r["misses"])

    total_hit = sum(m["hit"] for m in per_cat.values())
    total_gold = sum(m["total"] for m in per_cat.values())
    p50 = round(statistics.median(lat) * 1000, 1) if lat else None
    p95 = round(statistics.quantiles(lat, n=20)[18] * 1000, 1) if len(lat) >= 2 else (
        round(lat[0] * 1000, 1) if lat else None
    )
    per_cat_out = {
        c: {"recall": ratio(m["hit"], m["total"])} for c, m in sorted(per_cat.items())
    }
    thresholds = cfg.get("thresholds") or {}
    overall = ratio(total_hit, total_gold)
    person = ratio(per_cat.get("person", {}).get("hit", 0),
                   per_cat.get("person", {}).get("total", 0))
    fpr = (
        {"maskedNonSensitiveCharCount": masked_ns,
         "nonSensitiveCharCount": ns_total,
         "value": round(masked_ns / ns_total, 4)}
        if ns_total > 0 else None
    )
    gates = {
        "overallRecall>=90%": bool(overall and overall["value"] >= thresholds.get("overallRecall", 0.90)),
        "personRecall>=90%": bool(person and person["value"] >= thresholds.get("personRecall", 0.90)),
        "falsePositiveRate<=5%": bool(fpr and fpr["value"] <= thresholds.get("falsePositiveRate", 0.05)),
    } if thresholds else {}
    report = {
        "status": "MEASURED",
        "release_profile_id": cfg["release_profile_id"],
        "profile_version": cfg["profile_version"],
        "detectors": cfg["detectors"],
        "detector_stack": engine.stack(),
        "modelAssetsAvailable": True,
        "claimScope": "specified_benchmark_only",
        "benchmark": {
            "id": cfg.get("benchmark_id", "v42-synthetic"),
            "revision": dataset_revision,
            "sampleCount": len(docs),
            "scoredScope": list(scope),
            "overallRecall": overall,
            "personRecall": person,
            "falsePositiveRate": fpr,
            "maskedSensitiveChars": masked_sens,
            "perCategory": per_cat_out,
            "latencyMsPerDoc": {"p50": p50, "p95": p95, "warmupDocs": WARMUP_DOCS,
                                 "measuredDocs": len(lat)},
            "peakRssMb": _peak_rss_mb(),
            "evaluatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "gates": gates,
        "misses": misses,
        "machine": machine_info(),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                   encoding="utf-8")
    print(json.dumps({"profile": cfg["release_profile_id"], "gates": gates,
                       "overall": overall, "person": person, "fpr": fpr,
                       "p95": p50 and report["benchmark"]["latencyMsPerDoc"]["p95"]},
                     ensure_ascii=False))
    return 0 if (not thresholds or all(gates.values())) else 2


def write_competition(a_path: str, b_path: str, out_path: str | None) -> int:
    a = json.loads(Path(a_path).read_text(encoding="utf-8"))
    b = json.loads(Path(b_path).read_text(encoding="utf-8"))

    def row(r):
        bm = r.get("benchmark") or {}
        def fmt(m):
            return f'{100*m["value"]:.1f}% ({m["hitCount"]}/{m["groundTruthCount"]})' if m else "—"
        def fmtf(m):
            return f'{100*m["value"]:.1f}% ({m["maskedNonSensitiveCharCount"]}/{m["nonSensitiveCharCount"]})' if m else "—"
        return (
            f'| {r.get("release_profile_id","?")} | {fmt(bm.get("personRecall"))} '
            f'| {fmt((bm.get("perCategory",{}).get("org") or {}).get("recall") if bm.get("perCategory") else None)} '
            f'| {fmt((bm.get("perCategory",{}).get("location") or {}).get("recall") if bm.get("perCategory") else None)} '
            f'| {fmt(bm.get("overallRecall"))} | {fmtf(bm.get("falsePositiveRate"))} '
            f'| {bm.get("latencyMsPerDoc",{}).get("p50")} / {bm.get("latencyMsPerDoc",{}).get("p95")} ms '
            f'| {bm.get("peakRssMb")} MB | {r.get("status")} |'
        )

    lines = [
        "# CLUENER vs GLiNER 竞速实测（v4.2 卡 05-1）",
        "",
        f"- 数据集: {a.get('benchmark',{}).get('id','?')} @ {str(a.get('benchmark',{}).get('revision',''))[:16]} （合成，冻结）",
        f"- 机器: {a.get('machine',{})}",
        "",
        "| 引擎 | person 召回 | org 召回 | location 召回 | 范围内总体 | 误遮盖(非敏感字符) | p50/p95 | 峰值RSS | 状态 |",
        "|---|---|---|---|---|---|---|---|---|",
        row(a),
        row(b),
        "",
        "选择规则（05-1）：实际发布配置整体召回≥90%、person召回≥90%、误遮盖≤5%；",
        "通过者优先 person 召回，再比较 p95。本表为 NER 引擎在 person/org/location 范围内的",
        "竞速实测；发布门以 v42-release-default.json（规则+NER 全栈）报告为准。",
        "论文/模型卡 F1 数字不充当本机成绩。",
    ]
    text = "\n".join(lines) + "\n"
    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
