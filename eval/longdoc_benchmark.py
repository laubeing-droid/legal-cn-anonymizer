"""1000-CJK-character long-document latency benchmark (V42-R2 item 8).

The frozen latency gate (plan-v4.2) is "p95 <= 2s at 1000 Chinese
characters" on CPU. V42-R1 measured the competition corpus at ~90 chars/doc
average (p95 124.8 ms); this benchmark closes the dedicated long-document
measurement with the SAME production stack and the SAME methodology as
eval/evaluate_release.py (perf_counter around one full registry.detect,
warm-up excluded, p95 = quantiles(n=20)[18], 4 pinned torch threads).

Document: synthetic Chinese legal prose padded/truncated to EXACTLY 1000 CJK
characters with synthetic PII patterns embedded. Document text is never
printed — only character counts, detection counts and timings.

Usage:  python eval/longdoc_benchmark.py            # writes
        eval/results/v42/longdoc-p95.json and .md
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

CPU_THREADS = 4
TARGET_CJK = 1000
WARMUP_RUNS = 3
TIMED_RUNS = 20
GATE_P95_MS = 2000.0
# CLUENER RoBERTa positional budget is 512 tokens (~1 token per CJK char +
# specials); chunks stay well under it so every character is really seen by
# the NER engine.
CHUNK_CJK = 450

_SENTENCES = (
    "甲方委托乙方代理本案一审诉讼事宜，代理权限为特别授权。",
    "经办律师应当勤勉尽责，及时向委托人书面汇报案件进展情况。",
    "双方确认本协议条款系在平等自愿基础上协商一致订立。",
    "如一方违约，应向守约方支付合同约定金额百分之二十的违约金。",
    "案件受理费、保全费、鉴定费及相关差旅费用由委托人另行承担。",
    "本合同自双方签字盖章之日起生效，一式两份，各执一份为凭。",
)


def _pin_cpu_threads() -> None:
    os.environ.setdefault("OMP_NUM_THREADS", str(CPU_THREADS))
    try:
        import torch

        torch.set_num_threads(CPU_THREADS)
        torch.set_num_interop_threads(1)
    except Exception as exc:  # noqa: BLE001 - reported via machine info below
        print(f"note: torch thread pinning skipped: {type(exc).__name__}")


def _machine_info() -> dict:
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
        info["torch"] = "absent"
    return info


def _cjk_count(text: str) -> int:
    return sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")


def build_longdoc() -> str:
    """Synthetic contract prose truncated to EXACTLY TARGET_CJK CJK chars
    (ASCII digits/punctuation inside sentences do not count toward CJK)."""
    name = "张伟明"
    phone = "137" + "".join(str((i * 7 + 3) % 10) for i in range(8))
    sentences = []
    for i in range(200):
        sentences.append(
            f"委托事项{i}：{_SENTENCES[i % len(_SENTENCES)]}"
            f"经办律师{name}（联系电话{phone}）已出具第{i}号工作清单。"
        )
    text = "".join(sentences)
    kept, count = [], 0
    for ch in text:
        if "\u4e00" <= ch <= "\u9fff":
            count += 1
        kept.append(ch)
        if count >= TARGET_CJK:
            break
    return "".join(kept)


def _chunks(text: str, max_cjk: int = CHUNK_CJK) -> list[str]:
    """Split text so each chunk stays under the model's positional budget."""
    chunks, current, count = [], [], 0
    for ch in text:
        current.append(ch)
        if "\u4e00" <= ch <= "\u9fff":
            count += 1
            if count >= max_cjk:
                chunks.append("".join(current))
                current, count = [], 0
    if current:
        chunks.append("".join(current))
    return chunks


def main() -> int:
    _pin_cpu_threads()
    from legal_anonymizer.adapters.recognizers.registry import RecognizerRegistry

    doc = build_longdoc()
    cjk = _cjk_count(doc)
    if cjk != TARGET_CJK:
        print(f"FAIL: built document has {cjk} CJK chars, expected {TARGET_CJK}")
        return 1

    registry = RecognizerRegistry()
    if not registry.ner_available:
        print("CLOSED_BLOCK/model_unavailable:", registry.status.get("reason"))
        return 4

    chunks = _chunks(doc)

    def measure(fn):
        for _ in range(WARMUP_RUNS):
            fn()
        latencies, detection_counts = [], []
        for _ in range(TIMED_RUNS):
            t0 = time.perf_counter()
            dets = fn()
            latencies.append(time.perf_counter() - t0)
            detection_counts.append(len(dets))
        p50 = round(statistics.median(latencies) * 1000, 1)
        p95 = round(statistics.quantiles(latencies, n=20)[18] * 1000, 1)
        return {"p50": p50, "p95": p95,
                "detectionsPerRun": {"min": min(detection_counts),
                                     "max": max(detection_counts)}}

    # (a) raw single-shot: what the unmodified production path does with a
    # 1000-char doc — spacy_huggingface_pipelines CANNOT process docs beyond
    # the model's positional budget and SKIPS the annotation silently
    # ("Unable to process, skipping annotation"), i.e. NER contributes
    # nothing; only rules run. Measured to document that boundary, never to
    # claim the gate.
    raw = measure(lambda: registry.detect(doc))
    # (b) chunked full coverage: every character really reaches the NER
    # engine; per-run latency is the serial sum over all chunks (the honest
    # end-to-end cost of processing the whole document).
    chunked = measure(lambda: [d for c in chunks for d in registry.detect(c)])

    gate_pass = chunked["p95"] <= GATE_P95_MS

    report = {
        "status": "MEASURED",
        "benchmark": "longdoc-1000cjk",
        "cjkCharacters": cjk,
        "chunkCjk": CHUNK_CJK,
        "chunkCount": len(chunks),
        "engine": {
            "detectorStack": registry.detector_stack(),
            "registry": "rules+CLUENER (RecognizerRegistry default)",
        },
        "warmupRuns": WARMUP_RUNS,
        "timedRuns": TIMED_RUNS,
        "measurements": {
            "rawSingleShot": {
                **raw,
                "meaning": "unmodified production path on a 1000-char doc; "
                           "NER annotation is SKIPPED by "
                           "spacy_huggingface_pipelines (doc exceeds the "
                           "model's 512-token budget) — rules only",
            },
            "chunkedFullCoverage": {
                **chunked,
                "meaning": "document split into "
                           f"{len(chunks)} chunks of <= {CHUNK_CJK} CJK chars, "
                           "serially scanned; latency is the per-run sum — "
                           "every character reaches the NER engine",
            },
        },
        "latencyMs": {"p50": chunked["p50"], "p95": chunked["p95"],
                      "gate": GATE_P95_MS, "gatePass": gate_pass,
                      "gateBasis": "chunkedFullCoverage"},
        "machine": _machine_info(),
        "note": "synthetic document; surfaces never printed; same methodology "
                "as eval/evaluate_release.py (perf_counter, warm-up excluded, "
                "quantiles n=20). BOTH readings are recorded: the raw path "
                "silently drops NER on long docs — that production boundary "
                "is named here and NOT papered over by the chunked gate "
                "measurement.",
    }
    out_dir = ROOT / "eval" / "results" / "v42"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "longdoc-p95.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    md = [
        "# 1000 中文字符长文时延单基准（V42-R2 项 8）",
        "",
        f"- 状态: {report['status']}（合成文档，仅本机实测，原文不打印）",
        (f"- 引擎: {report['engine']['registry']}；预热 {WARMUP_RUNS} 次 + 计时 "
         f"{TIMED_RUNS} 次；CPU 线程钉定 {CPU_THREADS}"),
        "",
        "| 口径 | p50 | p95 | 每轮检出数 | 含义 |",
        "|---|---|---|---|---|",
        (f"| 整文直通 | {raw['p50']} ms | {raw['p95']} ms | "
         f"{raw['detectionsPerRun']['min']}–{raw['detectionsPerRun']['max']} | "
         "生产现行路径：超 512 token 时 spacy_huggingface_pipelines 跳过整篇 "
         "NER 注解（warning: \"Unable to process, skipping annotation\"），实际"
         "只有规则在工作——该数字不用于门判定 |"),
        (f"| 分块全覆盖（{len(chunks)} 块 ×≤{CHUNK_CJK} 字） | "
         f"{chunked['p50']} ms | {chunked['p95']} ms | "
         f"{chunked['detectionsPerRun']['min']}–"
         f"{chunked['detectionsPerRun']['max']} | 每个字符都真正经过 NER；"
         "时延为逐块串行之和 |"),
        "",
        (f"- 门（1000 中文字符 p95 ≤ 2 s，按分块全覆盖口径）: "
         f"{'PASS' if gate_pass else 'FAIL'}"),
        ("- 具名边界（记录，不擅修）：生产识别器对超过 CLUENER 512 token 预算的"
         "文档会静默失去 NER 覆盖（规则仍生效）；修复（生产管线内分块）属 "
         "NER 行为变更，需单独裁定，本轮不动。"),
        "",
        ("方法论与 eval/evaluate_release.py 同口径（perf_counter、预热排除、"
         "quantiles n=20）；机器信息见 longdoc-p95.json。实测数字，不引论文值。"),
        "",
    ]
    (out_dir / "longdoc-p95.md").write_text("\n".join(md), encoding="utf-8")
    print(f"raw(single-shot, NER-skipped) p95 {raw['p95']} ms | "
          f"chunked(full-coverage) p50 {chunked['p50']} ms / "
          f"p95 {chunked['p95']} ms — gate "
          f"{'PASS' if gate_pass else 'FAIL'} "
          f"-> eval/results/v42/longdoc-p95.{{json,md}}")
    return 0 if gate_pass else 2


if __name__ == "__main__":
    sys.exit(main())
