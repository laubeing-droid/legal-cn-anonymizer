# 1000 中文字符长文时延单基准（V42-R2 项 8）

- 状态: MEASURED（合成文档，仅本机实测，原文不打印）
- 引擎: rules+CLUENER (RecognizerRegistry default)；预热 3 次 + 计时 20 次；CPU 线程钉定 4

| 口径 | p50 | p95 | 每轮检出数 | 含义 |
|---|---|---|---|---|
| 整文直通 | 66.7 ms | 88.3 ms | 20–20 | 生产现行路径：超 512 token 时 spacy_huggingface_pipelines 跳过整篇 NER 注解（warning: "Unable to process, skipping annotation"），实际只有规则在工作——该数字不用于门判定 |
| 分块全覆盖（3 块 ×≤450 字） | 221.3 ms | 310.5 ms | 22–22 | 每个字符都真正经过 NER；时延为逐块串行之和 |

- 门（1000 中文字符 p95 ≤ 2 s，按分块全覆盖口径）: PASS
- 具名边界（记录，不擅修）：生产识别器对超过 CLUENER 512 token 预算的文档会静默失去 NER 覆盖（规则仍生效）；修复（生产管线内分块）属 NER 行为变更，需单独裁定，本轮不动。

方法论与 eval/evaluate_release.py 同口径（perf_counter、预热排除、quantiles n=20）；机器信息见 longdoc-p95.json。实测数字，不引论文值。
