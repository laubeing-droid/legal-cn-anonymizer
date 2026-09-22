# V42-R1 发布覆盖报告（plan-v4.2 卡05）

声明对象 = 本文件随附的**已测试发布配置与数据集**，不是对产品普遍性能的承诺：

- 发布配置：`eval/fixtures/v42-release-default.json`
  （releaseProfileId `cn-release-v42` / profileVersion `1`；
  detectorStack = 确定性规则 + CLUENER transformers-NER；
  verifierStack = GLiNER medium-v2.1 零样本跨编码器；LLM 关闭）
- 数据集：`eval/fixtures/v42-synthetic.jsonl`
  （benchmarkId `v42-synthetic`，revision `146cff21d12ff455…`（文件 sha256），
  27 篇全合成文档 / 98 个计分金标跨度；双语旧金标 77 + 反例增补 21）
- 机器与线程：Windows 11 AMD64，Python 3.12.10，torch 2.14.0+cpu，
  固定 4 线程，前 5 篇预热不计延迟（全部记录在各 JSON 的 `machine` 字段）

## 实测结果（分子/分母，按合同 `x-egress.metricDenominators`）

| 指标 | 数值 | 判定 |
|---|---|---|
| overallRecall | 56/98 = 57.1% | 低于 0.90 门，未达标 |
| personRecall | 21/34 = 61.8% | 低于 0.90 门，未达标 |
| falsePositiveRate（误遮盖非敏感字符） | 10/870 = 1.2% | ≤5% 达标 |
| 时延 p50/p95（每文档） | 见 release-default.json | p95 ≤ 2s 预算内 |
| 峰值 RSS | 见各 JSON | CLUENER ≈1.1GB |

`claimScope = specified_benchmark_only`。禁止把开启 LLM 的成绩转移给默认关闭
配置（本机 Ollama 未运行，LLM 轨 `release-llm.json` 为
`CLOSED_BLOCK/model_missing`、退出码 4，未产生任何成绩）。

## 发布判定

- `models/manifest.json → ner.qualified` 保持 **false**：人名召回门未达，
  默认生产路径对"仅由 NER 检出的表面形式"维持 REVIEW_REQUIRED
  （用户词典逐面确认的事项仍可按 S4 语义 AUTO_READY）。
- 门槛若需调整，按卡 05-4 单独裁定，不用"基础路径不作可用宣称"话术掩盖。
- 异构复核、覆盖声明、scan_bytes、九步处置的工程实现与拒收反例全部落地，
  见 STATUS.json V42-R1 与 reports/v42/*.xml。

## 已核瓶颈（待裁清单）

1. 双语金标文档（doc 7-10、12-14）中的英文姓名/机构超出中文 CLUENER 能力，
   是 person/overall 缺口主体（21 个漏检中 12 个为拉丁表面形式）。
2. "王某/赵某"式匿名化当事人与"老张/小李"式称谓为中文法律文书高频形态，
   模型漏检；已由异构复核引擎兜底检出（反例测试固定）。
3. PROJECT 代号类金标（Orca/Nebula 等）本质上只能由用户词典命中，
   规则与通用 NER 不应宣称覆盖。
