# V42-R2 交接文档（zcode 接手用）

会话基线：分支 `feat/s0-s12-local-egress`，HEAD `3cf4454`（V42-R1），工作树干净，
`reports/v42/regression.xml` 248 passed / 0 failed / 0 skipped。
本文件只记**代码和 STATUS.json 里看不出来的事实与欠账**；工程语义先读
`docs/construction/S0-S12-STATUS.md` 的 V42-R1 节与 `eval/results/v42/competition.md`。

## 一、机器与依赖事实（换环境前必读）

| 项 | 钉定值 |
|---|---|
| Python | 3.12.10（系统解释器，仓已 editable 安装） |
| presidio-analyzer | 2.2.364（自带 HuggingFaceNerRecognizer/GLiNERRecognizer） |
| spacy / zh_core_web_sm | 3.8.16 / 3.8.0（pkuseg 分词已装） |
| transformers / tokenizers | **4.57.6 / 0.22.2**（`spacy-huggingface-pipelines` 0.0.4 强制降自 5.x；transformers 5 未验证） |
| torch | 2.14.0+cpu |
| gliner | 0.2.29 —— **只准加载** `urchade/gliner_medium-v2.1`（异构复核引擎） |
| gliner2 | 2.0.0（+peft、accelerate）—— **只准加载** `fastino/gliner2-base-v1`；两包互换会静默退化成整句垃圾输出，两次复现过 |
| 模型权重 | `models/ner/`（2.7GB，gitignored）；revision+sha256 锁在 `models/manifest.json → ner.release_models`；运行时 `HF_HUB_OFFLINE=1` 由 recognizer 内部 setdefault |
| LLM | 本机无 Ollama，`release-llm` 轨固定 exit 4（CLOSED_BLOCK/model_missing） |
| 代理 | 装包/HF 下载走 `HTTPS_PROXY=http://127.0.0.1:10808`；仅施工期可用，产品运行期零网络 |

## 二、V42-R1 已知边界（设计使然，不是 bug）

- CLUENER 生产层丢弃"表面无 CJK 字符"的检出（英文词误标机构）。代价：双语金标
  偶然命中消失，person 76.5%→61.8%、误遮盖 4.9%→1.2%；两版数字都在
  competition.md，别把 61.8% 当回退去"修"。
- `ner.qualified=false`：所有仅靠 NER 检出的事项停在 REVIEW_REQUIRED；
  词典逐面确认的事项仍可 AUTO_READY（`sanitize_service.ner_honesty_review` 是
  四链共用门，改它=改发布语义，慎重）。
- verify 的 `_VERIFIER_MIN_CONFIDENCE=0.5` 是卡着"王某/赵某"反例下限定的
  （该反例跨度分 0.558）；调高会杀死残差测试。
- VerifyService 默认构造会起 RecognizerRegistry（懒加载，但会做资产哈希校验），
  单次 verify 进程内 GLiNER v2.1 约 5s 加载、峰值 RSS ≈1.1–1.6GB。

## 三、欠账清单（按优先级）

1. **桥在等三个不存在的模块**（`jusbench-repo/bridge/jusbench_bridge/providers.py:760`
   直接 import，失败则整个 anonymizer 路由表为空）：
   - `legal_anonymizer.application.pii_scan_service.scan_release_payload(request, timeout_seconds=…)`
     （错误要用带 `.code` 字符串属性的异常，桥按 `getattr(err,"code")` 转 RpcError）；
   - `legal_anonymizer.application.ingest_service`：`ingest_submit(state_root,
     sourceRefs, parserProfileRef)` / `ingest_status|cancel|resume(state_root, job_id)`；
   - `consumer_bundle_service.build_harness_handoff` 不接受桥传的
     `manifest=`、`source_dir=` 之外的 kwargs → 现签名只有 `(state_root, matter_id,
     out_dir, source_dir)`，桥会 TypeError。disposal 两函数已按桥签名落地（本波）。
   这三项属卡 05"pii 扫描服务化/摄取轨"，归后续波次；动工前先读桥代码取准契约，
   不要按本仓猜测设计。
2. **发布工件未随新代码重建**：`dist/` 的 SBOM/provenance/SHA256SUMS/
   acceptance-report 还是 S12 旧版，未含新 schema 与 extras；
   `THIRD_PARTY_NOTICES.md` 尚无 CLUENER(MIT)、GLiNER(Apache-2.0)、
   zh_core_web_sm 再分发记录（manifest 注释里提了 redistribution，文件本体没写）。
   重建走 S12 原 tools 流程。
3. **人名 90% 门未达（21/34）**，三条候选路线待用户裁定：
   a) 扩中文当事人确定性规则（`X某`/`老X`/`小X`/称谓式——注意误遮盖 5% 预算）；
   b) 用户词典运营侧补强；
   c) 微调或换中文 NER（需先例外的联网窗口+许可核验）。改门槛本身必须单独裁定。
4. **卡 05-4"现有 W15c-A 13 例 test_disposal.py"不存在**（全工作区检索过）；
   本波直接交付产品九步测试，主仓卡片该前提需要修正或补登。
5. **出域回执与消费门在别仓**：EgressReceipt/trustedConfigCheck 生产实现归 01
   主进程；02/06/07 消费拒收落位（jobs.py/trust.py/pii.py）不在本仓，A 侧只有
   测试内参考实现（tests/contract/test_coverage_refusal_v42.py 的
   `consumer_trusted_check`），别在本仓"顺手实现"。
6. **消费机离线装配**：模型 2.7GB 需预装并有装机脚本（现在只有 manifest 锁与
   `eval/README` 级口头步骤）；写 `scripts/` 时同步 S12 打包边界（wheel 不带权重）。
7. CLI 未暴露 `scan-bytes` 子命令（当前只有 Python 入口 scan_bytes_service）。
8. 时延门"1000 中文字符 p95≤2s"目前按平均 ≈90 字/文档实测（p95 124.8ms）；
   长文档单基准未跑。

## 四、复现与验收命令（cwd=仓根）

```text
python -B -m pytest -q -p no:cacheprovider tests --junitxml=reports/v42/regression.xml
python eval/evaluate_release.py --config eval/fixtures/v42-release-default.json --no-llm --output eval/results/v42/release-default.json   # 预期 exit 2（门未达）
python eval/evaluate_release.py --config eval/fixtures/v42-cluener.json --no-llm --output eval/results/v42/cluener.json
python eval/evaluate_release.py --config eval/fixtures/v42-gliner.json --no-llm --output eval/results/v42/gliner.json
python eval/evaluate_release.py --competition eval/results/v42/cluener.json eval/results/v42/gliner.json --out eval/results/v42/competition.md
python eval/run_eval.py --with-presidio --policy balanced --timeout 600 --out eval/results/v42/legacy-baseline.md
python -B -m pytest tests/recognizers/test_production_heterogeneous_v42.py tests/contract/test_coverage_refusal_v42.py -q --junitxml=reports/v42/coverage.xml
python -B -m pytest tests/jusbench/test_disposal_product_v42.py -q --junitxml=reports/v42/product-disposal.xml
python tools/build_schemas.py   # schema 唯一生成器，手改 JSON 会被覆盖
```

数据集冻结在 `eval/fixtures/v42-synthetic.jsonl`（rev `146cff21…`）+
`v42-synthetic.manifest.json` 逐文档哈希；改任何一行=换 benchmark revision，
覆盖声明与门判定必须重跑。

## 五、红线重申（本仓 AGENTS.md 之外、本轮实际踩过的）

- 不 commit 模型权重（`.gitignore models/ner/` 已设，别开洞）；
- 评测数字只报实测，禁止引论文 F1；改阈值要单独裁定；
- ruff 基线本就不干净（历史 329 项），只清自己触碰的文件；
- 不 push、不打 tag、不发 Release（本波未做，等用户明确授权）；
- 桥/legal-harness/juris-calculus 的内部一律不改，只按公开入口对齐本仓签名。
