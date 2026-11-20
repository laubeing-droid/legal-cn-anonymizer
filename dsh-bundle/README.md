# @legal-cn-anonymizer/dsh-bundle

legal-cn-anonymizer 的 **DSH bundle 四件套**（服务 + defineTool + fetch.register +
client panel），样板 = juscite-engine `packages/juscite/{cases,redaction}`（issue #10
Part A「anonymizer = DSH bundle 形态」落点；模块化铁律 2「独立能力域替换件」正例）。

## 能力面（只走公开 CLI，零实现知识）

| 面 | 内容 |
|---|---|
| 服务 | `createAnonymizerService(config)`：scrub/rehydrate 各一次一发（spawn `pythonLauncher -m legal_anonymizer`，stdin→stdout 管道）；映射 map/report 由 anonymizer 进程直写本侧 vault 目录——**身份映射永不出 anonymizer 侧**（安全边界 #2 不重开） |
| defineTool | `pii_scrub_text`（文本脱敏）/ `pii_rehydrate_text`（假名文本回填；mapHandle 闭集 + vault 目录 containment，拒任意路径读） |
| fetch.register | `/api/legal-cn-anonymizer/{state,scrub,rehydrate}`——**双宿主探测**：Juscite runtime 宿主服务键闭集无 connection → try/catch 具名跳过（不静默近似）；DSH 生态 Loader 上同路径真挂 |
| client panel | `exports["./client"]`（`window.__ModuleLoader__.load` wire，dsh-context@0.86.0 形状）：侧栏「隐私脱敏」说明页 + `pii_scrub_text` 工具卡视图，只消费 `ds-*` 语义令牌 |

## 诚实边界

- `--no-llm --no-critic` 口径 = **正则层离线兜底**：身份证号/手机号/银行卡/邮箱等
  结构化实体可命中；**姓名等 NER 实体不保证命中**（NER 2.7GB 权重不随包，
  `ner.qualified=false` 时姓名覆盖 = REVIEW_REQUIRED 人工复核兜底）。
- 永不输出 SAFE / 100% ANONYMIZED（NOTICE 状态枚举声明同源）。
- 退出码契约（公开文档）：0 ok / 3 degraded / 6 存在未回填假名 / 其余 error。

## Config（patch 行 config → env 兜底）

| 键 | 缺省链 |
|---|---|
| `anonymizerRoot` | config → `JUSCITE_ANONYMIZER_ROOT`（入口预检：`src/legal_anonymizer/__init__.py` 存在性） |
| `pythonLauncher` | config → `JUSCITE_PYTHON_LAUNCHER` → win `py -3` / POSIX `python3` |
| `vaultDir` | config → `JUSCITE_ANONYMIZER_VAULT` → `~/.legal-cn-anonymizer/dsh-vault` |
| `timeoutMs` | config（缺省 120000） |

## 验收（juscite 侧探针）

`probes/probe-b10-anonymizer-dsh-bundle.mjs`（juscite 仓）：S1 合成夹具段（默认跑，
bundle 形状在批2-01 宿主真实装载 + stub CLI 全链）+ S2 真仓段（`JUSCITE_PROBE_
ANONYMIZER_ROOT` 显式开启：真 bundle 装载 + 真 `py -3` CLI scrub→rehydrate 文本面
往返）。注：rehydrate `_read()` 一行缺陷修的 DOCX 分支回归面在 anonymizer 仓自身
`tests/docx/test_docx_pipeline.py::test_cli_docx_rehydrate_dispatch`（本 bundle 文本
面不载 docx 分支；修复随 wheel 同步入链）。
