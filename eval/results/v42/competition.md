# CLUENER vs GLiNER 竞速实测（v4.2 卡 05-1）

- 数据集: v42-synthetic @ 146cff21d12ff455 （合成，冻结）
- 机器: {'system': 'Windows 11', 'machine': 'AMD64', 'python': '3.12.10', 'cpu_count': 12, 'pinned_threads': 4, 'torch': '2.14.0+cpu', 'transformers': '4.57.6', 'presidio_analyzer': 'installed'}

| 引擎 | person 召回 | org 召回 | location 召回 | 范围内总体 | 误遮盖(非敏感字符) | p50/p95 | 峰值RSS | 状态 |
|---|---|---|---|---|---|---|---|---|
| race-cluener | 61.8% (21/34) | 57.1% (12/21) | 72.2% (13/18) | 63.0% (46/73) | 1.2% (14/1184) | 74.7 / 124.8 ms | 1107.9 MB | MEASURED |
| race-gliner | 26.5% (9/34) | 38.1% (8/21) | 27.8% (5/18) | 30.1% (22/73) | 6.0% (71/1184) | 211.0 / 275.0 ms | 2035.3 MB | MEASURED |

选择规则（05-1）：实际发布配置整体召回≥90%、person召回≥90%、误遮盖≤5%；
通过者优先 person 召回，再比较 p95。本表为 NER 引擎在 person/org/location 范围内的
竞速实测；发布门以 v42-release-default.json（规则+NER 全栈）报告为准。
论文/模型卡 F1 数字不充当本机成绩。

## 结论（按 05-1 规则，全部为冻结集实测，与本报告同轮生成）

1. 两引擎均未通过发布门（person 召回门 90%）：CLUENER 61.8%，GLiNER2 26.5%。
   无一"通过"，故不产生"通过者优先"比较；生产位由机制可用性决定：
   **生产位 = 规则 + CLUENER**（registry 默认构造），GLiNER2 落选竞速。
2. 异构复核引擎 = gliner_medium-v2.1（零样本跨编码器，与 CLUENER token-classification
   不同模型家族与解码机制，实测能检出 CLUENER 漏检的"王某/赵某"类匿名化当事人，
   见 tests/recognizers/test_production_heterogeneous_v42.py 反例）。
3. 误遮盖门内唯一达标者亦为 CLUENER（1.2% ≤5%；GLiNER2 6.0% 超门）。
   CLUENER 表面形式过滤规则：无 CJK 字符的检出（如把英文单词 "ignore" 标为机构）
   按模型噪声丢弃——丢弃前 person"召回"76.5% 中含双语金标文档的偶然命中，
   丢弃后为真实中文能力 61.8%，误遮盖 4.9%→1.2%。两版数字都记录于此，
   不以后者掩盖前者的成因。
4. 延迟预算（1000 中文字符 CPU p95≤2s）：CLUENER p95 124.8ms，通过。
   瓶颈记录：金标双语文档（doc 7-10/12-14 英文姓名/机构）超出中文模型能力，
   project 代号类金标需要用户词典；这两类是 90% 门未达的主要构成，
   属"待裁阈值/待扩规则"项，不擅自删竞速或改门。
5. 发布资格：models/manifest.json ner.qualified 保持 false，
   非词典确认事项维持 REVIEW_REQUIRED；不得引用本表之外的论文数字。
