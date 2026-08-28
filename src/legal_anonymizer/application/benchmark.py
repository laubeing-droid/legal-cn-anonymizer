"""Synthetic benchmark: fully synthetic Chinese legal corpus, mechanical
metrics, honest reporting. No real client data, no fabricated recall."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..adapters.documents.pdf.pdfium_parser import PdfInputError
from .rehydrate_service import RehydrateService
from .sanitize_service import SanitizeService
from .scan_service import ScanError
from .state import MatterState
from .verify_service import VerifyService
from ..adapters.recognizers.project_dictionary import ProjectDictionaryProvider
from ..domain.utility_snapshot import legal_date_multiset, money_multiset

BENCHMARK_ID = "SYN-BENCH-001"

# fully synthetic surfaces (invalid checksums on purpose so they are never
# mistaken for real data; the recognizer rules still catch them via regex +
# dictionary evidence)
PEOPLE = ["林晚秋", "程铁生", "邵一鸣", "沈孤鸿", "苗翠山"]
ORGS = ["云澜建设集团有限责任公司", "汀洲机械制造有限公司", "青崖律师事务所"]
PROJECTS = ["澜沧江畔安置房项目", "汀洲旧厂房改造工程"]
PHONES = ["13700001111", "13900002222"]
EMAILS = ["lin.wanqiu@example.test", "cheng.tiesheng@example.test"]


def _corpus_documents() -> list[tuple[str, str]]:
    docs = []
    docs.append(
        (
            "建工合同.md",
            "# 建设工程施工合同\n\n"
            f"发包人：{ORGS[0]}（简称云澜集团）\n承包人：{ORGS[1]}\n"
            f"项目负责人{PEOPLE[0]}，联系电话{PHONES[0]}，邮箱{EMAILS[0]}。\n"
            f"工程名称：{PROJECTS[0]}。合同总价人民币12,000,000.00元，"
            "进度款7,200,000.00元，质保金600,000.00元。\n"
            "2023年3月1日开工，2024年8月15日竣工验收，2024年9月1日交付使用。\n",
        )
    )
    docs.append(
        (
            "起诉状.md",
            "# 民事起诉状\n\n"
            f"原告{PEOPLE[1]}，被告{ORGS[0]}。\n"
            f"诉讼请求：支付拖欠工程款3,000,000.00元及利息（按年利率4.35%计算）。\n"
            f"事实与理由：{PEOPLE[2]}作为现场代表确认工程量。证据一至证据五。\n",
        )
    )
    docs.append(
        (
            "证据目录.md",
            "# 证据目录\n\n"
            f"1. 建设工程施工合同（{ORGS[0]}与{ORGS[1]}）。\n"
            "2. 付款凭证：2023年6月10日付款2,000,000.00元；2023年12月20日付款1,500,000.00元。\n"
            f"3. 微信聊天记录：{PEOPLE[3]}与{PEOPLE[4]}关于{PROJECTS[1]}的工期协商。\n"
            "4. 判决书：（2023）闽0602民初5678号。\n",
        )
    )
    docs.append(
        (
            "微信记录.md",
            "# 微信聊天导出\n\n"
            f"{PEOPLE[3]}：工期太紧了。\n{PEOPLE[4]}：{PROJECTS[1]}下月必须封顶，款项1,800,000.00元周五前付。\n"
            f"{PEOPLE[3]}：账户6222020200112233收到2,000,000.00元了。\n",
        )
    )
    docs.append(
        (
            "银行流水.md",
            "# 银行流水\n\n"
            "2023-06-10 转入 2,000,000.00元 备注：工程款\n"
            "2023-12-20 转入 1,500,000.00元 备注：进度款\n"
            "2024-01-15 转出 300,000.00元 备注：材料款\n",
        )
    )
    return docs


@dataclass
class BenchmarkMetrics:
    documents: int = 0
    critical_identifier_occurrences: int = 0
    critical_identifier_misses: int = 0
    subject_mentions: int = 0
    subject_misses: int = 0
    money_multiset_failures: int = 0
    legal_date_multiset_failures: int = 0
    roundtrip_failures: int = 0
    document_count_mismatches: int = 0
    notes: list[str] = field(default_factory=list)

    def to_payload(self) -> dict:
        return {
            "benchmark_id": BENCHMARK_ID,
            "synthetic_only": True,
            "documents": self.documents,
            "critical_identifier_occurrences": self.critical_identifier_occurrences,
            "critical_identifier_misses": self.critical_identifier_misses,
            "critical_identifier_miss_rate": (
                self.critical_identifier_misses / self.critical_identifier_occurrences
                if self.critical_identifier_occurrences else 0.0
            ),
            "subject_mentions": self.subject_mentions,
            "subject_misses": self.subject_misses,
            "money_multiset_failures": self.money_multiset_failures,
            "legal_date_multiset_failures": self.legal_date_multiset_failures,
            "roundtrip_failures": self.roundtrip_failures,
            "document_count_mismatches": self.document_count_mismatches,
            "ner_auto_release_qualified": False,
            "note": "Person/Org recall is measured against the user-dictionary baseline only; no NER recall number is claimed.",
        }


def _ground_truth_identifiers() -> list[str]:
    return PHONES + EMAILS


class BenchmarkRunner:
    def __init__(self, state_root: Path):
        self.state_root = Path(state_root)

    def run(self, base_dir: Path) -> BenchmarkMetrics:
        base_dir = Path(base_dir)
        input_dir = base_dir / "corpus"
        out_dir = base_dir / "out"
        input_dir.mkdir(parents=True, exist_ok=True)
        for name, text in _corpus_documents():
            (input_dir / name).write_text(text, encoding="utf-8")

        matter_id = "bench-001"
        if not (self.state_root / matter_id / "private.dpapi").exists():
            MatterState(self.state_root, matter_id).init("cn-ai-safe-v1")

        dictionary = ProjectDictionaryProvider(
            blacklist=(
                [{"value": p, "type": "PERSON"} for p in PEOPLE]
                + [{"value": o, "type": "LEGAL_PERSON"} for o in ORGS]
                + [{"value": o, "type": "LEGAL_PERSON"} for o in ["云澜集团"]]
                + [{"value": p, "type": "PROJECT"} for p in PROJECTS]
            ),
            aliases=[
                {"canonical": ORGS[0], "values": [ORGS[0], "云澜集团"], "type": "LEGAL_PERSON"},
            ],
        )
        result = SanitizeService(self.state_root).sanitize(
            matter_id, input_dir, out_dir, dictionary=dictionary
        )
        verify = VerifyService(self.state_root).verify(matter_id, out_dir)

        metrics = BenchmarkMetrics(documents=len(_corpus_documents()))
        # ground truth: every identifier occurrence must be transformed
        for name, text in _corpus_documents():
            for ident in _ground_truth_identifiers():
                metrics.critical_identifier_occurrences += text.count(ident)
        sanitized_text = "\n".join(
            f.read_text(encoding="utf-8") for f in sorted((out_dir / "sanitized").glob("doc-*.ai.md"))
        )
        for ident in _ground_truth_identifiers():
            metrics.critical_identifier_misses += sanitized_text.count(ident)
        # subject baseline: dictionary surfaces must all be replaced
        for surface in PEOPLE + ORGS + PROJECTS:
            occurrences = sum(
                text.count(surface) for _n, text in _corpus_documents()
            )
            if occurrences:
                metrics.subject_mentions += occurrences
                metrics.subject_misses += sanitized_text.count(surface)
        # utility multisets per document
        for i, (name, text) in enumerate(_corpus_documents(), start=1):
            report_path = out_dir / "reports" / f"doc-{i:03d}.report.json"
            if not report_path.exists():
                continue
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            out_text = (out_dir / "sanitized" / f"doc-{i:03d}.ai.md").read_text(encoding="utf-8")
            if payload.get("money_multiset") and money_multiset(out_text) != sorted(payload["money_multiset"]):
                metrics.money_multiset_failures += 1
            if payload.get("legal_date_multiset") and legal_date_multiset(out_text) != sorted(payload["legal_date_multiset"]):
                metrics.legal_date_multiset_failures += 1
        # roundtrip: rehydrate restores every subject surface
        rehydrate = RehydrateService(self.state_root)
        restored = rehydrate.rehydrate_text(matter_id, sanitized_text)
        for surface in PEOPLE + ORGS + PROJECTS:
            count_original = sum(text.count(surface) for _n, text in _corpus_documents())
            count_restored = restored.output_text.count(surface)
            if count_original != count_restored:
                metrics.roundtrip_failures += 1
        if verify.gates["completeness"] == "FAIL":
            metrics.document_count_mismatches += 1
        metrics.notes.append(f"sanitize status: {result.status}; verify status: {verify.status}")
        return metrics
