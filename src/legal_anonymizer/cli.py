"""Command-line interface.

    vault-engine scrub  INFILE [-o OUT] [--map MAP] [--report REPORT] ...
    vault-engine rehydrate INFILE --map MAP [-o OUT]
    vault-engine providers
    vault-engine models
    vault-engine version

Use ``-`` for INFILE/OUT to read stdin / write stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, formats
from .config import POLICIES, Config
from .mapping import Vault
from .pipeline import deidentify, rehydrate
from .providers import available

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DEGRADED = 3   # ran, but a requested protection layer did not (under-redacted)

DEFAULT_CLIP_MAP = os.path.join(os.path.expanduser("~"), ".vault-engine",
                                "clip.map.json")


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _write(path: str, data: str) -> None:
    if path == "-":
        sys.stdout.write(data)
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)


def _default_out(infile: str) -> str:
    if infile == "-":
        return "-"
    stem, ext = os.path.splitext(infile)
    return f"{stem}.scrubbed{ext or '.txt'}"


def _config_from(args: argparse.Namespace) -> Config:
    overrides = {
        "provider": args.provider, "model": args.model,
        "endpoint": args.endpoint, "api_key": args.api_key,
        "policy": args.policy, "locale": args.locale,
        "use_llm": (False if args.no_llm else None),
        "critic": (False if args.no_critic else None),
    }
    return Config.load(path=args.config,
                       overrides={k: v for k, v in overrides.items()
                                  if v is not None})


def cmd_scrub(args: argparse.Namespace) -> int:
    text = _read(args.infile)
    config = _config_from(args)
    segs = formats.segment(text, args.format)
    result = deidentify(text, config, segments=segs)

    out = args.out or _default_out(args.infile)
    _write(out, result.text)

    # reverse map — local only, never for the cloud
    if not args.one_way:
        map_path = args.map or (
            "vault.map.json" if out == "-" else out + ".map.json")
        if map_path != "-":
            result.vault.save(map_path)
        else:
            sys.stdout.write("\n" + json.dumps(result.map, ensure_ascii=False))

    if args.report:
        _write(args.report, result.report.to_markdown())

    # always tell the human what happened (on stderr so stdout stays clean)
    print(result.report.summary(), file=sys.stderr)
    for w in result.report.warnings:
        print("  ⚠️ " + w, file=sys.stderr)
    if not args.one_way and out != "-":
        print(f"  脱敏文本 → {out}", file=sys.stderr)
        print(f"  反向映射 → {map_path}  （本地保存，切勿出云/入库）", file=sys.stderr)

    if not result.safe and not args.allow_degraded:
        print("✗ 请求的模型检测层未运行；输出可能脱敏不足。确认无碍可加 "
              "--allow-degraded。", file=sys.stderr)
        return EXIT_DEGRADED
    return EXIT_OK


def cmd_rehydrate(args: argparse.Namespace) -> int:
    payload = _read(args.infile)
    if getattr(args, "matter", None):
        from .application.rehydrate_service import RehydrateService

        svc = RehydrateService(Path(args.state_dir))
        if args.infile.lower().endswith(".docx") and args.infile != "-":
            result = svc.rehydrate_docx(args.matter, Path(args.infile),
                                        Path(args.out or (args.infile + ".restored.docx")))
            print(f"已回填 {result.replacements} 处假名 → {result.output_text}", file=sys.stderr)
            return EXIT_OK
        result = svc.rehydrate_text(args.matter, payload)
        _write(args.out or "-", result.output_text)
        if result.unmatched_aliases:
            print(
                "⚠ 以下假名在输出中仍存在（可能映射不完整）: "
                + ", ".join(result.unmatched_aliases),
                file=sys.stderr,
            )
            return 6
        print(f"已回填 {result.replacements} 处假名（matter 级）。", file=sys.stderr)
        return EXIT_OK
    if not args.map:
        print("✗ rehydrate 需要 --map（legacy）或 --matter（案件级）。", file=sys.stderr)
        return 4
    vault = Vault.load(args.map)
    try:                                   # structured reply: rehydrate in place
        obj = json.loads(payload)
        restored = json.dumps(rehydrate(obj, vault), ensure_ascii=False, indent=2)
    except json.JSONDecodeError:           # plain text reply
        restored = rehydrate(payload, vault)
    _write(args.out or "-", restored)
    if args.out and args.out != "-":
        print(f"已回填真实身份 → {args.out}", file=sys.stderr)
    return EXIT_OK


def cmd_clip(args: argparse.Namespace) -> int:
    """Scrub (or rehydrate) the clipboard in place — the paste-into-ChatGPT hook."""
    from . import clipboard
    map_path = args.map or DEFAULT_CLIP_MAP
    try:
        text = clipboard.read_clipboard()
    except clipboard.ClipboardError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return EXIT_ERROR
    if not text.strip():
        print("剪贴板为空。", file=sys.stderr)
        return EXIT_ERROR

    if args.rehydrate:
        vault = Vault.load(map_path)
        try:
            restored = json.dumps(rehydrate(json.loads(text), vault),
                                  ensure_ascii=False, indent=2)
        except json.JSONDecodeError:
            restored = rehydrate(text, vault)
        clipboard.write_clipboard(restored)
        print("✓ 剪贴板已用本地映射还原为真实身份。", file=sys.stderr)
        return EXIT_OK

    config = _config_from(args)
    segs = formats.segment(text, args.format)
    result = deidentify(text, config, segments=segs)
    clipboard.write_clipboard(result.text)
    if not args.one_way:
        os.makedirs(os.path.dirname(map_path), exist_ok=True)
        result.vault.save(map_path)

    print(result.report.summary(), file=sys.stderr)
    for w in result.report.warnings:
        print("  ⚠️ " + w, file=sys.stderr)
    print("✓ 剪贴板已脱敏，可直接粘贴给云端 AI。", file=sys.stderr)
    if not args.one_way:
        print(f"  反向映射 → {map_path}（本地保存，勿出云）", file=sys.stderr)
        print("  云端回复贴回剪贴板后，用 `vault-engine clip --rehydrate` 还原。",
              file=sys.stderr)
    if not result.safe and not args.allow_degraded:
        print("✗ 模型检测层未运行，可能脱敏不足（--allow-degraded 忽略）。", file=sys.stderr)
        return EXIT_DEGRADED
    return EXIT_OK


def cmd_providers(_args: argparse.Namespace) -> int:
    print("可用 provider：")
    notes = {"null": "离线确定性检测（默认，无网络路径）",
             "null": "纯正则离线（无模型，仅兜底）"}
    for name in available():
        print(f"  - {name:14s} {notes.get(name, '')}")
    return EXIT_OK


def cmd_models(args: argparse.Namespace) -> int:
    print("本工具不连接任何模型端点（S0 边界：无网络检测后端）。", file=sys.stderr)
    print("本地 NER/OCR 模型清单见 models/manifest.json；缺失即 fail-closed。", file=sys.stderr)
    return EXIT_ERROR


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"vault-engine {__version__}")
    return EXIT_OK


# -- S4 matter commands --------------------------------------------------------


def _default_state_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "LegalAnonymizer")


_EXIT_BY_STATUS = {
    "AUTO_READY": 0,
    "READY_BY_HUMAN": 0,
    "REVIEW_REQUIRED": 2,
    "CLOSED_BLOCK": 3,
    "ENGINE_ERROR": 5,
}


def cmd_project_init(args: argparse.Namespace) -> int:
    from .application.state import MatterState, MatterStateError

    try:
        MatterState(Path(args.state_dir), args.matter).init(args.profile)
    except MatterStateError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"✓ 案件 {args.matter} 已初始化（profile={args.profile}）")
    return EXIT_OK


def cmd_project_status(args: argparse.Namespace) -> int:
    from .application.state import MatterState, MatterStateError

    try:
        payload = MatterState(Path(args.state_dir), args.matter).read_public()
    except (MatterStateError, OSError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 4
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_project_export(args: argparse.Namespace) -> int:
    from .application.portable_service import PortableError, export_portable

    try:
        export_portable(Path(args.state_dir), args.matter, Path(args.portable))
    except PortableError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 6
    print(f"✓ 可迁移项目已导出 → {args.portable}", file=sys.stderr)
    return EXIT_OK


def cmd_project_import(args: argparse.Namespace) -> int:
    from .application.portable_service import PortableError, import_portable

    try:
        matter = import_portable(Path(args.state_dir), Path(args.portable))
    except PortableError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 6
    print(f"✓ 案件 {matter} 已导入", file=sys.stderr)
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    from .application.scan_service import ScanError, scan

    try:
        report = scan(Path(args.input_dir), args.matter)
    except ScanError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 4
    payload = report.to_payload()
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for d in report.documents:
            print(f"{d.document_id}  {d.format:8s} {d.size:>9d}B  {d.path}")
    return EXIT_OK


def _load_dictionary(path: str | None):
    from .adapters.recognizers.project_dictionary import ProjectDictionaryProvider

    if not path:
        return None
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return ProjectDictionaryProvider(
        blacklist=payload.get("blacklist", []),
        whitelist=payload.get("whitelist", []),
        aliases=payload.get("aliases", []),
    )


def cmd_sanitize(args: argparse.Namespace) -> int:
    from .application.sanitize_service import SanitizeService
    from .application.docx_pipeline import DocxSanitizeService

    dictionary = _load_dictionary(args.dictionary)
    svc = SanitizeService(Path(args.state_dir))
    result = svc.sanitize(args.matter, Path(args.input_dir), Path(args.out),
                          dictionary=dictionary)

    # DOCX inputs go through the OOXML pipeline (doc ids continue the scan order)
    docx_files = sorted(
        p for p in Path(args.input_dir).rglob("*.docx") if not p.name.startswith("~$")
    )
    docx_status = None
    pdf_status = None
    if docx_files:
        docx_svc = DocxSanitizeService(Path(args.state_dir))
        start_index = len(result.documents) + 1
        for offset, p in enumerate(docx_files):
            doc_id = f"doc-{start_index + offset:03d}"
            docx_result = docx_svc.sanitize_docx(
                args.matter, p, Path(args.out), doc_id, dictionary=dictionary
            )
            docx_status = docx_result.status
            for r in docx_result.review_reasons:
                result.review_reasons.append(f"{doc_id}:{r}")

    pdf_files = sorted(
        p for p in Path(args.input_dir).rglob("*.pdf") if not p.name.startswith("~$")
    )
    if pdf_files:
        from .application.pdf_pipeline import PdfSanitizeService

        pdf_svc = PdfSanitizeService(Path(args.state_dir))
        start_index = len(result.documents) + len(docx_files) + 1
        for offset, p in enumerate(pdf_files):
            doc_id = f"doc-{start_index + offset:03d}"
            pdf_result = pdf_svc.sanitize_pdf(
                args.matter, p, Path(args.out), doc_id, dictionary=dictionary
            )
            pdf_status = pdf_result["status"]
            for r in pdf_result["review_reasons"]:
                result.review_reasons.append(f"{doc_id}:{r}")

    if args.json:
        print(json.dumps(result.receipt or {"status": result.status}, ensure_ascii=False, indent=2))
    else:
        worst = result.status
        if docx_status == "CLOSED_BLOCK":
            worst = "CLOSED_BLOCK"
        elif docx_status == "REVIEW_REQUIRED" and worst == "AUTO_READY":
            worst = "REVIEW_REQUIRED"
        print(f"状态: {worst}")
        for r in result.review_reasons:
            print(f"  复核原因: {r}")
        if result.receipt_path:
            print(f"回执: {result.receipt_path}")
    exit_code = result.exit_code
    if docx_status == "CLOSED_BLOCK" or pdf_status == "CLOSED_BLOCK":
        exit_code = 3
    elif (docx_status == "REVIEW_REQUIRED" or pdf_status == "REVIEW_REQUIRED") and exit_code == 0:
        exit_code = 2
    return exit_code


def cmd_review_issue(args: argparse.Namespace) -> int:
    from .application.review_service import ReviewError, issue_review_receipt, load_decisions

    try:
        decisions = load_decisions(Path(args.decisions)) if args.decisions else {
            "matter_id": args.matter, "decisions": []
        }
        receipt = issue_review_receipt(
            Path(args.state_dir), args.matter, Path(args.out_dir),
            decisions, args.reviewer, args.role,
        )
    except (ReviewError, OSError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 4
    if args.json:
        print(json.dumps(receipt, ensure_ascii=False, indent=2))
    else:
        print(f"✓ 人工复核回执已签发 → {Path(args.out_dir) / 'receipts' / 'human-review-receipt.json'}")
    return EXIT_OK


def cmd_bundle_consumer_protocol(args: argparse.Namespace) -> int:
    from .application.consumer_protocol import build_consumer_protocol

    result = build_consumer_protocol(Path(args.state_dir), Path(args.out))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_bundle_harness(args: argparse.Namespace) -> int:
    from .application.consumer_bundle_service import build_harness_handoff

    try:
        result = build_harness_handoff(
            Path(args.state_dir), args.matter, Path(args.out),
            source_dir=Path(args.source_out) if args.source_out else None,
        )
    except Exception as exc:  # noqa: BLE001 - HandoffError/ReviewError/MatterStateError
        print(f"✗ {exc}", file=sys.stderr)
        return 3
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_verify_consumer_bundle(args: argparse.Namespace) -> int:
    from tests.consumer.mock_consumer import verify_consumer_bundle

    ok, reason = verify_consumer_bundle(
        Path(args.bundle_dir), Path(args.protocol_dir) if args.protocol_dir else None
    )
    print(json.dumps({"result": ok, "reason": reason}, ensure_ascii=False, indent=2))
    return 0 if ok == "ACCEPTABLE_FOR_IMPORT" else 3


def cmd_verify(args: argparse.Namespace) -> int:
    from .application.verify_service import VerifyService

    result = VerifyService(Path(args.state_dir)).verify(args.matter, Path(args.out_dir))
    if args.json:
        print(json.dumps(
            {"status": result.status, "gates": result.gates,
             "residual_counts": result.residual_counts},
            ensure_ascii=False, indent=2))
    else:
        print(f"状态: {result.status}")
        for gate, outcome in result.gates.items():
            print(f"  {gate}: {outcome}")
    return result.exit_code


def _add_model_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--provider", help="null(默认；本工具不提供网络检测后端)")
    p.add_argument("--model", help="模型 tag，默认 qwen3.6:27b")
    p.add_argument("--endpoint", help="provider 端点 URL")
    p.add_argument("--api-key", dest="api_key", help="远程端点的 API key")
    p.add_argument("--config", help="JSON 配置文件路径（亦读 VAULT_* 环境变量）")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault-engine",
        description="出云前的身份脱敏：本地检测 + 一致化假名 + 可逆回路（默认本地模型）。")
    parser.add_argument("--version", action="version",
                        version=f"vault-engine {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scrub", help="脱敏一个文件/标准输入")
    s.add_argument("infile", help="输入文件（- 表示 stdin）")
    s.add_argument("-o", "--out", help="脱敏输出（默认 <name>.scrubbed.<ext>；- 表示 stdout）")
    s.add_argument("--map", help="反向映射保存路径（默认 <out>.map.json）")
    s.add_argument("--report", help="把完整风险报告写到此路径")
    s.add_argument("--format", choices=formats.FORMATS, default=formats.AUTO,
                   help="plain / markdown(保护 ``` 代码块) / auto(默认)")
    s.add_argument("--policy", choices=POLICIES, help="脱敏力度，默认 balanced")
    s.add_argument("--locale", help="zh(默认) / en：正则集与 prompt 语言")
    s.add_argument("--no-llm", action="store_true", help="仅正则、不调模型（离线兜底）")
    s.add_argument("--no-critic", action="store_true", help="跳过残留风险复审")
    s.add_argument("--one-way", action="store_true",
                   help="单向发布模式：不产出反向映射（不可回填）")
    s.add_argument("--allow-degraded", action="store_true",
                   help="即便模型层未运行也以 0 退出")
    _add_model_flags(s)
    s.set_defaults(func=cmd_scrub)

    r = sub.add_parser("rehydrate", help="回填：映射文件（legacy）或案件状态（--matter）二选一")
    r.add_argument("infile", help="云端回复（- 表示 stdin）")
    r.add_argument("--map", default=None, help="legacy: scrub 时产出的 *.map.json")
    r.add_argument("--matter", default=None, help="matter 级回填：使用案件私有状态")
    r.add_argument("--state-dir", default=_default_state_dir())
    r.add_argument("-o", "--out", help="输出路径（默认 stdout）")
    r.set_defaults(func=cmd_rehydrate)

    c = sub.add_parser("clip", help="脱敏剪贴板内容（贴进 ChatGPT 前一键洗）")
    c.add_argument("--rehydrate", action="store_true",
                   help="反向：用映射把剪贴板里的代号还原成真实身份")
    c.add_argument("--map", help=f"映射路径（默认 {DEFAULT_CLIP_MAP}）")
    c.add_argument("--format", choices=formats.FORMATS, default=formats.AUTO)
    c.add_argument("--policy", choices=POLICIES, help="脱敏力度，默认 balanced")
    c.add_argument("--locale", help="zh(默认) / en")
    c.add_argument("--no-llm", action="store_true", help="仅正则、不调模型")
    c.add_argument("--no-critic", action="store_true", help="跳过残留风险复审")
    c.add_argument("--one-way", action="store_true", help="不产出反向映射")
    c.add_argument("--allow-degraded", action="store_true",
                   help="即便模型层未运行也以 0 退出")
    _add_model_flags(c)
    c.set_defaults(func=cmd_clip)

    sub.add_parser("providers", help="列出可用大模型 provider").set_defaults(
        func=cmd_providers)

    m = sub.add_parser("models", help="列出本地 Ollama 已安装模型")
    m.add_argument("--endpoint", help="Ollama 端点，默认 http://localhost:11434")
    m.set_defaults(func=cmd_models)

    sub.add_parser("version", help="打印版本").set_defaults(func=cmd_version)

    # -- S4 matter commands ----------------------------------------------------

    p = sub.add_parser("project", help="案件项目管理（init/status）")
    p_sub = p.add_subparsers(dest="project_command", required=True)
    pi = p_sub.add_parser("init", help="初始化案件状态")
    pi.add_argument("--matter", required=True)
    pi.add_argument("--profile", default="cn-ai-safe-v1")
    pi.add_argument("--state-dir", default=_default_state_dir())
    pi.set_defaults(func=cmd_project_init)
    ps = p_sub.add_parser("status", help="查看案件状态")
    ps.add_argument("--matter", required=True)
    ps.add_argument("--state-dir", default=_default_state_dir())
    ps.set_defaults(func=cmd_project_status)
    pe = p_sub.add_parser("export", help="导出可迁移项目（.lapx，Scrypt+AES-GCM）")
    pe.add_argument("--matter", required=True)
    pe.add_argument("--portable", required=True)
    pe.add_argument("--state-dir", default=_default_state_dir())
    pe.set_defaults(func=cmd_project_export)
    pim = p_sub.add_parser("import", help="导入可迁移项目（密码经 getpass 输入）")
    pim.add_argument("--portable", required=True)
    pim.add_argument("--state-dir", default=_default_state_dir())
    pim.set_defaults(func=cmd_project_import)

    sc = sub.add_parser("scan", help="扫描材料目录并分配 doc-xxx 稳定编号")
    sc.add_argument("input_dir")
    sc.add_argument("--matter", required=True)
    sc.add_argument("--state-dir", default=_default_state_dir())
    sc.add_argument("--json", action="store_true", help="稳定 JSON 输出")
    sc.set_defaults(func=cmd_scan)

    sa = sub.add_parser("sanitize", help="案件级脱敏：识别→归并→假名化→报告→签名回执")
    sa.add_argument("input_dir")
    sa.add_argument("--matter", required=True)
    sa.add_argument("--out", required=True)
    sa.add_argument("--profile", default=None, help="仅当与 project init 不同时报错拦截")
    sa.add_argument("--state-dir", default=_default_state_dir())
    sa.add_argument("--dictionary", default=None, help="项目词典 JSON（blacklist/whitelist/aliases）")
    sa.add_argument("--json", action="store_true")
    sa.set_defaults(func=cmd_sanitize)

    ve = sub.add_parser("verify", help="独立验收：隐私/完整性/效用 Gate + 签名验收回执")
    ve.add_argument("out_dir")
    ve.add_argument("--matter", required=True)
    ve.add_argument("--state-dir", default=_default_state_dir())
    ve.add_argument("--json", action="store_true")
    ve.set_defaults(func=cmd_verify)

    rv = sub.add_parser("review", help="签发人工复核回执（绑定当前产物集合）")
    rv.add_argument("out_dir")
    rv.add_argument("--matter", required=True)
    rv.add_argument("--state-dir", default=_default_state_dir())
    rv.add_argument("--decisions", help="决定文件（JSON/YAML）")
    rv.add_argument("--reviewer", required=True, help="复核人标识（如 Windows SID）")
    rv.add_argument("--role", required=True,
                    choices=["UPLOADING_LAWYER", "MATTER_LEAD", "DESIGNATED_REVIEWER"])
    rv.add_argument("--json", action="store_true")
    rv.set_defaults(func=cmd_review_issue)

    bl = sub.add_parser("bundle", help="生成交付包（consumer-protocol / legal-harness）")
    bl_sub = bl.add_subparsers(dest="bundle_command", required=True)
    bc = bl_sub.add_parser("consumer-protocol", help="生成外部消费者协议包")
    bc.add_argument("--out", required=True)
    bc.add_argument("--state-dir", default=_default_state_dir())
    bc.set_defaults(func=cmd_bundle_consumer_protocol)
    bh = bl_sub.add_parser("legal-harness", help="生成 Legal Harness 交接包（仅脱敏器侧）")
    bh.add_argument("--matter", required=True)
    bh.add_argument("--out", required=True)
    bh.add_argument("--source-out", help="sanitize 输出目录（含 receipts/sanitized）")
    bh.add_argument("--state-dir", default=_default_state_dir())
    bh.set_defaults(func=cmd_bundle_harness)

    vb = sub.add_parser("verify-consumer-bundle", help="离线校验交接包（内置模拟消费者逻辑）")
    vb.add_argument("bundle_dir")
    vb.add_argument("--protocol-dir", help="consumer protocol 包根目录")
    vb.set_defaults(func=cmd_verify_consumer_bundle)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
