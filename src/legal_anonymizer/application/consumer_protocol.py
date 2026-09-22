"""Consumer protocol pack builder: schemas, signed examples, negative fixtures,
public key, signed contract manifest, SHA256SUMS and README. The pack lets any
offline consumer verify handoff bundles without this codebase."""

from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path

from ..contracts.consumer_manifest import (
    build_manifest,
    export_public_key,
    PUBLIC_SCHEMAS,
)
from ..contracts.canonical import canonical_hash
from .consumer_bundle_service import build_harness_handoff
from .review_service import issue_review_receipt
from .state import MatterState
from .sanitize_service import SanitizeService
from ..adapters.recognizers.project_dictionary import ProjectDictionaryProvider
from ..security.receipt_identity import ReceiptIdentity

DEMO_MATTER = "proto-demo"
DEMO_CONTRACT = (
    "# 建设工程施工合同\n\n"
    "发包人：暮云置业有限公司（以下简称“暮云置业”）\n"
    "承包人：青崖律师事务所（受托处理工程结算争议）\n\n"
    "项目负责人秦岭（联系电话13700009999，邮箱 qinling@example.test），"
    "工程名称：暮云江畔安置房项目。合同总价人民币8,000,000.00元。"
    "2023年9月1日开工，2024年6月30日竣工。\n"
)

DEMO_DICTIONARY = ProjectDictionaryProvider(
    blacklist=[
        {"value": "秦岭", "type": "PERSON"},
        {"value": "暮云置业有限公司", "type": "LEGAL_PERSON"},
        {"value": "暮云置业", "type": "LEGAL_PERSON"},
        {"value": "暮云江畔安置房项目", "type": "PROJECT"},
        {"value": "青崖律师事务所", "type": "LAW_FIRM"},
        {"value": "暮云江畔", "type": "LOCATION"},
    ],
    aliases=[
        {"canonical": "暮云置业有限公司", "values": ["暮云置业有限公司", "暮云置业"],
         "type": "LEGAL_PERSON"},
    ],
)


def _prepare_demo(state_root: Path, base_dir: Path, status: str) -> Path:
    out_dir = base_dir / "demo-out"
    if not (Path(state_root) / DEMO_MATTER / "private.dpapi").exists():
        MatterState(state_root, DEMO_MATTER).init("cn-ai-safe-v1")
    input_dir = base_dir / "demo-in"
    input_dir.mkdir(parents=True, exist_ok=True)
    (input_dir / "合同.md").write_text(DEMO_CONTRACT, encoding="utf-8")
    result = SanitizeService(state_root).sanitize(
        DEMO_MATTER, input_dir, out_dir, dictionary=DEMO_DICTIONARY
    )
    if status == "REVIEW_REQUIRED":
        state = MatterState.load(state_root, DEMO_MATTER)
        public = state.read_public()
        public["status"] = "REVIEW_REQUIRED"
        state.write_public(public)
    return out_dir


def build_consumer_protocol(state_root: Path, out_dir: Path,
                            repo_root: Path | None = None) -> dict:
    from ..security.safe_storage import atomic_write_bytes

    state_root = Path(state_root)
    out_dir = Path(out_dir)
    repo_root = repo_root or Path(__file__).resolve().parents[2]
    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / "schemas").mkdir(parents=True)
    (out_dir / "public-keys").mkdir(parents=True)
    examples = out_dir / "examples"
    negatives = out_dir / "negative-fixtures"

    # 1. schemas (exact copies)
    from ..contracts.schemas import SCHEMAS_DIR

    schemas_src = Path(SCHEMAS_DIR)
    for name in PUBLIC_SCHEMAS:
        shutil.copy2(
            schemas_src / f"{name}.schema.json",
            out_dir / "schemas" / f"{name}.schema.json",
        )

    identity = ReceiptIdentity(state_root / "identity").ensure()
    (out_dir / "public-keys" / "receipt-signing-public.json").write_text(
        json.dumps(export_public_key(identity), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    # 2. positive examples
    base_dir = out_dir.parent / ".consumer-protocol-work"
    base_dir.mkdir(parents=True, exist_ok=True)
    out_auto = _prepare_demo(state_root, base_dir, "AUTO_READY")
    example_auto = examples / "auto-ready"
    build_harness_handoff(state_root, DEMO_MATTER, example_auto, source_dir=out_auto)

    # ready-by-human: force review requirement + receipt
    state = MatterState.load(state_root, DEMO_MATTER)
    private = state.read_private()
    private["matter_review_required"] = True
    state.write_private(private)
    public = state.read_public()
    public["status"] = "REVIEW_REQUIRED"
    state.write_public(public)
    issue_review_receipt(
        state_root, DEMO_MATTER, out_auto,
        {"matter_id": DEMO_MATTER, "decisions": []},
        "protocol-demo-reviewer", "MATTER_LEAD",
    )
    example_human = examples / "ready-by-human"
    build_harness_handoff(state_root, DEMO_MATTER, example_human, source_dir=out_auto)

    # blocked example: a properly signed bundle with CLOSED_BLOCK status —
    # still refused by consumers because blocked materials are not importable
    blocked = examples / "blocked"
    shutil.copytree(example_auto, blocked)
    _set_status(blocked, "CLOSED_BLOCK", identity)

    # 3. negative fixtures (mutations of the auto-ready example)
    _write_negative_fixtures(example_auto, example_human, negatives, identity)

    # 4. manifest (signed)
    manifest = build_manifest(
        repo_root,
        export_public_key(identity),
        profile_ids=["cn-ai-safe-v1", "cn-publish-v1"],
    )
    manifest["signature"] = identity.sign(manifest)
    (out_dir / "consumer-contract-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    # 5. README + SHA256SUMS
    (out_dir / "README.md").write_text(_README_TEXT, encoding="utf-8")
    _write_sha256sums(out_dir)
    return {"protocol_dir": str(out_dir), "examples": 3, "negative_fixtures": 6}


def _set_status(bundle_dir: Path, status: str, identity=None) -> None:
    p = bundle_dir / "sanitized-bundle.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    doc["status"] = status
    if identity is not None:
        # producer-side re-sign so the refusal is on status, not signature
        doc["signature"] = identity.sign({k: v for k, v in doc.items() if k != "signature"})
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_negative_fixtures(auto: Path, human: Path, negatives: Path, identity) -> None:
    negatives.mkdir(parents=True, exist_ok=True)

    def clone(src: Path, name: str) -> Path:
        dst = negatives / name
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
        return dst

    # 1. bad signature: flip one byte of the bundle signature
    bad = clone(auto, "bad-signature")
    p = bad / "sanitized-bundle.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    sig = bytearray(base64.b64decode(doc["signature"]["signature"]))
    sig[0] ^= 0xFF
    doc["signature"]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 2. stale receipt: artifact changed after signing
    stale = clone(auto, "stale-receipt")
    f = next((stale / "sanitized").glob("doc-*.ai.md"))
    f.write_text(f.read_text(encoding="utf-8") + "\n后加内容\n", encoding="utf-8")

    # 3. mapping in bundle: private field inside a structured object
    mapping = clone(auto, "mapping-in-bundle")
    p = mapping / "sanitized-bundle.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    if doc["structured_objects"]:
        doc["structured_objects"][0]["canonical_surface"] = "秦岭"
    else:
        doc["structured_objects"].append({"canonical_surface": "秦岭"})
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 4. missing review: READY_BY_HUMAN without a human review receipt
    missing = clone(auto, "missing-review")
    _set_status(missing, "READY_BY_HUMAN", identity)  # signed; review receipt absent

    # 5. artifact hash mismatch: tamper the artifacts field (breaks signature AND hash)
    mismatch = clone(auto, "artifact-hash-mismatch")
    p = mismatch / "sanitized-bundle.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    doc["artifacts"][0]["sha256"] = "0" * 64
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 6. unknown schema field: extra field in the bundle
    unknown = clone(auto, "unknown-schema-field")
    p = unknown / "sanitized-bundle.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    doc["sneaky_private_note"] = "should be rejected"
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_sha256sums(pack: Path) -> None:
    import hashlib

    lines = []
    for f in sorted(pack.rglob("*")):
        if f.is_file() and f.name != "SHA256SUMS":
            rel = f.relative_to(pack).as_posix()
            lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {rel}")
    (pack / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


_README_TEXT = """# legal-cn-anonymizer consumer protocol pack v1

This pack is the single authoritative interface between the anonymizer and its
external consumers (e.g. Legal Harness). Consumers must:

1. pin the schema copies in `schemas/` (verify against `consumer-contract-manifest.json`);
2. trust ONLY the signer key in `public-keys/` (identified by key id + fingerprint);
3. verify every bundle: signature, artifact hashes, receipt binding, review status;
4. reject every fixture in `negative-fixtures/` — acceptance of any of them
   means the consumer verification is broken.

Status semantics: `AUTO_READY` and `READY_BY_HUMAN` (with a valid human review
receipt) are importable. `CLOSED_BLOCK` and `REVIEW_REQUIRED` are not.

The manifest is signed; the signer key never contains case data. Mapping and
private review data are never shipped — bundles containing private fields
(e.g. `canonical_surface`) must be rejected.
"""
