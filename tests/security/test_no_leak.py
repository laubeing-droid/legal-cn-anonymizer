"""S8 leak-exclusion checks: mapping and raw surfaces must not appear in any
public artifact (receipts, reports, sanitized markdown) or in state file names."""

from __future__ import annotations

import json
from pathlib import Path

from tests.markdown.test_pipeline import CONTRACT_MD, SYNTHETIC_ID, make_dictionary  # noqa: F401
from tests.markdown.test_pipeline import workspace  # reuse fixture
from legal_anonymizer.application.sanitize_service import SanitizeService
from tests.markdown.test_pipeline import TestMarkdownPipeline  # noqa: F401


def test_no_surfaces_in_public_artifacts(workspace):
    state_root, input_dir, out_dir = workspace
    result = SanitizeService(state_root).sanitize(
        "matter-001", input_dir, out_dir, dictionary=make_dictionary()
    )
    assert result.status == "AUTO_READY"
    leak_markers = ["张三", "丹霞青云置业有限公司", "中建第三工程有限公司", SYNTHETIC_ID]

    public_files = sorted((out_dir / "reports").glob("*.json")) + sorted(
        (out_dir / "receipts").glob("*.json")
    )
    assert public_files
    for f in public_files:
        text = f.read_text(encoding="utf-8")
        for marker in leak_markers:
            assert marker not in text, f"{f.name} leaks {marker!r}"

    sanitized = (out_dir / "sanitized" / "doc-001.ai.md").read_text(encoding="utf-8")
    for marker in leak_markers:
        assert marker not in sanitized

    # state directory listing: no surface-derived file names
    for p in (state_root / "matter-001").iterdir():
        for marker in leak_markers:
            assert marker not in p.name

    # receipt invariant: mapping exclusion asserted
    receipt = json.loads(
        (out_dir / "receipts" / "sanitization-receipt.json").read_text(encoding="utf-8")
    )
    assert receipt["invariants"]["mapping_excluded_from_public_bundle"] is True
