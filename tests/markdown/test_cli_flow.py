"""CLI-level S4 flow: project init -> sanitize -> verify -> rehydrate."""

from __future__ import annotations

import json
from pathlib import Path

from legal_anonymizer.cli import main
from tests.recognizers.test_cn_rules import SYNTHETIC_ID


def test_cli_matter_flow(tmp_path, capsys):
    state_dir = tmp_path / "state"
    input_dir = tmp_path / "m"
    out_dir = tmp_path / "out"
    input_dir.mkdir()
    (input_dir / "材料.md").write_text(
        f"负责人李四，电话13912345678，身份证{SYNTHETIC_ID}，工程款100万元。2023年5月1日开工。",
        encoding="utf-8",
    )
    dict_file = tmp_path / "dict.json"
    dict_file.write_text(
        json.dumps(
            {
                "blacklist": [
                    {"value": "李四", "type": "PERSON"},
                    {"value": "青云绿洲项目", "type": "PROJECT"},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    assert main(["project", "init", "--matter", "m-1", "--profile", "cn-ai-safe-v1",
                 "--state-dir", str(state_dir)]) == 0
    assert main(["sanitize", str(input_dir), "--matter", "m-1",
                 "--out", str(out_dir), "--state-dir", str(state_dir), "--json"]) == 2
    assert main(["verify", str(out_dir), "--matter", "m-1",
                 "--state-dir", str(state_dir), "--json"]) == 0
    sanitized = (out_dir / "sanitized" / "doc-001.ai.md").read_text(encoding="utf-8")
    assert SYNTHETIC_ID not in sanitized
    assert "13912345678" not in sanitized
    assert "100万元" in sanitized and "2023年5月1日" in sanitized
    caps = capsys.readouterr()
    assert "CLOSED_BLOCK" not in caps.out
