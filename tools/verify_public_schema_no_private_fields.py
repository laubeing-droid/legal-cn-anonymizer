"""Verify that public JSON Schemas never expose private (case-bearing) fields."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "src" / "legal_anonymizer" / "contracts" / "schemas"
PRIVATE_SCHEMAS = {"private-mention-v1.schema.json", "private-entity-v1.schema.json"}
FORBIDDEN_KEYS = {"surface", "canonical_surface", "aliases", "original_path", "raw_path",
                  "ocr_text", "raw_file_name", "original_filename"}


def walk(node, found, schema_name):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                for prop in value:
                    if prop.lower() in FORBIDDEN_KEYS:
                        found.append(f"{schema_name}: forbidden property '{prop}'")
            walk(value, found, schema_name)
    elif isinstance(node, list):
        for item in node:
            walk(item, found, schema_name)


def main() -> int:
    problems: list[str] = []
    for f in sorted(SCHEMA_DIR.glob("*.schema.json")):
        if f.name in PRIVATE_SCHEMAS:
            continue
        schema = json.loads(f.read_text(encoding="utf-8"))
        walk(schema, problems, f.name)
    if problems:
        print("FAIL")
        for p in problems:
            print(" -", p)
        return 1
    print("PASS: public schemas carry no private fields")
    return 0


if __name__ == "__main__":
    sys.exit(main())
