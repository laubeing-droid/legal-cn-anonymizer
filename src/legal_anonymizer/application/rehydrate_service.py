"""Rehydrate service: restore display aliases (and identifier aliases) in an AI
output back to the real surfaces, strictly. Fuzzy or near-miss text is never
rewritten — only exact alias matches and whitespace-inflated variants."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .state import MatterState, MatterStateError


@dataclass
class RehydrateResult:
    output_text: str
    replacements: int
    unmatched_aliases: list[str] = field(default_factory=list)


def _variants(alias: str) -> list[str]:
    """Exact alias plus common whitespace-inflated variants."""
    spaced = re.compile(r"\s*".join(re.escape(ch) for ch in alias))
    return [alias, spaced]


class RehydrateService:
    def __init__(self, state_root: Path):
        self.state_root = Path(state_root)

    def rehydrate_text(self, matter_id: str, text: str) -> RehydrateResult:
        try:
            state = MatterState.load(self.state_root, matter_id)
        except MatterStateError:
            raise
        private = state.read_private()
        pairs: list[tuple[str, str]] = []
        for e in private.get("entities", []):
            pairs.append((e["display_alias"], e["canonical_surface"]))
        for i in private.get("identifier_aliases", []):
            pairs.append((i["alias"], i["surface"]))
        # longest first so 法人A wins over overlapping shorter aliases
        pairs.sort(key=lambda p: -len(p[0]))

        total = 0
        used: set[str] = set()
        out = text
        for alias, surface in pairs:
            matched = False
            for pattern in _variants(alias):
                out, n = re.subn(pattern, surface.replace("\\", "\\\\"), out)
                if n:
                    total += n
                    matched = True
            if matched:
                used.add(alias)
        leftover = [a for a, _s in pairs if re.search(re.escape(a), out)]
        return RehydrateResult(
            output_text=out, replacements=total, unmatched_aliases=leftover
        )

    def rehydrate_file(self, matter_id: str, in_path: Path, out_path: Path) -> RehydrateResult:
        text = Path(in_path).read_text(encoding="utf-8")
        result = self.rehydrate_text(matter_id, text)
        Path(out_path).write_text(result.output_text, encoding="utf-8")
        return result

    def rehydrate_docx(self, matter_id: str, in_path: Path, out_path: Path) -> RehydrateResult:
        from ..adapters.documents.docx.rehydrate import rehydrate_docx

        state = MatterState.load(self.state_root, matter_id)
        private = state.read_private()
        pairs = [
            (e["display_alias"], e["canonical_surface"])
            for e in private.get("entities", [])
        ]
        pairs += [(i["alias"], i["surface"]) for i in private.get("identifier_aliases", [])]
        total = rehydrate_docx(Path(in_path), Path(out_path), pairs)
        return RehydrateResult(output_text=str(out_path), replacements=total)
