"""Project dictionary provider: user-curated blacklist / whitelist / aliases.
The dictionary is case-private state (DPAPI at S8); here it is a plain object.
Whitelist entries (e.g. public law-source citations) are excluded from output."""

from __future__ import annotations

import re

from ...ports.recognizer import Detection, RecognizerPort


class ProjectDictionaryProvider(RecognizerPort):
    name = "dictionary"

    def __init__(self, blacklist: list[dict] | None = None, whitelist: list[str] | None = None,
                 aliases: list[dict] | None = None):
        # blacklist: [{value, type, transform?}]
        self.blacklist = sorted(blacklist or [], key=lambda e: -len(e["value"]))
        self.whitelist = list(whitelist or [])
        self.aliases = aliases or []

    def _is_whitelisted(self, value: str) -> bool:
        return any(w in value or value in w for w in self.whitelist)

    def detect(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        for entry in self.blacklist:
            value = entry["value"]
            if self._is_whitelisted(value):
                continue
            for m in re.finditer(re.escape(value), text):
                out.append(
                    Detection(
                        surface=value,
                        entity_type=entry.get("type", "OTHER_PROTECTED"),
                        start=m.start(),
                        end=m.end(),
                        source="dictionary",
                        rule_id=f"dict:{entry.get('name', value[:12])}",
                        confidence=1.0,
                        severity="high",
                        evidence=("dictionary:user-confirmed",),
                        transform_hint=entry.get("transform"),
                    )
                )
        # alias groups: every alias surface maps to its canonical entity
        for group in self.aliases:
            for value in group.get("values", []):
                if self._is_whitelisted(value):
                    continue
                for m in re.finditer(re.escape(value), text):
                    out.append(
                        Detection(
                            surface=value,
                            entity_type=group.get("type", "LEGAL_PERSON"),
                            start=m.start(),
                            end=m.end(),
                            source="dictionary",
                            rule_id=f"alias:{group.get('canonical', '')[:12]}",
                            confidence=1.0,
                            severity="high",
                            evidence=(
                                f"alias-canonical:{group.get('canonical', '')}",
                                "dictionary:user-confirmed",
                            ),
                        )
                    )
        return out
