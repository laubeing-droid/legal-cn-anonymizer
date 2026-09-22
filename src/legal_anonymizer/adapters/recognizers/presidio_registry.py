"""Optional Presidio adapter. Presidio is a pluggable recognition backend, never
the state authority: it must not store mappings or decide release status. When
the ``presidio-analyzer`` extra is not installed this adapter reports
unavailable and the built-in rule engine keeps the same output contract."""

from __future__ import annotations

from ...ports.recognizer import Detection, RecognizerPort

try:  # pragma: no cover - exercised only when the extra is installed
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer

    _PRESIDIO_IMPORTABLE = True
except Exception:  # noqa: BLE001 - optional extra
    AnalyzerEngine = None
    Pattern = PatternRecognizer = None
    _PRESIDIO_IMPORTABLE = False

from .cn_rules import RULES


class PresidioRegistryAdapter(RecognizerPort):
    """Bridges the internal Rule set into Presidio PatternRecognizers so both
    engines share one rule source and produce the same Detection contract."""

    name = "presidio"

    def __init__(self) -> None:
        if not _PRESIDIO_IMPORTABLE:
            raise RuntimeError("presidio extra not installed")
        self._analyzer = AnalyzerEngine()
        for rule in RULES:
            self._analyzer.registry.add_recognizer(
                PatternRecognizer(
                    supported_entity=rule.entity_type,
                    patterns=[Pattern(name=rule.rule_id, regex=rule.re.pattern, score=0.9)],
                )
            )

    def detect(self, text: str) -> list[Detection]:
        results = self._analyzer.analyze(text=text, language="zh", return_decision_process=False)
        out = []
        for r in results:
            out.append(
                Detection(
                    surface=text[r.start : r.end],
                    entity_type=r.entity_type,
                    start=r.start,
                    end=r.end,
                    source="presidio",
                    rule_id=str(r.recognition_metadata.get("pattern_name", r.entity_type)),
                    confidence=float(r.score),
                )
            )
        return out


def presidio_available() -> bool:
    return _PRESIDIO_IMPORTABLE
