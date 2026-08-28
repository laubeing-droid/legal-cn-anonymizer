"""Recognizer ports. Detection engines (deterministic rules, dictionaries,
optional Presidio, optional local NER) all speak this contract. The engine that
*runs* recognizers never decides final release status — that is the verifier's
job (S9)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Detection:
    surface: str
    entity_type: str  # EntityType value or "IDENTIFIER:<kind>"
    start: int
    end: int
    source: str  # regex | dictionary | structure | ner | vision | presidio
    rule_id: str
    confidence: float
    severity: str = "normal"  # critical | high | normal
    evidence: tuple[str, ...] = field(default_factory=tuple)
    transform_hint: str | None = None  # from profile, engine never forces it


class RecognizerPort:
    """All recognizers return Detections with absolute character offsets over the
    exact text passed in."""

    name: str = "port"

    def detect(self, text: str) -> list[Detection]:
        raise NotImplementedError
