"""Recognizer registry: combines production providers and resolves overlaps.
The registry holds no state and no mappings.

Default construction (shared by every production pipeline call site) is
rules + Chinese NER (card 05-1). When the NER stack is unavailable the gap is
reported on ``status`` — services must surface REVIEW_REQUIRED, never let a
NER-dependent matter reach AUTO_READY over a rules-only fallback.
"""

from __future__ import annotations

from ...ports.recognizer import Detection, RecognizerPort
from .cn_rules import CnRuleRecognizer, resolve_overlaps
from .project_dictionary import ProjectDictionaryProvider


class RecognizerRegistry(RecognizerPort):
    name = "registry"

    def __init__(
        self,
        providers: list[RecognizerPort] | None = None,
        dictionary: ProjectDictionaryProvider | None = None,
    ):
        if providers is None:
            from .presidio_ner import build_production_providers

            providers, self.status = build_production_providers()
        else:
            self.status = {"ner_available": None, "reason": "custom providers", "detector_stack": []}
        self.providers: list[RecognizerPort] = list(providers)
        if dictionary is not None:
            self.providers.append(dictionary)

    @property
    def ner_available(self) -> bool:
        return bool(self.status.get("ner_available"))

    @property
    def degradations(self) -> list[str]:
        if self.status.get("ner_available") is False:
            return [f"{self.status.get('error_code', 'recognizer_degraded')}:"
                    + str(self.status.get("reason", ""))]
        return []

    def detector_stack(self) -> list[dict]:
        stack = []
        for p in self.providers:
            if isinstance(p, CnRuleRecognizer):
                stack.append(
                    {"mechanism": "deterministic-regex", "modelId": "cn-rules",
                     "modelVersion": "1.0"}
                )
            elif hasattr(p, "stack_descriptor"):
                stack.append(p.stack_descriptor())
        return stack

    def detect(self, text: str) -> list[Detection]:
        detections: list[Detection] = []
        for provider in self.providers:
            detections.extend(provider.detect(text))
        return resolve_overlaps(detections)
