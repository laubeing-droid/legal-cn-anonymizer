"""Recognizer registry: combines offline providers and resolves overlaps.
The registry holds no state and no mappings."""

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
        self.providers: list[RecognizerPort] = providers or [CnRuleRecognizer()]
        if dictionary is not None:
            self.providers.append(dictionary)

    def detect(self, text: str) -> list[Detection]:
        detections: list[Detection] = []
        for provider in self.providers:
            detections.extend(provider.detect(text))
        return resolve_overlaps(detections)
