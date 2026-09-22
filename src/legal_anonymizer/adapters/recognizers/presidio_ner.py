"""Production Chinese NER: Presidio transformers engine + hash-locked local
CLUENER model (plan-v4.2 card 05-1).

Engine wiring (verified against the installed presidio-analyzer 2.2.x API):
  NlpEngineProvider(nlp_engine_name="transformers")
    models: lang_code=zh, spacy=zh_core_web_sm (tokenization/sentence assist),
            transformers=<local locked uer/roberta-base-finetuned-cluener2020-chinese>
  The HF token-classification pipeline aggregates BIOES tags; CLUENER's real
  label set is B/I/S-name, -address, -company, -government, -organization plus
  book/game/movie/position/scene and O/[PAD]. `normalize_bioes_label` is the
  explicit BIOES->plain normalization used for mapping keys; non-PII labels
  (book/game/movie/position/scene) are ignored, never masked.

Missing components fail closed: `availability()` reports the named gap and the
caller must degrade the matter to REVIEW_REQUIRED — never silently fall back
to rules-only while still claiming AUTO_READY.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from ...ports.recognizer import Detection, RecognizerPort
from . import model_assets
from .model_assets import NerAsset

logger = logging.getLogger("legal_anonymizer.recognizers")

CLUENER_ASSET_ID = "cluener-roberta-base"
SPACY_MODEL = "zh_core_web_sm"

# Real CLUENER config labels (after BIOES normalization) -> our EntityType.
CLUENER_LABEL_MAP: dict[str, str] = {
    "name": "PERSON",
    "address": "LOCATION",
    "company": "LEGAL_PERSON",
    "organization": "LEGAL_PERSON",
    "government": "PUBLIC_AUTHORITY",
}
# Emitted by the model but not personal-information categories on their own.
CLUENER_NON_PII_LABELS = ("book", "game", "movie", "position", "scene")

_BIOES_PREFIXES = ("B-", "I-", "E-", "S-", "U-", "L-")

# one heavy analyzer per model dir per process (verify/sanitize share it, each
# with its own instance state; the analyzer itself is stateless for zh text)
_ANALYZER_CACHE: dict[str, object] = {}
_CACHE_LOCK = threading.Lock()


def normalize_bioes_label(label: str) -> str:
    """Strip the BIOES position prefix: 'S-name'/'B-name' -> 'name', 'O' -> 'O'."""
    for prefix in _BIOES_PREFIXES:
        if label.startswith(prefix):
            return label[len(prefix) :]
    return label


# model spans sometimes absorb the quotation/bracket pair around a name; the
# entity itself never includes those characters, so tighten offsets
_BORDER_CHARS = "“”„‟\"'＇‘’《》〈〉()（）[]【】｛｛｝}「」『』:：;；,，。.、 \t\r\n"


def tighten_span(text: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start] in _BORDER_CHARS:
        start += 1
    while end > start and text[end - 1] in _BORDER_CHARS:
        end -= 1
    return start, end


class NerUnavailableError(RuntimeError):
    error_code = "ner_model_unavailable"


class PresidioCnNerRecognizer(RecognizerPort):
    """Presidio transformers-engine NER over the locked CLUENER weights."""

    name = "ner-cluener-presidio-transformers"
    mechanism = "transformers-token-classification"

    def __init__(self, threshold: float = 0.35):
        self.threshold = threshold
        self._analyzer = None
        self._lock = threading.Lock()
        self.asset: NerAsset | None = model_assets.find_asset(CLUENER_ASSET_ID)

    # -- availability (cheap checks only; heavy models load lazily) ----------
    def availability(self) -> tuple[bool, str]:
        if not model_assets.import_ok("presidio_analyzer"):
            return False, "presidio-analyzer extra not installed"
        if not model_assets.import_ok("transformers"):
            return False, "transformers not installed"
        if not model_assets.import_ok("spacy"):
            return False, "spacy not installed"
        if not model_assets.import_ok("spacy_huggingface_pipelines"):
            return False, "spacy-huggingface-pipelines bridge not installed"
        if not model_assets.spacy_model_installed(SPACY_MODEL):
            return False, f"spacy model {SPACY_MODEL} not installed"
        if self.asset is None:
            return False, f"no locked asset {CLUENER_ASSET_ID!r} in models/manifest.json"
        ok, reason = model_assets.check_asset(CLUENER_ASSET_ID)
        if not ok:
            return False, reason
        return True, "ok"

    def stack_descriptor(self) -> dict:
        asset = self.asset
        return {
            "mechanism": self.mechanism,
            "modelId": asset.model_id if asset else "unavailable",
            "modelVersion": asset.revision if asset else "unavailable",
        }

    # -- engine construction (lazy, once) ------------------------------------
    def _build_analyzer(self):
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_analyzer.predefined_recognizers.nlp_engine_recognizers import (
            TransformersRecognizer,
        )

        asset = self.asset
        model_dir = str(Path(model_assets.repo_root() / asset.local_dir).resolve())
        with _CACHE_LOCK:
            cached = _ANALYZER_CACHE.get(model_dir)
        if cached is not None:
            return cached
        nlp_engine = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "transformers",
                "models": [
                    {
                        "lang_code": "zh",
                        "model_name": {"spacy": SPACY_MODEL, "transformers": model_dir},
                    }
                ],
                "ner_model_configuration": {
                    "model_to_presidio_entity_mapping": dict(CLUENER_LABEL_MAP),
                    "labels_to_ignore": list(CLUENER_NON_PII_LABELS),
                    "aggregation_strategy": "simple",
                    "stride": 0,
                    "alignment_mode": "expand",
                    "default_score": 0.5,
                },
            }
        ).create_engine()
        recognizer = TransformersRecognizer(
            supported_entities=sorted(set(CLUENER_LABEL_MAP.values())),
            supported_language="zh",
            name="presidio-cluener-zh",
        )
        registry = RecognizerRegistry(
            recognizers=[recognizer], supported_languages=["zh"]
        )
        analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            registry=registry,
            supported_languages=["zh"],
        )
        with _CACHE_LOCK:
            _ANALYZER_CACHE[model_dir] = analyzer
        return analyzer

    def _ensure_analyzer(self):
        if self._analyzer is None:
            with self._lock:
                if self._analyzer is None:
                    ok, reason = self.availability()
                    if not ok:
                        raise NerUnavailableError(reason)
                    self._analyzer = self._build_analyzer()
        return self._analyzer

    # -- RecognizerPort -------------------------------------------------------
    def detect(self, text: str) -> list[Detection]:
        if not text.strip():
            return []
        analyzer = self._ensure_analyzer()
        results = analyzer.analyze(text=text, language="zh")
        out: list[Detection] = []
        for r in results:
            if float(r.score) < self.threshold:
                continue
            start, end = tighten_span(text, int(r.start), int(r.end))
            if start >= end:
                continue
            surface = text[start:end]
            # the Chinese CLUENER model emits ASCII fragments (e.g. the word
            # "ignore") as org names; a surface without a single CJK char is
            # model noise for this engine and is dropped (never masked)
            if not any("\u4e00" <= ch <= "\u9fff" for ch in surface):
                continue
            out.append(
                Detection(
                    surface=surface,
                    entity_type=r.entity_type,
                    start=start,
                    end=end,
                    source="ner",
                    rule_id=f"ner.cluener.{r.entity_type}",
                    confidence=float(r.score),
                    severity="high",
                    evidence=(
                        "mechanism:transformers-token-classification",
                        f"model:{self.asset.model_id}@{self.asset.revision[:8]}",
                    ),
                )
            )
        return out


def build_production_providers() -> tuple[list[RecognizerPort], dict]:
    """Default production stack: deterministic rules + Chinese NER.

    Returns (providers, status). When NER components are missing the status is
    explicit and NON-OPT-IN: callers must surface it (REVIEW_REQUIRED /
    AVAILABLE=false). This function never hides the gap: the rules-only
    fallback is reported as a degradation, not as normal operation.
    """
    from .cn_rules import CnRuleRecognizer

    providers: list[RecognizerPort] = [CnRuleRecognizer()]
    ner = PresidioCnNerRecognizer()
    ok, reason = ner.availability()
    status = {
        "ner_available": ok,
        "reason": reason,
        "detector_stack": [ner.stack_descriptor()] if ok else [],
    }
    if ok:
        providers.append(ner)
    else:
        logger.warning("Chinese NER unavailable (%s); production stack degraded: "
                       "matters must not reach AUTO_READY on NER-dependent coverage", reason)
        status["error_code"] = NerUnavailableError.error_code
    return providers, status
