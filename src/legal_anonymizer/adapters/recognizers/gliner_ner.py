"""GLiNER recognizers — the non-CLUENER members of the engine race (05-1) and
the heterogeneous verifier (05-2).

Two different GLiNER stacks exist locally and they are NOT interchangeable:

  * `CnGliner2RaceRecognizer` — fastino/gliner2-base-v1 through the official
    `gliner2` package (its documented loader). Measured on the frozen Chinese
    synthetic benchmark it returns no Chinese entities at any usable threshold;
    that is a real measured result, not a wiring bug (the old `gliner` package
    mis-loads gliner2 weights and must never be used for it).

  * `CnGlinerVerifier` — urchade/gliner_medium-v2.1 through the legacy `gliner`
    package (its native config format). Chinese-capable, zero-shot span
    extraction: architecturally different from CLUENER token classification,
    so it serves as the heterogeneous verification engine. Spans are coarse;
    the verifier logic tolerates that (a coarse span that still names an
    alias is skipped, one that names an unknown surface is a residual).

Missing components fail closed with a named reason; callers degrade to
REVIEW_REQUIRED.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path

from ...ports.recognizer import Detection, RecognizerPort
from . import model_assets

logger = logging.getLogger("legal_anonymizer.recognizers")

GLINER2_ASSET_ID = "gliner2-base"
GLINER_V21_ASSET_ID = "gliner-medium-v21"

# release-gate zero-shot label set (Chinese prompts)
GLINER_LABEL_MAP: dict[str, str] = {
    "人名": "PERSON",
    "机构": "LEGAL_PERSON",
    "地点": "LOCATION",
}


class GlinerUnavailableError(RuntimeError):
    error_code = "ner_model_unavailable"


def _resolve_dir(asset_id: str) -> str:
    asset = model_assets.find_asset(asset_id)
    if asset is None:
        raise GlinerUnavailableError(f"no locked asset {asset_id!r}")
    ok, reason = model_assets.check_asset(asset_id)
    if not ok:
        raise GlinerUnavailableError(reason)
    return str(Path(model_assets.repo_root() / asset.local_dir).resolve())


class _BaseGliner(RecognizerPort):
    asset_id = ""
    package = ""

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
        self._model = None
        self._lock = threading.Lock()
        self.asset = model_assets.find_asset(self.asset_id)

    def availability(self) -> tuple[bool, str]:
        if not model_assets.import_ok(self.package):
            return False, f"{self.package} package not installed"
        if self.asset is None:
            return False, f"no locked asset {self.asset_id!r} in models/manifest.json"
        ok, reason = model_assets.check_asset(self.asset_id)
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

    def _load(self):
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        model_dir = _resolve_dir(self.asset_id)
        cache: dict = _MODEL_CACHE
        with self._lock:
            cached = cache.get(model_dir)
            if cached is not None:
                return cached
            if self.package == "gliner2":
                from gliner2 import GLiNER2

                cached = GLiNER2.from_pretrained(model_dir)
            else:
                from gliner import GLiNER

                cached = GLiNER.from_pretrained(model_dir)
            cache[model_dir] = cached
            return cached


_MODEL_CACHE: dict[str, object] = {}


class CnGliner2RaceRecognizer(_BaseGliner):
    name = "ner-gliner2-zeroshot"
    mechanism = "zero-shot-span-gliner2"
    asset_id = GLINER2_ASSET_ID
    package = "gliner2"

    def detect(self, text: str) -> list[Detection]:
        if not text.strip():
            return []
        model = self._load()
        res = model.extract_entities(
            text, list(GLINER_LABEL_MAP), threshold=self.threshold,
            include_spans=True,
        )
        out: list[Detection] = []
        for label, spans in (res.get("entities") or {}).items():
            entity = GLINER_LABEL_MAP.get(label)
            if entity is None:
                continue
            for sp in spans or []:
                if isinstance(sp, dict):
                    start, end = int(sp["start"]), int(sp["end"])
                    surface = sp.get("text", text[start:end])
                else:  # plain string without spans: locate it
                    surface = str(sp)
                    start = text.find(surface)
                    if start < 0:
                        continue
                    end = start + len(surface)
                out.append(_det(entity, surface, start, end, 0.9, self.asset))
        return out


class CnGlinerVerifier(_BaseGliner):
    name = "verify-gliner-v21-heterogeneous"
    mechanism = "zero-shot-span-gliner-v21"
    asset_id = GLINER_V21_ASSET_ID
    package = "gliner"

    def __init__(self, threshold: float = 0.3):
        super().__init__(threshold=threshold)

    def detect(self, text: str) -> list[Detection]:
        if not text.strip():
            return []
        model = self._load()
        raw = model.predict_entities(
            text, list(GLINER_LABEL_MAP), flat_ner=True, threshold=self.threshold
        )
        out: list[Detection] = []
        for e in raw:
            label = e.get("type") or e.get("label") or e.get("entity_group")
            entity = GLINER_LABEL_MAP.get(label)
            if entity is None:
                continue
            start, end = int(e["start"]), int(e["end"])
            out.append(_det(entity, text[start:end], start, end,
                            float(e.get("score", 0.0)), self.asset))
        return out


def _det(entity: str, surface: str, start: int, end: int, score: float,
         asset) -> Detection:
    return Detection(
        surface=surface,
        entity_type=entity,
        start=start,
        end=end,
        source="ner",
        rule_id=f"ner.gliner.{entity}",
        confidence=score,
        severity="high",
        evidence=(
            "mechanism:zero-shot-span",
            f"model:{asset.model_id}@{asset.revision[:8]}" if asset else "model:?",
        ),
    )
