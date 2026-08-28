"""RapidOCR adapter: local ONNX CPU OCR. Model files are hash-locked in
models/manifest.json; missing or mismatched models fail closed — never a
runtime download, never a silent "no text found"."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

_REPO_MODELS = Path(__file__).resolve().parents[4] / "models" / "manifest.json"


@dataclass
class OcrLine:
    text: str
    box: tuple[float, float, float, float]  # x0,y0,x1,y1 in page-image pixels
    confidence: float


class OcrUnavailableError(RuntimeError):
    error_code = "ocr_model_unavailable"


def _verify_models() -> None:
    manifest_path = _REPO_MODELS
    if not manifest_path.exists():
        raise OcrUnavailableError("model manifest missing; OCR unavailable (fail closed)")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    ocr = manifest.get("ocr", {})
    if not ocr.get("qualified"):
        raise OcrUnavailableError("OCR model not qualified; fail closed")
    import rapidocr

    root = Path(rapidocr.__file__).parent
    for entry in ocr.get("files", []):
        f = root / entry["path"]
        if not f.exists():
            raise OcrUnavailableError(f"OCR model file missing: {entry['path']}")
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            raise OcrUnavailableError(f"OCR model hash mismatch: {entry['path']}")


class RapidOcrEngine:
    def __init__(self):
        _verify_models()
        try:
            from rapidocr import RapidOCR

            self._engine = RapidOCR()
        except Exception as exc:  # noqa: BLE001
            raise OcrUnavailableError(f"RapidOCR init failed: {type(exc).__name__}") from exc

    def run(self, image) -> tuple[list[OcrLine], bool]:
        """Returns (lines sorted in reading order, all_ok)."""
        result = self._engine(image)
        lines: list[OcrLine] = []
        if result.txts:
            for text, score, box in zip(result.txts, result.scores, result.boxes):
                xs = [p[0] for p in box]
                ys = [p[1] for p in box]
                lines.append(
                    OcrLine(
                        text=text,
                        box=(float(min(xs)), float(min(ys)), float(max(xs)), float(max(ys))),
                        confidence=float(score),
                    )
                )
        lines.sort(key=lambda l: (round(l.box[1] / 12), l.box[0]))
        return lines, True
