"""Vision signals: QR / DataMatrix / PDF417 via zxing-cpp. Decoded text feeds
the identifier recognizers; a detected-but-undecodable code is QR_UNREADABLE
review — never ignored. publish mode physically removes codes (S9 decision)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CodeSignal:
    format: str
    text: str | None  # None when detected but undecodable
    box: tuple[float, float, float, float] | None


class VisionSignalProvider:
    def __init__(self, enabled: bool | None = None):
        try:
            import zxingcpp

            self._zxing = zxingcpp
        except Exception:  # noqa: BLE001 - optional extra
            self._zxing = None
        if enabled is None:
            enabled = self._zxing is not None
        self.enabled = enabled

    def scan(self, image) -> list[CodeSignal]:
        if not self.enabled:
            return []
        try:
            results = self._zxing.read_barcodes(image)
        except Exception:  # noqa: BLE001
            return []
        out = []
        for r in results:
            box = None
            if r.position is not None:
                xs = [p.x for p in r.position]
                ys = [p.y for p in r.position]
                box = (float(min(xs)), float(min(ys)), float(max(xs)), float(max(ys)))
            out.append(CodeSignal(format=str(r.format.name), text=r.text, box=box))
        return out
