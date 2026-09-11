"""The GuardLayer pipeline — run an ensemble of scanners and aggregate a verdict.

Design: layered detection. Each scanner votes with Detections; the pipeline
combines them into a single risk score and maps it to allow / flag / block via
two thresholds. No single detector is reliable against prompt injection, so the
value is in combining several cheap, independent signals.
"""

from __future__ import annotations

from collections.abc import Sequence

from guardlayer.models import Detection, Direction, ScanResult, Verdict
from guardlayer.scanners.base import Scanner
from guardlayer.scanners.heuristics import HeuristicScanner


class GuardLayer:
    """Scan LLM inputs/outputs against a configurable set of detectors."""

    def __init__(
        self,
        scanners: Sequence[Scanner] | None = None,
        *,
        flag_threshold: float = 0.4,
        block_threshold: float = 0.8,
    ) -> None:
        if not 0.0 <= flag_threshold <= block_threshold <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= flag <= block <= 1")
        # Default ensemble: the zero-dependency heuristic core.
        self.scanners: list[Scanner] = list(scanners) if scanners else [HeuristicScanner()]
        self.flag_threshold = flag_threshold
        self.block_threshold = block_threshold

    def scan(self, text: str, direction: Direction = "input") -> ScanResult:
        detections: list[Detection] = []
        for scanner in self.scanners:
            detections.extend(scanner.scan(text, direction))

        score = self._aggregate(detections)
        verdict = self._verdict(score)
        return ScanResult(
            verdict=verdict,
            score=round(score, 3),
            direction=direction,
            detections=detections,
        )

    def _aggregate(self, detections: list[Detection]) -> float:
        """Combine per-detection severities into one risk score in [0, 1].

        Uses a probabilistic OR (noisy-or): independent signals compound, so
        several weak hits raise the score, but it never exceeds 1.0.
        """
        product = 1.0
        for d in detections:
            product *= (1.0 - d.severity)
        return 1.0 - product

    def _verdict(self, score: float) -> Verdict:
        if score >= self.block_threshold:
            return Verdict.BLOCK
        if score >= self.flag_threshold:
            return Verdict.FLAG
        return Verdict.ALLOW
