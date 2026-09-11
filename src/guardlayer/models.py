"""Core data models for GuardLayer scan results.

Kept dependency-free (standard library only) so the engine imports and runs
anywhere; optional integrations (API, embeddings) live behind extras.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Literal

Direction = Literal["input", "output"]


class Verdict(str, Enum):
    """Overall decision for a scanned piece of text."""

    ALLOW = "allow"   # nothing notable found
    FLAG = "flag"     # suspicious — log / review, do not necessarily block
    BLOCK = "block"   # high-confidence threat — stop it


@dataclass(frozen=True)
class Detection:
    """A single signal raised by one scanner."""

    scanner: str          # which scanner produced this (e.g. "heuristics")
    rule: str             # the specific rule that matched (e.g. "ignore_previous_instructions")
    severity: float       # 0.0–1.0 confidence/impact of this single signal
    message: str          # human-readable explanation
    span: tuple[int, int] | None = None  # (start, end) char offsets in the text, if applicable

    def __post_init__(self) -> None:
        if not 0.0 <= self.severity <= 1.0:
            raise ValueError("severity must be within [0.0, 1.0]")


@dataclass
class ScanResult:
    """The aggregated outcome of running the pipeline over one text."""

    verdict: Verdict
    score: float                       # 0.0–1.0 aggregate risk
    direction: Direction
    detections: list[Detection] = field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK

    def to_dict(self) -> dict:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        return data
