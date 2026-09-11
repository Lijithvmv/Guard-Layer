"""The Scanner contract.

Every detector implements this protocol, so the pipeline can run an arbitrary
ensemble of them without knowing their internals. New detectors (embedding
similarity, transformer classifier, canary tokens, ...) just implement `scan`.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from guardlayer.models import Detection, Direction


@runtime_checkable
class Scanner(Protocol):
    """A detector that inspects text and returns zero or more Detections."""

    name: str

    def scan(self, text: str, direction: Direction = "input") -> list[Detection]:
        """Inspect `text` and return any signals found (empty list if clean)."""
        ...
