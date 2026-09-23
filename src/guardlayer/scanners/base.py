"""The Scanner contract.

Every detector implements this protocol, so the pipeline can run an arbitrary
ensemble of them without knowing their internals. A scanner declares which
directions it applies to (input / output / context) and returns Detections.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterable
from typing import ClassVar, Protocol, runtime_checkable

from guardlayer.models import DIRECTIONS, Detection, ScanContext


@runtime_checkable
class Scanner(Protocol):
    """A detector that inspects text and returns zero or more Detections."""

    name: str
    directions: frozenset[str]

    def scan(self, text: str, context: ScanContext) -> list[Detection]:
        """Inspect `text` and return any signals found (empty list if clean)."""
        ...


class BaseScanner:
    """Convenience base class: holds `name`/`directions` and builds Detections."""

    name: ClassVar[str] = "base"
    default_directions: ClassVar[frozenset[str]] = frozenset(DIRECTIONS)

    def __init__(self, directions: Iterable[str] | None = None) -> None:
        self.directions: frozenset[str] = frozenset(directions) if directions else self.default_directions
        unknown = self.directions - set(DIRECTIONS)
        if unknown:
            raise ValueError(f"unknown direction(s): {sorted(unknown)}")

    def scan(self, text: str, context: ScanContext) -> list[Detection]:  # pragma: no cover - abstract
        raise NotImplementedError

    def detection(
        self,
        rule: str,
        category: str,
        severity: float,
        message: str,
        span: tuple[int, int] | None = None,
        **metadata: object,
    ) -> Detection:
        return Detection(
            scanner=self.name,
            rule=rule,
            category=category,
            severity=max(0.0, min(1.0, severity)),
            message=message,
            span=span,
            metadata=dict(metadata),
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(directions={sorted(self.directions)})"


class SpanIndex:
    """Non-overlapping spans with O(log n) overlap checks (keeps many-match inputs linear-ish)."""

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []

    def overlaps(self, span: tuple[int, int]) -> bool:
        i = bisect_right(self._starts, span[0])
        return (i > 0 and self._ends[i - 1] > span[0]) or (i < len(self._starts) and self._starts[i] < span[1])

    def add(self, span: tuple[int, int]) -> None:
        i = bisect_right(self._starts, span[0])
        self._starts.insert(i, span[0])
        self._ends.insert(i, span[1])
