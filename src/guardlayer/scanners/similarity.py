"""Similarity scanner — flags text that closely resembles known attacks.

Backed by a `VectorStore` seeded with the bundled attack corpus. Long texts are
split into overlapping sentence windows so an attack buried inside a benign
document (indirect injection) still scores. The pipeline can `learn()` newly
blocked prompts, so the store grows with the attacks you actually see.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from guardlayer.models import Category, Detection, ScanContext
from guardlayer.scanners.base import BaseScanner
from guardlayer.vectorstore import Embedder, VectorStore, builtin_attack_corpus

_SENTENCE_RE = re.compile(r"(?<=[.!?\n])\s+")


class SimilarityScanner(BaseScanner):
    name = "similarity"
    default_directions = frozenset({"input", "context"})

    def __init__(
        self,
        store: VectorStore | None = None,
        *,
        embedder: Embedder | None = None,
        threshold: float = 0.55,
        load_builtin: bool = True,
        corpus_file: str | Path | None = None,
        window_sentences: int = 3,
        max_windows: int = 256,
        directions: Iterable[str] | None = None,
    ) -> None:
        super().__init__(directions)
        self.store = store if store is not None else VectorStore(embedder)
        if load_builtin and store is None:
            self.store.add(builtin_attack_corpus(), {"source": "builtin"})
        if corpus_file:
            self.store.load(corpus_file)
        self.threshold = threshold
        self.window_sentences = window_sentences
        self.max_windows = max_windows

    def _windows(self, text: str) -> list[str]:
        sentences = [s for s in _SENTENCE_RE.split(text.strip()) if s.strip()]
        size = self.window_sentences
        if len(sentences) <= size:
            return [text]
        spans = [" ".join(sentences[i : i + size]) for i in range(len(sentences) - size + 1)]
        if len(spans) + len(sentences) <= self.max_windows:
            return spans + sentences  # single sentences catch short attacks padded by long neighbours
        # Over budget: spread the windows across the whole document rather than stopping early,
        # so an attack buried at the end of a long page is still seen. Windows overlap by one
        # sentence (step size - 1), so any attack of up to two sentences sits whole in one window.
        step = max(1, size - 1)
        starts = list(range(0, len(spans), step))
        if starts[-1] != len(spans) - 1:
            starts.append(len(spans) - 1)
        if len(starts) > self.max_windows:  # a very long text: even spacing, with gaps
            starts = _spread(starts, self.max_windows)
        windows = [spans[i] for i in starts]
        return windows + _spread(sentences, self.max_windows - len(windows))

    def scan(self, text: str, context: ScanContext) -> list[Detection]:
        if not text.strip() or not len(self.store):
            return []
        windows = self._windows(text)
        vectors = self.store.embedder.embed(windows)
        best_score, best_match, best_window = 0.0, None, ""
        for window, vector in zip(windows, vectors, strict=True):
            matches = self.store.query_vector(vector, k=1)
            if matches and matches[0].score > best_score:
                best_score, best_match, best_window = matches[0].score, matches[0], window
        if best_match is None or best_score < self.threshold:
            return []
        # Map similarity in [threshold, 1] onto severity in [0.5, 0.95].
        span = (self.threshold, 1.0)
        severity = 0.5 + 0.45 * (best_score - span[0]) / max(1e-9, span[1] - span[0])
        start = text.find(best_window)
        return [
            self.detection(
                "known_attack_similarity", Category.KNOWN_ATTACK.value, severity,
                f"Closely resembles a known attack (similarity {best_score:.2f}).",
                (start, start + len(best_window)) if start >= 0 and best_window != text else None,
                similarity=best_score, matched=best_match.text[:200], matched_source=best_match.metadata.get("source"),
            )
        ]  # fmt: skip

    def learn(self, text: str, **metadata: object) -> bool:
        """Add a confirmed attack to the store. Returns True if it was new."""
        return self.store.add([text], {"source": "learned", **metadata}) > 0


def _spread(items: list, n: int) -> list:  # type: ignore[type-arg]
    """`n` items evenly spaced across `items`, keeping the first and last."""
    if n <= 0:
        return []
    if n >= len(items):
        return list(items)
    if n == 1:
        return [items[0]]
    return [items[round(i * (len(items) - 1) / (n - 1))] for i in range(n)]
