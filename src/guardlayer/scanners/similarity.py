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
        max_windows: int = 64,
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
        if len(sentences) <= self.window_sentences:
            return [text]
        windows = [" ".join(sentences[i : i + self.window_sentences]) for i in range(len(sentences) - self.window_sentences + 1)]
        windows += sentences  # single sentences catch short attacks padded by long neighbours
        return windows[: self.max_windows]

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
