"""Prompt-response relevance — flags responses that drift away from what was asked.

A response unrelated to its prompt can mean an injected instruction hijacked the
model. Opt-in: it needs `context.prompt`, and is only reliable with a semantic
embedder (character n-grams cannot tell that an answer relates to a question).
"""

from __future__ import annotations

from collections.abc import Iterable

from guardlayer.models import Category, Detection, ScanContext
from guardlayer.scanners.base import BaseScanner
from guardlayer.vectorstore import Embedder, cosine


class RelevanceScanner(BaseScanner):
    name = "relevance"
    default_directions = frozenset({"output"})

    def __init__(self, embedder: Embedder, *, min_similarity: float = 0.2, directions: Iterable[str] | None = None) -> None:
        super().__init__(directions)
        self.embedder = embedder
        self.min_similarity = min_similarity

    def scan(self, text: str, context: ScanContext) -> list[Detection]:
        if not context.prompt or not text.strip():
            return []
        prompt_vec, response_vec = self.embedder.embed([context.prompt, text])
        similarity = cosine(prompt_vec, response_vec)
        if similarity >= self.min_similarity:
            return []
        return [
            self.detection(
                "off_topic_response", Category.GOAL_HIJACK.value, 0.45,
                f"Response is unrelated to the prompt (similarity {similarity:.2f}).",
                similarity=round(similarity, 3),
            )
        ]  # fmt: skip
