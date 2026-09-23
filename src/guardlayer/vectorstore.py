"""A tiny, dependency-free vector store for known-attack similarity search.

The default `NgramEmbedder` turns text into a sparse, L2-normalised vector of hashed
character trigrams and word uni/bi-grams — cheap, deterministic, and good at catching
lightly-edited copies of known attacks. For paraphrase-level recall, plug in a
semantic embedder (`SentenceTransformerEmbedder`, or `CallableEmbedder` around any
embeddings API). Both kinds share the same store interface.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import zlib
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

from guardlayer.normalize import normalize

SparseVector = dict[int, float]
DenseVector = list[float]
Vector = SparseVector | DenseVector

_WORD_RE = re.compile(r"[a-z0-9']+")


class Embedder(Protocol):
    name: str

    def embed(self, texts: Sequence[str]) -> list[Vector]: ...


class NgramEmbedder:
    """Hashed char-trigram + word n-gram sparse embeddings (pure standard library)."""

    name = "ngram"

    def __init__(self, dim: int = 1 << 20) -> None:
        self.dim = dim

    def _features(self, text: str) -> Counter[str]:
        text = normalize(text).lower()
        words = _WORD_RE.findall(text)
        feats: Counter[str] = Counter()
        padded = f" {' '.join(words)} "
        for i in range(len(padded) - 2):
            feats["c:" + padded[i : i + 3]] += 1
        for w in words:
            feats["w:" + w] += 2
        for a, b in zip(words, words[1:], strict=False):
            feats["b:" + a + " " + b] += 3
        return feats

    def embed_one(self, text: str) -> SparseVector:
        vec: SparseVector = {}
        for feat, count in self._features(text).items():
            idx = zlib.crc32(feat.encode()) % self.dim
            vec[idx] = vec.get(idx, 0.0) + 1.0 + math.log(count)
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {k: v / norm for k, v in vec.items()}

    def embed(self, texts: Sequence[str]) -> list[Vector]:
        return [self.embed_one(t) for t in texts]


class CallableEmbedder:
    """Wrap any `fn(list[str]) -> list[list[float]]` (OpenAI, Ollama, Bedrock, ...)."""

    def __init__(self, fn: Callable[[list[str]], Sequence[Sequence[float]]], name: str = "callable") -> None:
        self.fn = fn
        self.name = name

    def embed(self, texts: Sequence[str]) -> list[Vector]:
        return [_unit(list(map(float, v))) for v in self.fn(list(texts))]


class SentenceTransformerEmbedder:
    """Local semantic embeddings (install the `embeddings` extra)."""

    def __init__(self, model: str = "sentence-transformers/all-MiniLM-L6-v2") -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ModuleNotFoundError as exc:  # pragma: no cover - optional dependency
            raise ModuleNotFoundError("SentenceTransformerEmbedder needs: pip install 'guardlayer[embeddings]'") from exc
        self._model = SentenceTransformer(model)
        self.name = f"st:{model}"

    def embed(self, texts: Sequence[str]) -> list[Vector]:  # pragma: no cover - optional dependency
        vectors = self._model.encode(list(texts), normalize_embeddings=True)
        return [list(map(float, v)) for v in vectors]


def _unit(vec: DenseVector) -> DenseVector:
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


def cosine(a: Vector, b: Vector) -> float:
    """Cosine similarity of two unit vectors (sparse dicts or dense lists)."""
    if isinstance(a, dict) and isinstance(b, dict):
        if len(a) > len(b):
            a, b = b, a
        return sum(v * b.get(k, 0.0) for k, v in a.items())
    if isinstance(a, dict) or isinstance(b, dict):
        raise TypeError("cannot compare sparse and dense vectors")
    return sum(x * y for x, y in zip(a, b, strict=True))


@dataclass
class Match:
    text: str
    score: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Entry:
    text: str
    vector: Vector
    metadata: dict[str, Any]


class VectorStore:
    """In-memory store with exact cosine search; persists as JSON (texts + metadata)."""

    def __init__(self, embedder: Embedder | None = None) -> None:
        self.embedder: Embedder = embedder or NgramEmbedder()
        self._entries: list[_Entry] = []
        self._hashes: set[str] = set()
        # Inverted index for sparse vectors: feature -> [(entry index, weight)]. Queries then
        # touch only entries sharing a feature, instead of every entry.
        self._postings: dict[int, list[tuple[int, float]]] = {}
        self._lock = threading.RLock()

    def __len__(self) -> int:
        return len(self._entries)

    def add(self, texts: Iterable[str], metadata: dict[str, Any] | None = None) -> int:
        """Add texts (de-duplicated). Returns how many were new."""
        fresh: list[str] = []
        with self._lock:
            for text in texts:
                text = text.strip()
                digest = hashlib.sha256(normalize(text).lower().encode()).hexdigest()
                if text and digest not in self._hashes:
                    self._hashes.add(digest)
                    fresh.append(text)
            if not fresh:
                return 0
            vectors = self.embedder.embed(fresh)
            for text, vector in zip(fresh, vectors, strict=True):
                if isinstance(vector, dict):
                    idx = len(self._entries)
                    for feature, weight in vector.items():
                        self._postings.setdefault(feature, []).append((idx, weight))
                self._entries.append(_Entry(text, vector, dict(metadata or {})))
        return len(fresh)

    def query(self, text: str, k: int = 3) -> list[Match]:
        return self.query_vector(self.embedder.embed([text])[0], k)

    def query_vector(self, vector: Vector, k: int = 3) -> list[Match]:
        with self._lock:
            if isinstance(vector, dict) and self._entries and isinstance(self._entries[0].vector, dict):
                sums: dict[int, float] = {}
                for feature, weight in vector.items():
                    for idx, other in self._postings.get(feature, ()):
                        sums[idx] = sums.get(idx, 0.0) + weight * other
                scored = [(score, self._entries[idx]) for idx, score in sums.items()]
            else:
                scored = [(cosine(vector, e.vector), e) for e in self._entries]
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [Match(e.text, round(s, 4), e.metadata) for s, e in scored[:k]]

    def save(self, path: str | Path) -> None:
        with self._lock:
            data = {"embedder": self.embedder.name, "entries": [{"text": e.text, "metadata": e.metadata} for e in self._entries]}
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")

    def load(self, path: str | Path) -> int:
        """Load texts from a .json store file or a plain .txt file (one text per line, # comments)."""
        path = Path(path)
        raw = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            added = 0
            for item in json.loads(raw)["entries"]:
                added += self.add([item["text"]], item.get("metadata"))
            return added
        return self.add(_lines(raw), {"source": path.name})


def _lines(raw: str) -> list[str]:
    return [line.strip() for line in raw.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def builtin_attack_corpus() -> list[str]:
    """The bundled corpus of known injection/jailbreak prompts."""
    return _lines(resources.files("guardlayer.data").joinpath("known_attacks.txt").read_text(encoding="utf-8"))
