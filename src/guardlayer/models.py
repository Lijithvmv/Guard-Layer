"""Core data models: verdicts, detections, scan context and scan results.

Kept dependency-free (standard library only) so the engine imports and runs
anywhere; optional integrations (API, embeddings, classifiers) live behind extras.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Literal

# Where a piece of text sits relative to the model:
#   input   - untrusted text going INTO the model (user prompt)
#   output  - text coming OUT of the model (response, tool-call arguments)
#   context - third-party text the model will read (RAG chunks, web pages, tool results);
#             the channel for *indirect* prompt injection.
Direction = Literal["input", "output", "context"]
DIRECTIONS: tuple[str, ...] = ("input", "output", "context")


class Verdict(str, Enum):
    """Overall decision for a scanned piece of text."""

    ALLOW = "allow"  # nothing notable found
    FLAG = "flag"  # suspicious — log / review, do not necessarily block
    BLOCK = "block"  # high-confidence threat — stop it

    @property
    def rank(self) -> int:
        return _VERDICT_RANK[self]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Verdict):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Verdict):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Verdict):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Verdict):
            return NotImplemented
        return self.rank < other.rank


_VERDICT_RANK = {Verdict.ALLOW: 0, Verdict.FLAG: 1, Verdict.BLOCK: 2}


class Category(str, Enum):
    """Threat categories. Detections carry the string value, so custom scanners may add their own."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    DATA_EXFILTRATION = "data_exfiltration"
    SECRET = "secret"
    PII = "pii"
    OBFUSCATION = "obfuscation"
    KNOWN_ATTACK = "known_attack"
    UNSAFE_COMMAND = "unsafe_command"
    UNSAFE_LINK = "unsafe_link"
    RESOURCE_ABUSE = "resource_abuse"
    GOAL_HIJACK = "goal_hijack"
    POLICY = "policy"


class Action(str, Enum):
    """What the pipeline does with a detection of a given category."""

    SCORE = "score"  # contribute severity to the aggregate risk score (default)
    BLOCK = "block"  # force a BLOCK verdict regardless of score
    FLAG = "flag"  # force at least a FLAG verdict
    REDACT = "redact"  # mask the matched span in the returned text; not scored
    LOG = "log"  # record only; neither scored nor acted on


@dataclass(frozen=True)
class Detection:
    """A single signal raised by one scanner."""

    scanner: str  # which scanner produced this (e.g. "heuristics")
    rule: str  # the specific rule that matched (e.g. "ignore_previous_instructions")
    category: str  # a Category value (or a custom string)
    severity: float  # 0.0–1.0 confidence/impact of this single signal
    message: str  # human-readable explanation
    span: tuple[int, int] | None = None  # (start, end) offsets in the scanned text, if applicable
    metadata: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def __post_init__(self) -> None:
        if not 0.0 <= self.severity <= 1.0:
            raise ValueError("severity must be within [0.0, 1.0]")
        if isinstance(self.category, Category):
            object.__setattr__(self, "category", self.category.value)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["span"] = list(self.span) if self.span else None
        return data


@dataclass
class ScanContext:
    """Everything a scanner may need besides the text itself.

    Output scanners use `prompt`/`system_prompt`/`canary_tokens` to detect leakage and
    hijacking; `metadata` is free-form (user id, session id, tool name, source URL, ...).
    """

    direction: Direction = "input"
    prompt: str | None = None  # the user prompt that produced an output
    system_prompt: str | None = None  # the system prompt, to detect it leaking
    canary_tokens: list[str] = field(default_factory=list)  # tokens that must NOT appear in output
    expected_canary: str | None = None  # a token that MUST appear in output (goal-hijack check)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """The aggregated outcome of running the pipeline over one text."""

    verdict: Verdict
    score: float  # 0.0–1.0 aggregate risk
    direction: Direction
    detections: list[Detection] = field(default_factory=list)
    text: str = ""  # the text to use downstream — redacted if any REDACT action fired
    modified: bool = False  # True when `text` differs from the scanned input
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = field(default_factory=time.time)
    latency_ms: float = 0.0
    timings_ms: dict[str, float] = field(default_factory=dict)  # per-scanner latency
    errors: list[str] = field(default_factory=list)  # scanners that raised
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK

    @property
    def is_flagged(self) -> bool:
        return self.verdict is Verdict.FLAG

    @property
    def allowed(self) -> bool:
        """True unless the verdict is BLOCK."""
        return self.verdict is not Verdict.BLOCK

    @property
    def categories(self) -> list[str]:
        return sorted({d.category for d in self.detections})

    def to_dict(self, *, include_text: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "timestamp": self.timestamp,
            "verdict": self.verdict.value,
            "score": self.score,
            "direction": self.direction,
            "categories": self.categories,
            "detections": [d.to_dict() for d in self.detections],
            "modified": self.modified,
            "latency_ms": self.latency_ms,
            "timings_ms": self.timings_ms,
            "errors": self.errors,
            "metadata": self.metadata,
        }
        if include_text:
            data["text"] = self.text
        return data

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), default=str, **kwargs)
