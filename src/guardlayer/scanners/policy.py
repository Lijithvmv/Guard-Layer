"""Policy scanners: resource limits (flooding, many-shot) and custom deny-lists."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable

from guardlayer.models import Category, Detection, ScanContext
from guardlayer.scanners.base import BaseScanner

_TURN_RE = re.compile(r"^\s*(user|human|assistant|ai|bot|q|a|question|answer)\s*:", re.IGNORECASE | re.MULTILINE)
_WORD_RE = re.compile(r"\w+")
_CHAR_RUN_RE = re.compile(r"(.)\1{199,}", re.DOTALL)


class LimitsScanner(BaseScanner):
    """Oversized inputs, token flooding, and many-shot jailbreak structure."""

    name = "limits"
    default_directions = frozenset({"input", "context"})

    def __init__(
        self,
        *,
        max_chars: int = 50_000,
        max_turns: int = 16,
        flood_ratio: float = 0.4,
        directions: Iterable[str] | None = None,
    ) -> None:
        super().__init__(directions)
        self.max_chars = max_chars
        self.max_turns = max_turns
        self.flood_ratio = flood_ratio

    def scan(self, text: str, context: ScanContext) -> list[Detection]:
        found: list[Detection] = []
        abuse = Category.RESOURCE_ABUSE.value
        if len(text) > self.max_chars:
            found.append(self.detection("oversized_input", abuse, 0.6, f"Input is {len(text):,} chars (limit {self.max_chars:,}).", length=len(text)))

        turns = len(_TURN_RE.findall(text))
        if turns >= self.max_turns:
            found.append(self.detection("many_shot_pattern", Category.JAILBREAK.value, 0.6, f"{turns} embedded dialogue turns (many-shot jailbreak pattern).", turns=turns))

        words = [w.lower() for w in _WORD_RE.findall(text)]
        if len(words) >= 200:
            word, count = Counter(words).most_common(1)[0]
            if count / len(words) >= self.flood_ratio:
                found.append(self.detection("token_flooding", abuse, 0.5, f"Word {word!r} makes up {count / len(words):.0%} of the input.", ratio=round(count / len(words), 3)))

        run = _CHAR_RUN_RE.search(text)
        if run:
            found.append(self.detection("character_flooding", abuse, 0.4, "Very long run of a repeated character.", run.span()))
        return found


class DenyListScanner(BaseScanner):
    """Blocks custom terms / regexes: banned topics, confidential codenames, competitor names..."""

    name = "denylist"

    def __init__(
        self,
        terms: Iterable[str] = (),
        patterns: Iterable[str] = (),
        *,
        severity: float = 0.9,
        category: str = Category.POLICY.value,
        directions: Iterable[str] | None = None,
    ) -> None:
        super().__init__(directions)
        self.severity = severity
        self.category = category
        self._matchers: list[tuple[str, re.Pattern[str]]] = [(t, re.compile(rf"(?<!\w){re.escape(t)}(?!\w)", re.IGNORECASE)) for t in terms if t]
        self._matchers += [(p, re.compile(p, re.IGNORECASE)) for p in patterns if p]

    def scan(self, text: str, context: ScanContext) -> list[Detection]:
        found: list[Detection] = []
        for label, pattern in self._matchers:
            match = pattern.search(text)
            if match:
                found.append(self.detection("denylist_match", self.category, self.severity, f"Matches deny-list entry {label!r}.", match.span(), entry=label))
        return found
