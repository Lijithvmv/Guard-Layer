"""Output-side leakage detectors: canary tokens and system-prompt overlap."""

from __future__ import annotations

import re
from collections.abc import Iterable

from guardlayer.canary import CanaryManager
from guardlayer.models import Category, Detection, ScanContext
from guardlayer.scanners.base import BaseScanner

LEAK = Category.SYSTEM_PROMPT_LEAK.value
_WORD_RE = re.compile(r"\w+")


class CanaryScanner(BaseScanner):
    """Flags responses that contain a leak canary or omit a required echo canary."""

    name = "canary"
    default_directions = frozenset({"output"})

    def __init__(self, manager: CanaryManager | None = None, *, directions: Iterable[str] | None = None) -> None:
        super().__init__(directions)
        self.manager = manager if manager is not None else CanaryManager()

    def scan(self, text: str, context: ScanContext) -> list[Detection]:
        found: list[Detection] = []
        leaked = set(self.manager.find(text))
        leaked.update(t for t in context.canary_tokens if t in text)
        for token in sorted(leaked):
            start = text.find(token)
            found.append(self.detection("canary_leak", LEAK, 1.0, "Response contains a canary token — the prompt leaked.", (start, start + len(token)), token=token))

        expected = context.expected_canary
        if expected and expected not in text:
            found.append(self.detection("canary_missing", Category.GOAL_HIJACK.value, 0.8, "Required echo canary is missing — the model's goal may have been hijacked.", token=expected))
        return found


class PromptLeakScanner(BaseScanner):
    """Detects a response reproducing substantial parts of the system prompt.

    Measures the share of the system prompt's word n-grams that reappear in the output.
    Needs `context.system_prompt`; does nothing without it.
    """

    name = "prompt_leak"
    default_directions = frozenset({"output"})

    def __init__(self, *, ngram: int = 5, min_coverage: float = 0.2, directions: Iterable[str] | None = None) -> None:
        super().__init__(directions)
        self.ngram = ngram
        self.min_coverage = min_coverage

    def scan(self, text: str, context: ScanContext) -> list[Detection]:
        if not context.system_prompt:
            return []
        sys_words = [w.lower() for w in _WORD_RE.findall(context.system_prompt)]
        out_words = [w.lower() for w in _WORD_RE.findall(text)]
        n = min(self.ngram, len(sys_words))
        if n < 3 or len(out_words) < n:
            return []
        sys_grams = {tuple(sys_words[i : i + n]) for i in range(len(sys_words) - n + 1)}
        out_grams = {tuple(out_words[i : i + n]) for i in range(len(out_words) - n + 1)}
        coverage = len(sys_grams & out_grams) / len(sys_grams)
        if coverage < self.min_coverage:
            return []
        severity = min(1.0, 0.55 + coverage * 0.6)
        return [
            self.detection(
                "system_prompt_overlap", LEAK, severity,
                f"Response reproduces {coverage:.0%} of the system prompt.",
                coverage=round(coverage, 3),
            )
        ]  # fmt: skip
