"""Heuristic (rule-based) detector for injection, jailbreak, leakage and unsafe-command patterns.

The zero-dependency first layer: runs in microseconds, needs no model, and catches
the documented attack phrasings. To resist trivial evasion it matches every rule
against the raw text *and* against de-obfuscated views of it (homoglyph-folded,
leetspeak-folded, de-spaced, tag-smuggled ASCII, and decoded base64/hex/percent/rot13
payloads). Heuristics remain easy to paraphrase around, so combine them with the
similarity and classifier layers.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from pathlib import Path

from guardlayer.models import Detection, ScanContext
from guardlayer.normalize import decode_payloads, text_variants
from guardlayer.rules import DEFAULT_RULES, Rule, load_rules
from guardlayer.scanners.base import BaseScanner


class HeuristicScanner(BaseScanner):
    """Signature-based detector with de-obfuscation."""

    name = "heuristics"

    def __init__(
        self,
        rules: Sequence[Rule] | None = None,
        *,
        extra_rules: Iterable[Rule] = (),
        rules_file: str | Path | None = None,
        disabled_rules: Iterable[str] = (),
        deobfuscate: bool = True,
        directions: Iterable[str] | None = None,
    ) -> None:
        super().__init__(directions)
        selected = list(rules if rules is not None else DEFAULT_RULES) + list(extra_rules)
        if rules_file:
            selected += load_rules(rules_file)
        disabled = set(disabled_rules)
        self.rules: list[Rule] = [r for r in selected if r.name not in disabled]
        self.deobfuscate = deobfuscate
        self._compiled: list[tuple[Rule, re.Pattern[str]]] = [(r, r.compile()) for r in self.rules]

    def scan(self, text: str, context: ScanContext) -> list[Detection]:
        active = [(r, p) for r, p in self._compiled if context.direction in r.directions]
        if not active:
            return []

        detections: list[Detection] = []
        pending: list[tuple[Rule, re.Pattern[str]]] = []
        for rule, pattern in active:
            match = pattern.search(text)
            if match:
                detections.append(self._hit(rule, match.span(), variant="raw"))
            else:
                pending.append((rule, pattern))

        if pending and self.deobfuscate:
            views = list(text_variants(text).items())
            views += [(f"decoded:{enc}", decoded) for enc, decoded in decode_payloads(text)]
            for rule, pattern in pending:
                for variant, view in views:
                    if pattern.search(view):
                        # Offsets refer to the transformed view, so no span is reported.
                        detections.append(self._hit(rule, None, variant=variant))
                        break
        return detections

    def _hit(self, rule: Rule, span: tuple[int, int] | None, *, variant: str) -> Detection:
        message = rule.message if variant == "raw" else f"{rule.message} (found after {variant} de-obfuscation)"
        return self.detection(rule.name, rule.category, rule.severity, message, span, variant=variant)
