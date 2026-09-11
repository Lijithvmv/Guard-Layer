"""Heuristic (rule-based) detector for common prompt-injection and jailbreak patterns.

This is the zero-dependency core detector: it runs instantly, needs no model, and
catches the most common documented attack phrasings. It is deliberately a *first
layer* — heuristics are easy to evade, so they are meant to be combined with the
similarity and classifier scanners on the roadmap, not relied on alone.

Each rule is a (name, pattern, severity, message) tuple. Patterns are compiled
case-insensitively. Severities reflect how strongly the phrase indicates an attack.
"""

from __future__ import annotations

import re

from guardlayer.models import Detection, Direction

# (rule_name, regex, severity, message)
_RULES: list[tuple[str, str, float, str]] = [
    (
        "ignore_previous_instructions",
        r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|above|prior|earlier|all)\b.{0,20}\b(instruction|prompt|rule|context|message)s?\b",
        0.9,
        "Attempt to override prior instructions.",
    ),
    (
        "reveal_system_prompt",
        r"\b(reveal|show|print|repeat|tell me|what (is|are))\b.{0,30}\b(your )?(system|initial|original|hidden)\b.{0,15}\b(prompt|instruction|message|rule)s?\b",
        0.85,
        "Attempt to extract the system prompt.",
    ),
    (
        "role_override_persona",
        r"\byou are (now )?(a |an )?(dan|do anything now|unrestricted|jailbroken|developer mode|evil|unfiltered)\b",
        0.9,
        "Persona/role override (jailbreak persona).",
    ),
    (
        "developer_debug_mode",
        r"\b(enable|activate|switch to|enter)\b.{0,20}\b(developer|debug|god|sudo|admin|root)\b.{0,10}\bmode\b",
        0.8,
        "Request to enter a privileged/unrestricted mode.",
    ),
    (
        "override_guardrails",
        r"\b(bypass|disable|turn off|ignore)\b.{0,20}\b(safety|guardrail|filter|moderation|restriction|policy|policies)\b",
        0.85,
        "Attempt to disable safety controls.",
    ),
    (
        "pretend_hypothetical",
        r"\b(pretend|imagine|roleplay|let'?s say)\b.{0,40}\b(no (rules|restrictions|limits)|anything is allowed|without (any )?(restrictions|filter))\b",
        0.7,
        "Hypothetical framing used to elicit restricted output.",
    ),
    (
        "exfiltration_instruction",
        r"\b(send|post|exfiltrate|leak|forward|email)\b.{0,30}\b(secret|api key|token|password|credential|system prompt)s?\b",
        0.9,
        "Instruction to exfiltrate secrets.",
    ),
    (
        "long_base64_blob",
        r"\b[A-Za-z0-9+/]{200,}={0,2}\b",
        0.5,
        "Long base64-like blob (possible obfuscated payload).",
    ),
]


class HeuristicScanner:
    """Rule-based detector for well-known injection/jailbreak phrasings."""

    name = "heuristics"

    def __init__(self) -> None:
        self._compiled: list[tuple[str, re.Pattern[str], float, str]] = [
            (name, re.compile(pattern, re.IGNORECASE | re.DOTALL), severity, message)
            for name, pattern, severity, message in _RULES
        ]

    def scan(self, text: str, direction: Direction = "input") -> list[Detection]:
        detections: list[Detection] = []
        for rule, pattern, severity, message in self._compiled:
            match = pattern.search(text)
            if match:
                detections.append(
                    Detection(
                        scanner=self.name,
                        rule=rule,
                        severity=severity,
                        message=message,
                        span=match.span(),
                    )
                )
        return detections
