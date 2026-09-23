"""Secret / credential detector.

Catches API keys, tokens, private keys and passwords in prompts (users pasting
credentials into a third-party model) and in responses (the model or a tool
leaking them). By default the pipeline *redacts* secret matches rather than
scoring them, so the text can still flow with the secret masked.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from guardlayer.models import Category, Detection, ScanContext
from guardlayer.normalize import shannon_entropy
from guardlayer.scanners.base import BaseScanner, SpanIndex

SECRET = Category.SECRET.value

# (rule, pattern, severity, capture group holding the secret value (0 = whole match))
_SECRET_PATTERNS: list[tuple[str, str, float, int]] = [
    ("private_key", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)", 1.0, 0),
    ("aws_access_key_id", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", 0.9, 0),
    ("aws_secret_access_key", r"(?i)\baws[\w.-]{0,20}(?:secret|private)[\w.-]{0,20}\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})\b", 0.95, 1),
    ("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}", 0.95, 0),
    ("openai_api_key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}", 0.9, 0),
    ("github_token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b", 0.95, 0),
    ("gitlab_token", r"\bglpat-[A-Za-z0-9_-]{20,}\b", 0.95, 0),
    ("slack_token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b", 0.9, 0),
    ("slack_webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}", 0.8, 0),
    ("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", 0.9, 0),
    ("stripe_key", r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\b", 0.95, 0),
    ("huggingface_token", r"\bhf_[A-Za-z0-9]{34,}\b", 0.9, 0),
    ("twilio_key", r"\bSK[0-9a-fA-F]{32}\b", 0.7, 0),
    ("sendgrid_key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", 0.95, 0),
    ("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b", 0.9, 0),
    ("azure_storage_key", r"(?i)\bAccountKey=([A-Za-z0-9+/=]{40,})", 0.95, 1),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", 0.7, 0),
    ("url_credentials", r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:([^\s@/]{3,})@[^\s/]+", 0.85, 1),
    ("bearer_token", r"(?i)\bauthorization\s*:\s*bearer\s+([A-Za-z0-9._~+/-]{16,}=*)", 0.85, 1),
]  # fmt: skip

_GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|token|passw(?:or)?d|pwd|client[_-]?secret|private[_-]?key)\b"
    r"[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{8,})"
)


class SecretsScanner(BaseScanner):
    name = "secrets"

    def __init__(
        self,
        *,
        generic_assignments: bool = True,
        min_generic_entropy: float = 3.0,
        disabled_rules: Iterable[str] = (),
        directions: Iterable[str] | None = None,
    ) -> None:
        super().__init__(directions)
        disabled = set(disabled_rules)
        self._patterns = [(rule, re.compile(p), sev, grp) for rule, p, sev, grp in _SECRET_PATTERNS if rule not in disabled]
        self.generic_assignments = generic_assignments and "generic_secret" not in disabled
        self.min_generic_entropy = min_generic_entropy

    def scan(self, text: str, context: ScanContext) -> list[Detection]:
        found: list[Detection] = []
        taken = SpanIndex()

        for rule, pattern, severity, group in self._patterns:
            for match in pattern.finditer(text):
                span = match.span(group)
                if span[0] < 0 or taken.overlaps(span):
                    continue
                taken.add(span)
                found.append(self.detection(rule, SECRET, severity, f"Possible {rule.replace('_', ' ')}.", span))

        if self.generic_assignments:
            for match in _GENERIC_ASSIGNMENT.finditer(text):
                value = match.group(2)
                span = match.span(2)
                if taken.overlaps(span) or shannon_entropy(value) < self.min_generic_entropy or _is_placeholder(value):
                    continue
                taken.add(span)
                found.append(self.detection("generic_secret", SECRET, 0.6, f"Value assigned to {match.group(1)!r} looks like a secret.", span))
        return found


_PLACEHOLDER_RE = re.compile(r"(?i)^(<[^>]*>|\$\{?[\w.]+\}?|\{\{.*\}\}|x{4,}|\*{4,}|(your|my|the|example|dummy|changeme|placeholder|redacted)[\w-]*|os\.environ.*|process\.env.*)$")


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.match(value))
