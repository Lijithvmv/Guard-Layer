"""Personally identifiable information (PII) detector.

Pattern matching with checksum validation where the format has one (Luhn for
payment cards, mod-97 for IBAN, Verhoeff for Aadhaar), which keeps false
positives low without any ML dependency. Pair with the REDACT action to mask
PII in model responses.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable

from guardlayer.models import Category, Detection, ScanContext
from guardlayer.scanners.base import BaseScanner, SpanIndex

PII = Category.PII.value


def luhn_valid(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_valid(iban: str) -> bool:
    iban = iban.replace(" ", "").upper()
    if not 15 <= len(iban) <= 34:
        return False
    rearranged = iban[4:] + iban[:4]
    try:
        return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1
    except ValueError:
        return False


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]  # fmt: skip
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]  # fmt: skip


def verhoeff_valid(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _valid_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified)


def _valid_phone(s: str) -> bool:
    n = len(_digits(s))
    return 10 <= n <= 15


# entity -> (pattern, severity, validator)
_ENTITIES: dict[str, tuple[str, float, Callable[[str], bool] | None]] = {
    "credit_card": (r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])", 0.8, lambda s: 13 <= len(_digits(s)) <= 19 and luhn_valid(_digits(s))),
    "aadhaar": (r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)", 0.7, lambda s: verhoeff_valid(_digits(s))),
    "us_ssn": (r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)", 0.8, None),
    "iban": (r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", 0.6, iban_valid),
    "email": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 0.3, None),
    "phone": (r"(?<![\w+])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,5}[ .-])\d{3,5}(?:[ .-]?\d{3,5})?(?![\w])|(?<![\w+])\+\d{10,14}(?!\w)", 0.3, _valid_phone),
    "indian_pan": (r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b", 0.5, None),
    "ip_address": (r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", 0.2, _valid_ip),
}

DEFAULT_ENTITIES: tuple[str, ...] = tuple(_ENTITIES)


class PIIScanner(BaseScanner):
    name = "pii"

    def __init__(self, entities: Iterable[str] | None = None, *, directions: Iterable[str] | None = None) -> None:
        super().__init__(directions)
        chosen = list(entities) if entities is not None else list(DEFAULT_ENTITIES)
        unknown = set(chosen) - set(_ENTITIES)
        if unknown:
            raise ValueError(f"unknown PII entities: {sorted(unknown)}; available: {sorted(_ENTITIES)}")
        # Keep the canonical order: specific, checksum-validated entities claim spans first.
        self._entities = [(e, re.compile(_ENTITIES[e][0]), _ENTITIES[e][1], _ENTITIES[e][2]) for e in _ENTITIES if e in chosen]

    def scan(self, text: str, context: ScanContext) -> list[Detection]:
        found: list[Detection] = []
        taken = SpanIndex()
        for entity, pattern, severity, validator in self._entities:
            for match in pattern.finditer(text):
                span = match.span()
                if taken.overlaps(span):
                    continue
                if validator and not validator(match.group()):
                    continue
                taken.add(span)
                found.append(self.detection(entity, PII, severity, f"Contains {entity.replace('_', ' ')}.", span))
        return found
