"""Text normalization and de-obfuscation.

Attackers dodge pattern matching with homoglyphs, invisible characters, leetspeak,
s p a c e d letters and encoded payloads. These helpers produce alternative *views*
of a text that scanners can match against in addition to the raw text.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import math
import re
import unicodedata
from collections import Counter
from urllib.parse import unquote

# Zero-width, soft-hyphen and other invisible formatting characters.
INVISIBLE_RE = re.compile("[­᠎​-‏⁠-⁤﻿]")
# Bidirectional overrides/isolates ("Trojan Source").
BIDI_RE = re.compile("[‪-‮⁦-⁩]")
# Unicode tag block: invisible, but maps 1:1 onto ASCII ("ASCII smuggling").
TAG_RE = re.compile("[\U000e0000-\U000e007f]")

_WS_RE = re.compile(r"\s+")
_SPACED_RE = re.compile(r"\b(?:[A-Za-z][ .\-_*|]){3,}[A-Za-z]\b")
_SPACED_SEP_RE = re.compile(r"[ .\-_*|]")
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){10,}\b")
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_ROT13_HINT_RE = re.compile(r"\brot[\s-]?13\b", re.IGNORECASE)

# Common Cyrillic / Greek look-alikes folded onto Latin.
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
        "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
        "ɡ": "g", "һ": "h", "ӏ": "l", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
        "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J",
        "Ѕ": "S", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
        "τ": "t", "υ": "u", "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
        "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y",
        "Χ": "X",
    }
)  # fmt: skip

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})


def decode_tag_chars(text: str) -> str:
    """Recover ASCII hidden in Unicode tag characters (U+E0000–U+E007F)."""
    return "".join(chr(ord(ch) - 0xE0000) for ch in TAG_RE.findall(text) if 0x20 <= ord(ch) - 0xE0000 < 0x7F)


def normalize(text: str, *, collapse_whitespace: bool = True) -> str:
    """NFKC-normalize, drop invisible characters, fold homoglyphs, collapse whitespace."""
    out = unicodedata.normalize("NFKC", text)
    out = TAG_RE.sub("", out)
    out = INVISIBLE_RE.sub("", out)
    out = BIDI_RE.sub("", out)
    out = out.translate(_CONFUSABLES)
    return _WS_RE.sub(" ", out).strip() if collapse_whitespace else out


def despace(text: str) -> str:
    """Join s-p-a-c-e-d o.u.t letters back into words."""
    return _SPACED_RE.sub(lambda m: _SPACED_SEP_RE.sub("", m.group()), text)


def text_variants(text: str) -> dict[str, str]:
    """Alternative views of `text` worth scanning, excluding the raw text itself.

    Keys name the transformation; only variants that differ from the raw text are returned.
    """
    variants: dict[str, str] = {}
    norm = normalize(text)
    candidates = {
        "normalized": norm,
        "leetspeak": norm.translate(_LEET),
        # De-space before collapsing whitespace: wider gaps mark the original word boundaries.
        "despaced": _WS_RE.sub(" ", despace(normalize(text, collapse_whitespace=False))).strip(),
        "smuggled": decode_tag_chars(text),
    }
    seen = {text}
    for name, value in candidates.items():
        if value and value not in seen:
            variants[name] = value
            seen.add(value)
    return variants


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(ch.isprintable() or ch in "\n\r\t" for ch in text) / len(text)


def _looks_like_text(decoded: str) -> bool:
    return len(decoded) >= 8 and printable_ratio(decoded) >= 0.95 and any(ch.isalpha() for ch in decoded) and " " in decoded


def decode_payloads(text: str, *, max_items: int = 8) -> list[tuple[str, str]]:
    """Find and decode embedded base64 / hex / percent-encoded / rot13 payloads.

    Returns (encoding, decoded_text) pairs for payloads that decode to readable text.
    """
    found: list[tuple[str, str]] = []

    for match in _B64_RE.finditer(text):
        token = match.group()
        if token.isalpha() and not any(ch.isupper() for ch in token[1:]):
            continue  # a long ordinary word, not base64
        padded = token + "=" * (-len(token) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(padded).decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if _looks_like_text(decoded):
                found.append(("base64", decoded))
                break
        if len(found) >= max_items:
            return found

    for match in _HEX_RE.finditer(text):
        try:
            decoded = bytes.fromhex(match.group()).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(decoded):
            found.append(("hex", decoded))

    if len(_PCT_RE.findall(text)) >= 3:
        decoded = unquote(text)
        if decoded != text:
            found.append(("percent", decoded))

    if _ROT13_HINT_RE.search(text):
        found.append(("rot13", codecs.decode(text, "rot13")))

    return found[:max_items]


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())
