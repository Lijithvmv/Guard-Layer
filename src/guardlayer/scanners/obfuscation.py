"""Obfuscation detector: invisible characters, ASCII smuggling, homoglyphs, encoded blobs.

Hiding instructions from the human reviewer while leaving them readable to the model
is a hallmark of injection. This scanner flags the hiding itself, independent of
what is hidden (the heuristic scanner separately inspects the decoded content).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from guardlayer.models import Category, Detection, ScanContext
from guardlayer.normalize import BIDI_RE, INVISIBLE_RE, TAG_RE, decode_payloads, decode_tag_chars, shannon_entropy
from guardlayer.scanners.base import BaseScanner

OBF = Category.OBFUSCATION.value

_MIXED_SCRIPT_RE = re.compile(r"\b(?=\w*[A-Za-z])(?=\w*[Ͱ-ϿЀ-ӿ])\w{3,}\b")
_BLOB_RE = re.compile(r"[A-Za-z0-9+/=_-]{120,}")


class ObfuscationScanner(BaseScanner):
    name = "obfuscation"

    def __init__(
        self,
        *,
        zero_width_threshold: int = 3,
        blob_min_length: int = 120,
        entropy_threshold: float = 5.3,
        directions: Iterable[str] | None = None,
    ) -> None:
        super().__init__(directions)
        self.zero_width_threshold = zero_width_threshold
        self.blob_re = _BLOB_RE if blob_min_length == 120 else re.compile(rf"[A-Za-z0-9+/=_-]{{{blob_min_length},}}")
        self.entropy_threshold = entropy_threshold

    def scan(self, text: str, context: ScanContext) -> list[Detection]:
        found: list[Detection] = []

        tags = TAG_RE.search(text)
        if tags:
            hidden = decode_tag_chars(text)
            found.append(
                self.detection(
                    "ascii_smuggling", OBF, 0.9,
                    "Invisible Unicode tag characters encode hidden ASCII text.",
                    tags.span(), hidden_preview=hidden[:200],
                )
            )  # fmt: skip

        bidi = BIDI_RE.search(text)
        if bidi:
            found.append(self.detection("bidi_override", OBF, 0.6, "Bidirectional override characters (text-reordering trick).", bidi.span()))

        zero_width = INVISIBLE_RE.findall(text)
        if len(zero_width) >= self.zero_width_threshold:
            first = INVISIBLE_RE.search(text)
            found.append(
                self.detection(
                    "zero_width_chars", OBF, min(0.7, 0.3 + 0.05 * len(zero_width)),
                    f"{len(zero_width)} zero-width/invisible characters.",
                    first.span() if first else None, count=len(zero_width),
                )
            )  # fmt: skip

        mixed = _MIXED_SCRIPT_RE.search(text)
        if mixed:
            found.append(self.detection("homoglyph_mixed_script", OBF, 0.5, f"Word mixes Latin and Cyrillic/Greek letters: {mixed.group()!r}.", mixed.span()))

        blob = self.blob_re.search(text)
        if blob:
            decodable = bool(decode_payloads(blob.group(), max_items=1))
            found.append(
                self.detection(
                    "encoded_blob", OBF, 0.5 if decodable else 0.3,
                    "Long encoded blob" + (" that decodes to readable text." if decodable else "."),
                    blob.span(), decodes_to_text=decodable,
                )
            )  # fmt: skip

        if len(text) >= 200 and not blob:
            entropy = shannon_entropy(text)
            whitespace = sum(ch.isspace() for ch in text) / len(text)
            if entropy >= self.entropy_threshold and whitespace < 0.05:
                found.append(self.detection("high_entropy", OBF, 0.3, f"Unusually high character entropy ({entropy:.2f} bits/char).", entropy=round(entropy, 2)))

        return found
