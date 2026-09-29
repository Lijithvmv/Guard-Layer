"""Content GuardLayer can't read as text: extract what it can, and label the rest untrusted.

A tool can return bytes (a PDF, an image, audio) or MCP-style content blocks (`{"type": "image", "data": ...}`). Turning
those into a string and "scanning" it would scan nothing while looking reassuring. Instead:

* **Extractors** turn known formats into text, which is scanned like any other content: PDF text with `pypdf`
  (`pip install "guardlayer[extract]"`) and image OCR with `pytesseract` (`pip install "guardlayer[ocr]"`, plus the
  Tesseract program). Both are optional; without them the content is simply unreadable. Add your own with
  `guard.extractors.append(fn)`, where `fn(data: bytes, mime: str) -> str | None`.
* **Unreadable content is untrusted.** Whatever can't be extracted (audio, video, binaries, images without OCR) marks the
  session untrusted, unless the tool is declared trusted, and is recorded as `unreadable_content`. So the containment rules
  still apply to an instruction hidden in an image nobody could read.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Iterable, Mapping
from typing import Any

Extractor = Callable[[bytes, str], "str | None"]
MAX_EXTRACT_BYTES = 20 * 1024 * 1024  # don't try to parse anything bigger

_MAGIC = (
    (b"%PDF", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"ID3", "audio/mpeg"),
    (b"fLaC", "audio/flac"),
    (b"OggS", "audio/ogg"),
)


def sniff(data: bytes) -> str:
    """The media type of `data` from its first bytes; text/plain if it decodes as mostly printable UTF-8."""
    for magic, mime in _MAGIC:
        if data.startswith(magic):
            return mime
    if data[:4] == b"RIFF" and data[8:12] in (b"WEBP", b"WAVE"):
        return "image/webp" if data[8:12] == b"WEBP" else "audio/wav"
    try:
        text = data[:4096].decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream"
    return "text/plain" if text and sum(c.isprintable() or c in "\r\n\t" for c in text) >= 0.95 * len(text) else "application/octet-stream"


def pdf_text(data: bytes, mime: str) -> str | None:
    """Text of a PDF (needs `pypdf`)."""
    if mime != "application/pdf":
        return None
    try:
        import io

        from pypdf import PdfReader
    except ModuleNotFoundError:
        return None
    try:
        reader = PdfReader(io.BytesIO(data))
        return "\n".join(page.extract_text() or "" for page in reader.pages[:200])
    except Exception:  # a malformed PDF is unreadable, not a crash
        return None


def ocr_text(data: bytes, mime: str) -> str | None:
    """Text in an image, by OCR (needs `pytesseract`, Pillow and the Tesseract program)."""
    if not mime.startswith("image/"):
        return None
    try:
        import io

        import pytesseract
        from PIL import Image
    except ModuleNotFoundError:
        return None
    try:
        return pytesseract.image_to_string(Image.open(io.BytesIO(data)))
    except Exception:  # Tesseract missing or the image unreadable
        return None


DEFAULT_EXTRACTORS: tuple[Extractor, ...] = (pdf_text, ocr_text)


def media_parts(result: Any) -> tuple[list[str], list[tuple[bytes, str]]] | None:
    """Split a tool result into text parts and binary parts, or None if it's ordinary (text/JSON) data.

    Handles raw bytes and MCP-style content blocks: `{"type": "text", "text": ...}`, `{"type": "image" | "audio",
    "data": <base64>, "mimeType": ...}`, and `{"type": "resource", "resource": {"blob": <base64>, "mimeType": ...}}`,
    alone or in a list.
    """
    if isinstance(result, (bytes, bytearray, memoryview)):
        data = bytes(result)
        mime = sniff(data)
        if mime == "text/plain":
            return [data.decode("utf-8", errors="replace")], []
        return [], [(data, mime)]
    blocks = result if isinstance(result, list) else [result] if isinstance(result, Mapping) else None
    if not blocks or not all(isinstance(b, Mapping) and b.get("type") in {"text", "image", "audio", "resource"} for b in blocks):
        return None
    if not any(b.get("type") in {"image", "audio"} or "blob" in (b.get("resource") or {}) for b in blocks):
        return None  # text-only blocks: the ordinary path handles them
    texts: list[str] = []
    blobs: list[tuple[bytes, str]] = []
    for b in blocks:
        payload = b.get("resource") if b.get("type") == "resource" else b
        if b.get("type") == "text":
            texts.append(str(b.get("text", "")))
        elif isinstance(payload, Mapping) and ("data" in payload or "blob" in payload):
            try:
                data = base64.b64decode(str(payload.get("data") or payload.get("blob")), validate=False)
            except (binascii.Error, ValueError):
                data = b""
            blobs.append((data, str(payload.get("mimeType") or sniff(data))))
        elif isinstance(payload, Mapping) and payload.get("text"):
            texts.append(str(payload["text"]))
    return texts, blobs


def extract(blobs: Iterable[tuple[bytes, str]], extractors: Iterable[Extractor]) -> tuple[list[str], list[str]]:
    """(extracted texts, media types that couldn't be read)."""
    texts: list[str] = []
    unreadable: list[str] = []
    for data, mime in blobs:
        text = None
        if 0 < len(data) <= MAX_EXTRACT_BYTES:
            for fn in extractors:
                text = fn(data, mime)
                if text and text.strip():
                    break
        if text and text.strip():
            texts.append(f"[text extracted from {mime}]\n{text}")
        else:
            unreadable.append(mime)
    return texts, unreadable
