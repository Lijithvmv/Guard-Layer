"""Canary tokens — detect system-prompt leakage and goal hijacking.

Two uses:
  * **Leak detection**: embed a random token in the system prompt. If it ever shows up in
    a response, the model disclosed its instructions.
  * **Goal-hijack detection**: instruct the model to always echo a token. If the token is
    missing from the response, an injected instruction likely took over.
"""

from __future__ import annotations

import re
import secrets
import threading
from collections import OrderedDict
from dataclasses import dataclass

_LEAK_TEMPLATE = "<!-- {token} -->\n{prompt}"
_ECHO_TEMPLATE = "{prompt}\n\nAlways begin your response with the exact marker {token} and nothing else on that line."


@dataclass(frozen=True)
class Canary:
    token: str
    prompt: str  # the prompt with the canary embedded
    echo: bool  # True if the model was asked to echo the token (goal-hijack mode)


class CanaryManager:
    """Generates canary tokens and remembers recent ones so outputs can be checked against them."""

    def __init__(self, prefix: str = "gl", byte_length: int = 8, max_tracked: int = 10_000) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,16}", prefix):
            raise ValueError("canary prefix must be 1-16 characters of [A-Za-z0-9_-]")
        self.prefix = prefix
        self.byte_length = byte_length
        self.max_tracked = max_tracked
        self._tokens: OrderedDict[str, bool] = OrderedDict()  # token -> echo mode
        self._lock = threading.Lock()
        self._token_re = re.compile(rf"\b{re.escape(prefix)}-[0-9a-f]{{{byte_length * 2}}}\b")

    def generate(self) -> str:
        return f"{self.prefix}-{secrets.token_hex(self.byte_length)}"

    def add(self, prompt: str, *, echo: bool = False, token: str | None = None) -> Canary:
        """Embed a canary in `prompt` and start tracking it."""
        token = token or self.generate()
        template = _ECHO_TEMPLATE if echo else _LEAK_TEMPLATE
        self.register(token, echo=echo)
        return Canary(token=token, prompt=template.format(token=token, prompt=prompt), echo=echo)

    def register(self, token: str, *, echo: bool = False) -> None:
        with self._lock:
            self._tokens[token] = echo
            self._tokens.move_to_end(token)
            while len(self._tokens) > self.max_tracked:
                self._tokens.popitem(last=False)

    def forget(self, token: str) -> None:
        with self._lock:
            self._tokens.pop(token, None)

    def is_echo(self, token: str) -> bool:
        with self._lock:
            return self._tokens.get(token, False)

    def find(self, text: str) -> list[str]:
        """Return tracked leak-mode canary tokens that appear in `text`."""
        with self._lock:
            return [t for t in self._token_re.findall(text) if t in self._tokens and not self._tokens[t]]

    def __len__(self) -> int:
        return len(self._tokens)
