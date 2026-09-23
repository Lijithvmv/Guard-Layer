"""Audit logging: a hook that writes each scan result as one JSON line.

By default the scanned text is NOT written — only its SHA-256 and length — so the
audit trail itself never becomes a store of user prompts, secrets or PII.

    guard.add_hook(AuditLogger("guardlayer-audit.jsonl", min_verdict=Verdict.FLAG))
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path
from typing import IO, Any

from guardlayer.models import ScanResult, Verdict

logger = logging.getLogger("guardlayer.audit")


class AuditLogger:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        stream: IO[str] | None = None,
        min_verdict: Verdict = Verdict.ALLOW,
        include_text: bool = False,
        use_logging: bool = False,
    ) -> None:
        if path is None and stream is None and not use_logging:
            raise ValueError("AuditLogger needs a path, a stream, or use_logging=True")
        self.path = Path(path) if path else None
        self.stream = stream
        self.min_verdict = min_verdict
        self.include_text = include_text
        self.use_logging = use_logging
        self._lock = threading.Lock()

    def record(self, result: ScanResult) -> dict[str, Any]:
        entry = result.to_dict(include_text=self.include_text)
        entry["text_sha256"] = hashlib.sha256(result.text.encode("utf-8")).hexdigest()
        entry["text_length"] = len(result.text)
        if not self.include_text:
            for d in entry["detections"]:  # matched values (e.g. secrets) must not leak into logs
                d["metadata"] = {k: v for k, v in d["metadata"].items() if k not in {"hidden_preview", "matched", "url", "token"}}
        return entry

    def __call__(self, result: ScanResult) -> None:
        if result.verdict < self.min_verdict:
            return
        line = json.dumps(self.record(result), ensure_ascii=False, default=str)
        with self._lock:
            if self.path:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            if self.stream:
                self.stream.write(line + "\n")
                self.stream.flush()
        if self.use_logging:
            level = logging.WARNING if result.verdict is Verdict.BLOCK else logging.INFO
            logger.log(level, line)
