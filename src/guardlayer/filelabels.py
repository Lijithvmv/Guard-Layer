"""File labels: a file written while the agent's context was untrusted or sensitive keeps that label.

Without this, an agent can launder a label through the file system: write a script while reading an untrusted page,
then run `bash deploy.sh`, a command that looks harmless on its own. With file labels:

* a tool that **writes** a path, while the session's label is above trusted/public, records that label for the path;
* any later tool call that **mentions** the path (reading it, uploading it, running it) raises the session's label to it,
  in this session or another one;
* **running** a file whose integrity is untrusted or hostile needs review (`untrusted_file_executed`).

Paths are normalised (`~` expanded, made absolute, case-folded on Windows). Relative paths resolve against the guard
process's working directory, which for hooks is the project directory. The store is bounded; the oldest entries go first.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from guardlayer.labels import BOTTOM, Label, combine

PATH_ARGUMENTS = ("path", "file_path", "filepath", "filename", "file", "target", "dest", "destination", "output", "notebook_path")
_TOKEN = re.compile(r"""[^\s'"`;|&<>(){}]+""")
MAX_FILES = 5000


def normalise(path: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(path.strip().strip("'\""))))


def looks_like_path(token: str) -> bool:
    return ("/" in token or "\\" in token or "." in token.lstrip(".")) and not token.startswith(("http://", "https://", "-"))


class FileLabelStore:
    """Path -> label. In memory by default; a JSON file when `path` is given (shared across processes)."""

    def __init__(self, path: str | Path | None = None, max_files: int = MAX_FILES) -> None:
        self.path = Path(path) if path else None
        self.max_files = max_files
        self._memory: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _load(self) -> dict[str, dict[str, Any]]:
        if self.path is None:
            return self._memory
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict[str, dict[str, Any]]) -> None:
        if len(data) > self.max_files:
            for key in sorted(data, key=lambda k: data[k].get("t", 0))[: len(data) - self.max_files]:
                del data[key]
        if self.path is None:
            self._memory = data
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def get(self, path: str) -> Label | None:
        entry = self._load().get(normalise(path))
        return Label.from_dict(entry) if entry else None

    def record(self, paths: Iterable[str], label: Label) -> None:
        """Remember `label` for each path (combined with any label it already has)."""
        if label == BOTTOM:
            return
        with self._lock:
            data = dict(self._load())
            for p in paths:
                key = normalise(p)
                old = Label.from_dict(data[key]) if key in data else BOTTOM
                data[key] = {**combine(old, label).to_dict(), "t": time.time()}
            self._save(data)

    def referenced(self, arguments: Mapping[str, Any] | str | None, text: str) -> list[tuple[str, Label]]:
        """Labelled files that a tool call mentions, by path argument or anywhere in its argument text."""
        data = self._load()
        if not data:
            return []
        from guardlayer.tools import argument_values

        candidates = {v for name in PATH_ARGUMENTS for v in argument_values(arguments, name)}
        candidates |= {t for t in _TOKEN.findall(text[:65_536]) if looks_like_path(t)}
        found = []
        for c in candidates:
            key = normalise(c)
            if key in data:
                found.append((key, Label.from_dict(data[key])))
        return found


def written_paths(arguments: Mapping[str, Any] | str | None) -> list[str]:
    from guardlayer.tools import argument_values

    return [v for name in PATH_ARGUMENTS for v in argument_values(arguments, name) if v]
