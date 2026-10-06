"""Replay helper: rebuild the files an agent wrote, so file rules judge their real content.

`untrusted_file_executed` opens a script to see what it would do. Replaying old sessions, the file is usually gone
(or changed since), so GuardLayer fails safe and holds: a measurement artefact. This keeps a virtual copy of every
file written in the transcript (Claude Code Write/Edit/MultiEdit; OpenHands str_replace_editor create/str_replace/
insert) and serves it to the rule. A file whose content can't be rebuilt (an edit to a file the transcript never
showed) is "unknown": `install(mode="hold")` keeps the fail-safe hold, `mode="skip"` judges it local, so a replay can
report both bounds. Counters say how often each case happened.
"""

from __future__ import annotations

import collections
import os
import tempfile
from typing import Any

import guardlayer.session as session_module
from guardlayer.consequence import file_consequence as _disk_file_consequence
from guardlayer.filelabels import normalise


class VirtualFiles:
    def __init__(self) -> None:
        self.content: dict[str, str | None] = {}  # normalised path -> text, or None when unknown
        self.counts: collections.Counter[str] = collections.Counter()
        self.missing: collections.Counter[str] = collections.Counter()  # paths looked up but never written in the transcript
        self._tmp = tempfile.mkdtemp(prefix="gl-vfs-")

    # ------------------------------------------------------------------ recording writes
    def record(self, tool: str, args: Any) -> None:
        if not isinstance(args, dict):
            return
        if tool == "Write":
            self._set(args.get("file_path"), args.get("content"))
        elif tool == "Edit":
            self._edit(args.get("file_path"), [(args.get("old_string"), args.get("new_string"), args.get("replace_all"))])
        elif tool == "MultiEdit":
            edits = [(e.get("old_string"), e.get("new_string"), e.get("replace_all")) for e in args.get("edits") or [] if isinstance(e, dict)]
            self._edit(args.get("file_path"), edits)
        elif tool == "str_replace_editor":
            cmd, path = args.get("command"), args.get("path")
            if cmd == "create":
                self._set(path, args.get("file_text"))
            elif cmd == "str_replace":
                self._edit(path, [(args.get("old_str"), args.get("new_str") or "", False)])
            elif cmd == "insert":
                base = self.content.get(normalise(path)) if path else None
                if base is None:
                    self._unknown(path)
                else:
                    lines = base.split("\n")
                    at = int(args.get("insert_line") or 0)
                    self._set(path, "\n".join(lines[:at] + [str(args.get("new_str") or "")] + lines[at:]))

    def _set(self, path: Any, text: Any) -> None:
        if isinstance(path, str) and path:
            self.content[normalise(path)] = text if isinstance(text, str) else None

    def _unknown(self, path: Any) -> None:
        if isinstance(path, str) and path:
            self.content[normalise(path)] = None

    def _edit(self, path: Any, edits: list[tuple[Any, Any, Any]]) -> None:
        if not isinstance(path, str) or not path:
            return
        text = self.content.get(normalise(path))
        if text is None:
            self._unknown(path)  # an edit to a file whose earlier content the transcript never showed
            return
        for old, new, every in edits:
            if not isinstance(old, str) or old not in text:
                self._unknown(path)
                return
            text = text.replace(old, str(new or ""), -1 if every else 1)
        self._set(path, text)

    # ------------------------------------------------------------------ serving the rule
    def install(self, mode: str = "hold") -> None:
        """Route GuardLayer's file-consequence lookups through the rebuilt files."""
        def file_consequence(path: str) -> str:
            key = normalise(path)
            if key in self.content:
                text = self.content[key]
                if text is None:
                    self.counts["unknown"] += 1
                    return "outbound" if mode == "hold" else "local"
                self.counts["rebuilt"] += 1
                tmp = os.path.join(self._tmp, "f" + os.path.splitext(key)[1])
                with open(tmp, "w", encoding="utf-8") as fh:
                    fh.write(text)
                return _disk_file_consequence(tmp)
            self.counts["not_written_in_transcript"] += 1
            self.missing[key] += 1
            return _disk_file_consequence(path) if os.path.exists(path) else ("outbound" if mode == "hold" else "local")

        session_module.file_consequence = file_consequence
