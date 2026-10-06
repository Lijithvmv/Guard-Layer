"""File labels: a file written while the agent's context was untrusted or sensitive keeps that label.

Experimental (0.7): not yet used outside tests and benchmarks; the stored format may change.

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


def _lookup(data: Mapping[str, Any], key: str) -> Any:
    """The label of a path, or of the nearest labelled directory above it (a cloned repository, a download folder)."""
    if key in data:
        return data[key]
    parent = os.path.dirname(key)
    while parent and parent != key:
        if parent in data:
            return data[parent]
        key, parent = parent, os.path.dirname(parent)
    return None


_INTERPRETERS = {"python", "python3", "py", "bash", "sh", "zsh", "node", "deno", "bun", "ruby", "perl", "php", "pwsh",
                 "powershell", "source", ".", "Rscript", "lua", "tsx", "ts-node"}


def deleted_paths(arguments: Mapping[str, Any] | str | None) -> list[str] | None:
    """The paths a plain delete command removes (`rm`, `del`, `Remove-Item`, after an optional `cd`), resolved against
    that `cd`; None if the command is anything else (a pipeline, a script, several commands)."""
    from guardlayer.shell import analyse  # local import: shell imports nothing from here

    command = arguments.get("command") or arguments.get("cmd") if isinstance(arguments, Mapping) else arguments
    if not isinstance(command, str):
        return None
    view = analyse(command.replace("\\", "/"))
    if view is None:
        return None
    cmds = [c for p in view.commands for c in p if c.argv]
    base = ""
    if len(cmds) == 2 and cmds[0].argv[0] == "cd" and len(cmds[0].argv) == 2:
        base = re.sub(r"^/([a-zA-Z])/", r"\1:/", cmds[0].argv[1])
        cmds = cmds[1:]
    if len(cmds) != 1 or re.split(r"[/\\]", cmds[0].argv[0])[-1].removesuffix(".exe") not in ("rm", "del", "unlink", "Remove-Item"):
        return None
    if cmds[0].redirects:
        return None
    targets = []
    for a in cmds[0].argv[1:]:
        if a.startswith("-") or a.startswith("$"):
            continue
        if any(ch in a for ch in "*?["):
            return None  # a glob: can't tell which files it removes
        a = re.sub(r"^/([a-zA-Z])/", r"\1:/", a)
        targets.append(a if os.path.isabs(a) or not base else os.path.join(base, a))
    return targets or None


def executed_paths(arguments: Mapping[str, Any] | str | None) -> list[str]:
    """Files a shell command runs: the program itself (`./build.sh`) or an interpreter's script (`python x.py`).
    A file it only reads, writes or redirects to (`tail run.log`, `> /dev/null`) is not run."""
    from guardlayer.shell import analyse  # local import: shell imports nothing from here

    command = arguments.get("command") or arguments.get("cmd") if isinstance(arguments, Mapping) else arguments
    if not isinstance(command, str):
        return []
    # Windows paths: bash would read their backslashes as escapes; for finding the file a command runs, they're
    # separators (paths are compared after `normalise`).
    view = analyse(command.replace("\\", "/"))
    if view is None:
        return []
    out: list[str] = []
    for pipeline in view.commands:
        for cmd in pipeline:
            if not cmd.argv:
                continue
            prog = cmd.argv[0]
            name = re.split(r"[/\\]", prog)[-1].removesuffix(".exe")
            if name in _INTERPRETERS:
                args = cmd.argv[1:]
                if args and args[0] in ("-c", "-m", "-e", "-Command", "-EncodedCommand"):
                    continue  # inline code or a module: no script file
                script = next((a for a in args if not a.startswith("-")), None)
                if script and script != "-":
                    out.append(script)
            elif looks_like_path(prog) and ("/" in prog or "\\" in prog):
                out.append(prog)
    return out


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
        entry = _lookup(self._load(), normalise(path))
        return Label.from_dict(entry) if entry else None

    def record(self, paths: Iterable[str], label: Label, *, check_created: bool = False) -> None:
        """Remember `label` for each path (combined with any label it already has).

        A file written in a clean context is recorded with the neutral label, which changes no rule (they act only on
        untrusted or confidential labels). With `check_created` (before the write runs), a path that doesn't exist
        yet and has no record is marked as created by the agent: deleting it later loses none of the user's data. A
        file the agent only edited is the user's and is never marked."""
        with self._lock:
            data = dict(self._load())
            for p in paths:
                key = normalise(p)
                old = Label.from_dict(data[key]) if key in data else BOTTOM
                created = data[key].get("created", False) if key in data else (check_created and not os.path.exists(key))
                data[key] = {**combine(old, label).to_dict(), "t": time.time(), "created": created}
            self._save(data)

    def created_by_agent(self, path: str) -> bool:
        entry = self._load().get(normalise(path))
        return bool(entry and entry.get("created"))

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
            entry = _lookup(data, key)
            if entry:
                found.append((key, Label.from_dict(entry)))
        return found


def written_paths(arguments: Mapping[str, Any] | str | None) -> list[str]:
    from guardlayer.tools import argument_values

    paths = [v for name in PATH_ARGUMENTS for v in argument_values(arguments, name) if v]
    command = arguments.get("command") or arguments.get("cmd") if isinstance(arguments, Mapping) else None
    if isinstance(command, str):
        paths += shell_written_paths(command)
    return paths


_OUTPUT_FLAGS = {"curl": ("-o", "--output"), "wget": ("-O", "--output-document", "-P", "--directory-prefix")}


def shell_written_paths(command: str) -> list[str]:
    """Files or directories a shell command writes: redirect targets, `curl -o`, `wget -O`/`-P`, `git clone` targets.

    A file downloaded and then read with a local command (`cat page.html`) must keep where it came from."""
    from guardlayer.shell import analyse  # local import: shell imports nothing from here

    view = analyse(command)
    if view is None:
        return []
    out: list[str] = []
    for pipeline in view.commands:
        for cmd in pipeline:
            out += [t for op, t in cmd.redirects if op in (">", ">>", "&>", "1>", "2>") and t not in ("/dev/null", "nul", "NUL")]
            if not cmd.argv:
                continue
            prog = re.split(r"[/\\]", cmd.argv[0])[-1].removesuffix(".exe")
            args = cmd.argv[1:]
            for flag in _OUTPUT_FLAGS.get(prog, ()):
                for i, a in enumerate(args):
                    if a == flag and i + 1 < len(args):
                        out.append(args[i + 1])
                    elif a.startswith(flag + "="):
                        out.append(a.split("=", 1)[1])
            if prog == "git" and args[:1] == ["clone"]:
                rest = [a for a in args[1:] if not a.startswith("-")]
                if len(rest) >= 2:
                    out.append(rest[1])
                elif rest:
                    out.append(re.sub(r"\.git$", "", rest[0].rstrip("/").rsplit("/", 1)[-1]))
    # A label on ".", "..", the working folder or a drive root would cover everything beneath it.
    return [p for p in out if p and p.strip("/\\") not in ("", ".", "..") and not re.fullmatch(r"[A-Za-z]:[/\\]?", p)
            and normalise(p) != normalise(os.getcwd())]
