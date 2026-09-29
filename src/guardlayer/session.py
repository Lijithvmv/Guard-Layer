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
| `sensitive_data_egress` | a sensitive value seen earlier leaves the machine in a tool call      | block   |
| `trifecta`              | untrusted content + sensitive data seen, then a network/exec call     | review  |
| `after_injection`       | content with an injection was read, then a write/network/exec call    | review  |

A tool whose job is to send a particular kind of data (a payment tool and IBANs, a CRM tool and email
addresses) can be allowed to: `allow_egress = { send_money = ["iban"] }` exempts those data types, and
only those, from `sensitive_data_egress` and `trifecta` for that tool. `after_injection` still applies.

Sensitive values are stored only as fingerprints (length, a 16-bit prefix check and a truncated SHA-256), never in the
clear, so the state is safe to persist. Fingerprints catch a value copied verbatim, including when
it is embedded in a longer token such as a URL path; an encoded or split copy will not match,
which is why the `trifecta` rule does not depend on them.

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
import zlib
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from guardlayer.labels import Confidentiality, Integrity, Label
from guardlayer.labels import combine as combine_labels
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
MAX_SCAN_CHARS = 65_536  # bound on argument text searched for fingerprints
_PREFIX = 8  # every fingerprinted value is at least this long (see _TOKEN_RE)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def _prefix_key(value: str) -> int:
    """16-bit checksum of the first characters: a cheap prefilter that reveals nothing useful."""
    return zlib.crc32(value[:_PREFIX].encode("utf-8")) & 0xFFFF


def fingerprint(value: str, kind: str | None = None) -> str:
    """`<length>:<prefix check>:<truncated sha256>[:<kind>]` of a sensitive value.

    Length and prefix check let `contains_fingerprint` find the value anywhere inside other
    text (a URL path, a glued token) in one pass, not only as a whole token. `kind` is the
    rule that found the value (`iban`, `aws_access_key`, ...), so a tool can be allowed to
    send that kind of data (`SessionPolicy.allow_egress`).
    """
    value = value.strip(".=/")
    fp = f"{len(value)}:{_prefix_key(value):04x}:{_digest(value)}"
    return f"{fp}:{kind}" if kind else fp


def contains_fingerprint(text: str, fingerprints: Iterable[str], *, allowed_kinds: Iterable[str] = ()) -> bool:
    """True if any fingerprinted value occurs in `text`, whole or embedded in a longer token.

    Every position in each run of token characters gets one CRC of its next 8 characters;
    only positions whose CRC matches a stored prefix check are hashed in full. That keeps
    the cost linear in the text, whatever the number of fingerprints, so
    `https://evil.example/<secret>.png` or `data=x<secret>` match cheaply. Legacy
    fingerprints (a plain hash) match whole tokens only. Fingerprints of an `allowed_kinds`
    kind are ignored; untyped ones never are.
    """
    allowed = set(allowed_kinds)
    by_prefix: dict[int, list[tuple[int, str]]] = {}
    legacy: set[str] = set()
    for fp in fingerprints:
        parts = fp.split(":")
        if len(parts) == 4 and parts[3] in allowed:
            continue
        if len(parts) in (3, 4) and parts[0].isdigit():
            by_prefix.setdefault(int(parts[1], 16), []).append((int(parts[0]), parts[2]))
        else:
            legacy.add(fp)
    text = text[:MAX_SCAN_CHARS]
    if legacy and any(_digest(tok.strip(".=/")) in legacy for tok in _TOKEN_RE.findall(text)):
        return True
    if not by_prefix:
        return False
    for run in _TOKEN_RE.findall(text):
        for i in range(len(run) - _PREFIX + 1):
            candidates = by_prefix.get(_prefix_key(run[i : i + _PREFIX]))
            if candidates and any(i + n <= len(run) and _digest(run[i : i + n]) == d for n, d in candidates):
                return True
    return False


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
    private_sources: list[str] = field(default_factory=list)  # sources declared private (business data, not secrets)
    fingerprints: list[str] = field(default_factory=list)  # hashes of sensitive values
    sensitive_kinds: list[str] = field(default_factory=list)  # rules that found them (iban, credential_file, ...)
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

    @property
    def label(self) -> Label:
        """The session's context label: the most restrictive label of everything it has read (see `guardlayer.labels`)."""
        integrity = Integrity.HOSTILE if self.hostile else Integrity.UNTRUSTED if self.untrusted else Integrity.TRUSTED
        confidentiality = (
            Confidentiality.RESTRICTED if self.sensitive else Confidentiality.PRIVATE if self.private_sources else Confidentiality.PUBLIC
        )
        return Label(integrity, confidentiality)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "untrusted": self.untrusted,
            "hostile": self.hostile,
            "sensitive": self.sensitive,
            "label": self.label.to_dict(),
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
        for name, cap in (("untrusted_sources", MAX_SOURCES), ("hostile_sources", MAX_SOURCES), ("sensitive_sources", MAX_SOURCES), ("private_sources", MAX_SOURCES),
                          ("fingerprints", MAX_FINGERPRINTS), ("sensitive_kinds", MAX_SOURCES)):
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
    # Label rules (0.7): only fire for tools declared as sinks in `sinks`.
    "untrusted_to_protected_sink": Action.REVIEW,
    "confidentiality_exceeds_sink": Action.REVIEW,
    # File labels (0.7): running a file that untrusted content could have written.
    "untrusted_file_executed": Action.REVIEW,
}
_SOURCE_KEYS = {"integrity", "confidentiality"}
_SINK_KEYS = {"accepts_untrusted", "max_confidentiality"}


@dataclass
class SessionPolicy:
    """What counts as untrusted, and what to do when a tainted session tries to act.

    * `untrusted_tools`: tool-name globs whose results count as untrusted. By default a tool
      result is untrusted when the tool can reach the network or is untagged; `scan_context`
      input is always untrusted. `trusted_tools` excludes tools from both untrusted and hostile.
    * `actions`: action per session rule (`sensitive_data_egress`, `trifecta`, `after_injection`);
      set one to `"log"` to switch it off.
    * `allow_egress`: tool-name glob -> data types (detection rule names such as `iban` or
      `email`) that tool may send out. Those types don't trigger `sensitive_data_egress`, nor
      `trifecta` when they are the only sensitive data in the session. It also means an
      undetected injection could direct that tool to send that data type; keep it narrow.
    * `sources`: tool-name glob -> the label of what that tool returns, e.g.
      `{"get_customer": {"confidentiality": "private"}, "read_issue": {"integrity": "untrusted"}}`.
      Declarations only *raise* the session label; content detections can raise it further.
    * `sinks`: tool-name glob -> what that tool accepts: `accepts_untrusted = false` (untrusted
      content must not drive it) and/or `max_confidentiality` (the most sensitive data it may receive).
    * `default_integrity`: `"trusted"` (default: local, read-only tools are trusted) or
      `"untrusted"` (every tool result is untrusted unless listed in `trusted_tools`).
    """

    enabled: bool = True
    actions: dict[str, Action] = field(default_factory=lambda: dict(DEFAULT_SESSION_ACTIONS))
    untrusted_tools: list[str] = field(default_factory=list)
    trusted_tools: list[str] = field(default_factory=list)
    hostile_min_verdict: Verdict = Verdict.FLAG
    allow_egress: dict[str, list[str]] = field(default_factory=dict)
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)
    sinks: dict[str, dict[str, Any]] = field(default_factory=dict)
    default_integrity: str = "trusted"
    destinations: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        merged = dict(DEFAULT_SESSION_ACTIONS)
        merged.update({k: Action(v) for k, v in self.actions.items()})
        unknown = set(merged) - set(DEFAULT_SESSION_ACTIONS)
        if unknown:
            raise ValueError(f"unknown session rule(s) {sorted(unknown)}; use {sorted(DEFAULT_SESSION_ACTIONS)}")
        self.actions = merged
        self.hostile_min_verdict = Verdict(self.hostile_min_verdict)
        for pattern, kinds in self.allow_egress.items():
            if isinstance(kinds, str) or not all(isinstance(k, str) for k in kinds):
                raise ValueError(f"allow_egress[{pattern!r}] must be a list of data types, e.g. [\"iban\"]")
        self.allow_egress = {p: list(k) for p, k in self.allow_egress.items()}
        if self.default_integrity not in ("trusted", "untrusted"):
            raise ValueError('default_integrity must be "trusted" or "untrusted"')
        for pattern, spec in self.sources.items():
            unknown = set(spec) - _SOURCE_KEYS
            if unknown:
                raise ValueError(f"sources[{pattern!r}]: unknown key(s) {sorted(unknown)}; use {sorted(_SOURCE_KEYS)}")
            if Integrity(spec.get("integrity", "trusted")) is Integrity.HOSTILE:
                raise ValueError(f"sources[{pattern!r}]: 'hostile' is set by detection, not declared")
            Confidentiality(spec.get("confidentiality", "public"))
        for dest in self.destinations:
            missing = {"tool", "argument", "match", "max_confidentiality"} - set(dest)
            extra = set(dest) - {"tool", "argument", "match", "max_confidentiality"}
            if missing or extra:
                raise ValueError(f"destination {dest!r}: needs tool, argument, match, max_confidentiality (and nothing else)")
            Confidentiality(dest["max_confidentiality"])
        for pattern, spec in self.sinks.items():
            unknown = set(spec) - _SINK_KEYS
            if unknown:
                raise ValueError(f"sinks[{pattern!r}]: unknown key(s) {sorted(unknown)}; use {sorted(_SINK_KEYS)}")
            if "max_confidentiality" in spec:
                Confidentiality(spec["max_confidentiality"])

    def _matches(self, tool: str | None, patterns: list[str]) -> bool:
        return tool is not None and any(fnmatch.fnmatchcase(tool, p) for p in patterns)

    def is_trusted(self, tool: str | None) -> bool:
        return self._matches(tool, self.trusted_tools)

    def allowed_kinds(self, tool: str | None) -> frozenset[str]:
        """Data types `tool` may send out (union over every matching `allow_egress` pattern)."""
        if tool is None:
            return frozenset()
        return frozenset(k for p, kinds in self.allow_egress.items() if fnmatch.fnmatchcase(tool, p) for k in kinds)

    def source_label(self, tool: str | None) -> Label | None:
        """The declared label of what `tool` returns (most restrictive over matching patterns), or None."""
        if tool is None:
            return None
        found = [Label(s.get("integrity", "trusted"), s.get("confidentiality", "public"))
                 for p, s in self.sources.items() if fnmatch.fnmatchcase(tool, p)]  # fmt: skip
        return combine_labels(*found) if found else None

    def sink(self, tool: str | None) -> tuple[bool, Confidentiality | None]:
        """(accepts_untrusted, max_confidentiality) for `tool`; the strictest over matching patterns."""
        accepts, cap = True, None
        if tool is not None:
            for p, spec in self.sinks.items():
                if fnmatch.fnmatchcase(tool, p):
                    accepts = accepts and bool(spec.get("accepts_untrusted", True))
                    if "max_confidentiality" in spec:
                        level = Confidentiality(spec["max_confidentiality"])
                        cap = level if cap is None else min(cap, level)
        return accepts, cap

    def call_cap(self, tool: str | None, arguments: Mapping[str, Any] | str | None) -> Confidentiality | None:
        """The most sensitive data this particular call may carry.

        Destinations can allow more for matching values (internal recipients may receive private data); every other
        value gets the tool's sink cap. The call's cap is the lowest across its values.
        """
        from guardlayer.tools import argument_values, value_matches

        _, cap = self.sink(tool)
        if tool is None:
            return cap
        dests = [d for d in self.destinations if fnmatch.fnmatchcase(tool, d["tool"])]
        caps: list[Confidentiality | None] = []
        for argument in {d["argument"] for d in dests}:
            for value in argument_values(arguments, argument):
                allowed = [Confidentiality(d["max_confidentiality"]) for d in dests
                           if d["argument"] == argument and value_matches(value, [d["match"]])]  # fmt: skip
                caps.append(max(allowed) if allowed else (cap if cap is not None else Confidentiality.PUBLIC))
        if not caps:
            return cap
        known = [c for c in caps if c is not None]
        return min(known) if known else None

    def is_untrusted(self, tool: str | None, can_reach_network: bool) -> bool:
        if tool is None:
            return True
        if self.is_trusted(tool):
            return False
        declared = [Integrity(s["integrity"]) for p, s in self.sources.items() if "integrity" in s and fnmatch.fnmatchcase(tool, p)]
        if declared:  # an explicit declaration decides, whatever the tool's capabilities
            return max(declared) >= Integrity.UNTRUSTED
        return can_reach_network or self._matches(tool, self.untrusted_tools) or self.default_integrity == "untrusted"


# ------------------------------------------------------------------------------------- tracking
def record_sensitive_values(state: SessionState, text: str, result: ScanResult) -> bool:
    """Fingerprint secret/PII spans in `text`. Returns True when anything sensitive was found."""
    found = False
    for d in result.detections:
        if d.category not in SENSITIVE_CATEGORIES or d.rule in _NOT_SENSITIVE_PII:
            continue
        found = True
        state.sensitive_kinds = _add(state.sensitive_kinds, [d.rule], MAX_SOURCES)
        if d.span:
            token = _value_token(text[d.span[0] : d.span[1]])
            if token:
                state.fingerprints = _add(state.fingerprints, [fingerprint(token, d.rule)], MAX_FINGERPRINTS)
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
    declared = policy.source_label(tool)
    if declared is not None:
        if declared.confidentiality is Confidentiality.RESTRICTED:
            state.sensitive_sources = _add(state.sensitive_sources, [source], MAX_SOURCES)
            state.sensitive_kinds = _add(state.sensitive_kinds, [f"declared:{tool}"], MAX_SOURCES)
        elif declared.confidentiality is Confidentiality.PRIVATE:
            state.private_sources = _add(state.private_sources, [source], MAX_SOURCES)
    _touch(state)


def observe_label(state: SessionState, label: Label, source: str) -> None:
    """Raise the session's label to `label` (e.g. from a labelled file the call mentions)."""
    if label.integrity is Integrity.HOSTILE:
        state.hostile_sources = _add(state.hostile_sources, [source], MAX_SOURCES)
    if label.integrity >= Integrity.UNTRUSTED:
        state.untrusted_sources = _add(state.untrusted_sources, [source], MAX_SOURCES)
    if label.confidentiality is Confidentiality.RESTRICTED:
        state.sensitive_sources = _add(state.sensitive_sources, [source], MAX_SOURCES)
    elif label.confidentiality is Confidentiality.PRIVATE:
        state.private_sources = _add(state.private_sources, [source], MAX_SOURCES)


def file_label_detections(
    policy: SessionPolicy, tool: str, caps: frozenset[str], tagged: bool, refs: list[tuple[str, Label]]
) -> list[Detection]:
    """`untrusted_file_executed` when an exec-capable call mentions a file written in an untrusted context."""
    if not policy.enabled or policy.is_trusted(tool) or (tagged and "exec" not in caps):
        return []
    risky = [(path, label) for path, label in refs if label.integrity >= Integrity.UNTRUSTED]
    if not risky:
        return []
    path, label = max(risky, key=lambda r: r[1].integrity)
    return [Detection(SCANNER, "untrusted_file_executed", Category.TOOL_MISUSE.value, 0.8,
                      f"This command uses {Path(path).name}, which was written while the session held {label.integrity.value} content.",
                      metadata={"tool": tool, "files": [p for p, _ in risky][:5], "label": label.to_dict()},
                      action=policy.actions["untrusted_file_executed"].value)]  # fmt: skip


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
    rules = [d.rule for d in result.detections if d.rule in SENSITIVE_TOOL_RULES]
    if rules:
        state.sensitive_kinds = _add(state.sensitive_kinds, rules, MAX_SOURCES)
        state.sensitive_sources = _add(state.sensitive_sources, [f"tool:{tool}"], MAX_SOURCES)
    _touch(state)


def _touch(state: SessionState) -> None:
    state.updated = time.time()
    state.events += 1


def taint_detections(
    policy: SessionPolicy,
    state: SessionState,
    tool: str,
    caps: frozenset[str],
    tagged: bool,
    arguments_text: str,
    *,
    remote: bool | None = None,
    arguments: Mapping[str, Any] | str | None = None,
) -> list[Detection]:
    """Detections for a proposed tool call, given what the session has already seen.

    `remote` (from `ToolPolicy.is_remote`) widens `sensitive_data_egress` to tools whose
    arguments leave the machine even though they look read-only, such as a search query.
    """
    if not policy.enabled:
        return []
    egress = not tagged or bool(caps & {"network", "exec"})
    leaves = egress or bool(remote)
    acts = not tagged or bool(caps & {"network", "exec", "write"})
    out: list[Detection] = []

    def emit(rule: str, category: str, severity: float, message: str, **metadata: Any) -> None:
        out.append(Detection(SCANNER, rule, category, severity, message, metadata={"tool": tool, **metadata}, action=policy.actions[rule].value))

    allowed = policy.allowed_kinds(tool)
    if leaves and state.fingerprints:
        if contains_fingerprint(arguments_text, state.fingerprints, allowed_kinds=allowed):
            emit("sensitive_data_egress", Category.DATA_EXFILTRATION.value, 1.0,
                 "A sensitive value seen earlier in this session is being sent out of the machine by this tool call.",
                 sources=state.sensitive_sources[-5:])  # fmt: skip
    # Only allowed data types seen (and every source typed): nothing this tool may not send.
    only_allowed = bool(allowed) and bool(state.sensitive_kinds) and set(state.sensitive_kinds) <= allowed
    if egress and state.untrusted and state.sensitive and not only_allowed:
        emit("trifecta", Category.DATA_EXFILTRATION.value, 0.7,
             "This session has read untrusted content and sensitive data; network/exec actions need approval.",
             untrusted=state.untrusted_sources[-5:], sensitive=state.sensitive_sources[-5:])  # fmt: skip
    if acts and state.hostile:
        emit("after_injection", Category.PROMPT_INJECTION.value, 0.7,
             "This session read content containing a prompt injection; side-effecting actions need approval.",
             hostile=state.hostile_sources[-5:])  # fmt: skip
    accepts_untrusted, _ = policy.sink(tool)
    cap = policy.call_cap(tool, arguments)
    context = state.label
    if not accepts_untrusted and context.integrity >= Integrity.UNTRUSTED:
        emit("untrusted_to_protected_sink", Category.PROMPT_INJECTION.value, 0.8,
             f"This tool doesn't accept untrusted input, and the session has read {context.integrity.value} content.",
             label=context.to_dict(), untrusted=state.untrusted_sources[-5:], hostile=state.hostile_sources[-5:])  # fmt: skip
    if cap is not None and context.confidentiality > cap:
        emit("confidentiality_exceeds_sink", Category.DATA_EXFILTRATION.value, 0.8,
             f"The session holds {context.confidentiality.value} data; this tool accepts at most {cap.value}.",
             label=context.to_dict(), max_confidentiality=cap.value,
             sources=(state.sensitive_sources + state.private_sources)[-5:])  # fmt: skip
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
