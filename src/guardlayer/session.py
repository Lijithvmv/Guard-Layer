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

import base64
import fnmatch
import hashlib
import html
import json
import logging
import os
import re
import tempfile
import threading
import time
import uuid
import zlib
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import unquote

from guardlayer.consequence import (
    DESTINATION_ARGS,
    consequence,
    destination_places,
    destination_values,
    distinctive_values,
    file_consequence,
    phrases,
    places,
)
from guardlayer.labels import Confidentiality, Integrity, Label
from guardlayer.labels import combine as combine_labels
from guardlayer.models import Action, Category, Detection, ScanResult, Verdict
from guardlayer.normalize import decode_payloads, despace, normalize

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
MAX_PHRASES = 20_000
MAX_SCAN_CHARS = 65_536  # bound on argument text searched for fingerprints
SEAM_CHARS = 500  # how much of the previous untrusted content is kept to scan across the boundary with the next one
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


_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")
_ENCODED = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")


def squash(value: str) -> str:
    """Letters and digits only: `s k-p r o j` and `sk_proj` both become `skproj`."""
    return _NON_ALNUM.sub("", value)


def _printable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text and sum(c.isprintable() for c in text) >= 0.9 * len(text) else None


def _decoded_views(text: str) -> list[str]:
    """base64, hex and URL-decoded copies of `text`'s encoded-looking tokens (bounded, linear)."""
    import base64
    import binascii
    from urllib.parse import unquote

    out: list[str] = []
    budget = MAX_SCAN_CHARS
    if "%" in text:
        out.append(unquote(text))
    for token in _ENCODED.findall(text):
        if budget <= 0:
            break
        for decode in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = _printable(decode(token + "=" * (-len(token) % 4)))
            except (binascii.Error, ValueError):
                decoded = None
            if decoded:
                out.append(decoded)
                budget -= len(decoded)
                break
    for token in _HEX.findall(text):
        if budget <= 0:
            break
        decoded = _printable(bytes.fromhex(token))
        if decoded:
            out.append(decoded)
            budget -= len(decoded)
    return out


def contains_fingerprint(text: str, fingerprints: Iterable[str], *, allowed_kinds: Iterable[str] = ()) -> bool:
    """True if any fingerprinted value occurs in `text`, whole or embedded in a longer token.

    Also checked: the text with separators removed (`s k - p r o j ...`), and base64, hex and URL-decoded copies of
    its encoded-looking tokens, so a lightly disguised copy of a secret still matches. Every view is scanned in linear
    time.

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
    decoded = _decoded_views(text)
    views = [text, squash(text), *decoded, *(squash(v) for v in decoded)]
    for view in views:
        if legacy and any(_digest(tok.strip(".=/")) in legacy for tok in _TOKEN_RE.findall(view)):
            return True
        if not by_prefix:
            continue
        for run in _TOKEN_RE.findall(view):
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
    hostile_values: list[str] = field(default_factory=list)  # hashes of distinctive values seen in hostile content
    untrusted_values: list[str] = field(default_factory=list)  # hashes of distinctive values seen in untrusted content
    user_values: list[str] = field(default_factory=list)  # hashes of distinctive values in the user's messages and trusted content
    untrusted_phrases: list[str] = field(default_factory=list)  # hashes of 1-4 word runs of untrusted content
    hostile_phrases: list[str] = field(default_factory=list)  # hashes of 1-4 word runs of hostile content (where a destination may come from)
    user_phrases: list[str] = field(default_factory=list)  # hashes of 1-4 word runs of the user's own messages
    untrusted_places: list[str] = field(default_factory=list)  # hashes of places (host/path, address) untrusted content named
    user_places: list[str] = field(default_factory=list)  # hashes of places the user or trusted content named
    private_marks: list[str] = field(default_factory=list)  # hashes of identifiers and 6-word runs from declared-private sources
    unmarked_private: bool = False  # private data entered without text to mark (a labelled file): judge session-wide
    public_words: list[str] = field(default_factory=list)  # hashes of words in untrusted content and user prompts: not private, so sending them leaks nothing
    sensitive_kinds: list[str] = field(default_factory=list)  # rules that found them (iban, credential_file, ...)
    task: str | None = None  # the task profile in force (see guardlayer.tasks)
    task_args: dict[str, Any] = field(default_factory=dict)  # values from the trusted request, for {task.NAME}
    task_tools: list[str] | None = None  # tools still allowed; None = no task set
    task_version: int = 0  # bumped on every task change; the newest wins when copies of a session merge
    task_log: list[str] = field(default_factory=list)
    seam: str = ""  # the (redacted) last SEAM_CHARS of the latest untrusted content, to catch instructions split across two
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
        # A shallow copy: fields are str, number, bool, None, lists of str, or task_args (asdict copies element by element)
        data = {name: (type(v)(v) if isinstance(v := getattr(self, name), (list, dict)) else v) for name in self.__dataclass_fields__}
        for name in _PACKED:  # one base64 string instead of tens of thousands of JSON strings per save
            data[name] = {"packed": base64.b64encode(bytes.fromhex("".join(data[name]))).decode("ascii")}
        return data

    def copy(self) -> SessionState:
        """An independent copy (lists and dicts copied; their items are immutable)."""
        return SessionState(**{name: (type(v)(v) if isinstance(v := getattr(self, name), (list, dict)) else v)
                               for name in self.__dataclass_fields__})  # fmt: skip

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SessionState:
        known = set(cls.__dataclass_fields__)
        data = dict(data)
        for name in _PACKED:
            value = data.get(name)
            if isinstance(value, Mapping):
                raw = base64.b64decode(value.get("packed", ""))
                hexed, w = raw.hex(), 2 * _H_BYTES
                data[name] = [hexed[i : i + w] for i in range(0, len(hexed), w)]
            elif isinstance(value, list):  # an older format: those hashes no longer match; start these lists afresh
                data[name] = [v for v in value if isinstance(v, str) and len(v) == 2 * _H_BYTES]
        return cls(**{k: v for k, v in data.items() if k in known})

    def merge(self, other: SessionState) -> None:
        """Union another copy of this session into this one (state only grows, so merging is safe)."""
        for name, cap in (("untrusted_sources", MAX_SOURCES), ("hostile_sources", MAX_SOURCES), ("sensitive_sources", MAX_SOURCES), ("private_sources", MAX_SOURCES),
                          ("fingerprints", MAX_FINGERPRINTS), ("sensitive_kinds", MAX_SOURCES),
                          ("hostile_values", MAX_FINGERPRINTS), ("user_values", MAX_FINGERPRINTS),
                          ("untrusted_values", MAX_FINGERPRINTS), ("hostile_phrases", MAX_PHRASES), ("user_phrases", MAX_PHRASES),
                          ("untrusted_phrases", MAX_PHRASES), ("untrusted_places", MAX_PHRASES), ("user_places", MAX_PHRASES), ("private_marks", MAX_PHRASES),
                          ("public_words", MAX_PHRASES)):
            setattr(self, name, _add(getattr(other, name), getattr(self, name), cap))
        self.created = min(self.created, other.created)
        self.updated = max(self.updated, other.updated)
        self.events = max(self.events, other.events)
        if other.task_version > self.task_version:
            self.task, self.task_args, self.task_tools = other.task, dict(other.task_args), other.task_tools
            self.task_version, self.task_log = other.task_version, list(other.task_log)


logger = logging.getLogger("guardlayer")

_H_BYTES = 8
# Lists only ever tested for membership: kept as short hashes and saved packed.
_PACKED = ("untrusted_phrases", "hostile_phrases", "user_phrases", "untrusted_places", "user_places", "private_marks",
           "public_words")


_KEY: bytes | None = None


def _hash_key() -> bytes:
    """The installation's key for membership hashes, shared by every GuardLayer process (hook server, CLI, replays).

    Short phrases are guessable, so an unkeyed hash of "send to fred" is as good as the text. The key lives in
    `~/.guardlayer/hash.key` (or `GUARDLAYER_HASH_KEY_FILE`), readable only by the user: someone who can read both
    the session files and the key can still test guesses. If the key can't be stored, hashes are unkeyed (with a
    warning) rather than random per process, which would stop separate hook processes recognising each other's state.
    """
    global _KEY
    if _KEY is not None:
        return _KEY
    path = Path(os.environ.get("GUARDLAYER_HASH_KEY_FILE", "~/.guardlayer/hash.key")).expanduser()
    try:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(os.urandom(32))
            except FileExistsError:
                pass  # another process created it first
        key = path.read_bytes()
        if len(key) < 16:
            raise ValueError("hash key file too short")
        _KEY = key[:32]
    except (OSError, ValueError) as exc:
        logger.warning("GuardLayer: no hash key (%s); membership hashes are unkeyed", exc)
        _KEY = b""
    return _KEY


def _h(value: str, kind: str) -> str:
    """A keyed 64-bit hash for membership lists (phrases, places, words, private marks). A chance collision among
    20,000 entries is ~1e-11. Values are never stored in clear."""
    data = f"{kind}\0{value}".encode("utf-8", "replace")
    return hashlib.blake2b(data, digest_size=_H_BYTES, key=_hash_key()).hexdigest()


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
        # The state this process last read or wrote, by file version (mtime, size). A state loaded from the file's
        # current version needs no merge when saved; an unchanged file needs no re-read. ~40 ms a call on a full
        # session. Anything else (another process wrote, or the state wasn't loaded from this version) merges as before.
        self._known: dict[Path, tuple[tuple[int, int], SessionState]] = {}

    @staticmethod
    def _version(path: Path) -> tuple[int, int] | None:
        try:
            st = path.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def _remember(self, path: Path, state: SessionState) -> None:
        version = self._version(path)
        if version is None:
            self._known.pop(path, None)
        else:
            self._known[path] = (version, state.copy())

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
        path = self._path(session_id)
        known = self._known.get(path)
        version = self._version(path)
        if known is not None and known[0] == version:
            state: SessionState | None = known[1].copy()
        else:
            state = self._read(path)
            if state is not None:
                self._remember(path, state)
        if state is None or state.id != session_id:
            return None
        state._loaded_from = version  # lineage: saving it back over this same version needs no merge
        if self.ttl is not None and time.time() - state.updated > self.ttl:
            return None
        return state

    def put(self, state: SessionState) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self._path(state.id)
        lock = self._lock(path)
        try:
            version = self._version(path)
            if version is not None and getattr(state, "_loaded_from", None) != version:
                known = self._known.get(path)
                current = known[1].copy() if known is not None and known[0] == version else self._read(path)
                if current is not None and current.id == state.id:
                    state.merge(current)
            fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".tmp-", suffix=".json")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(json.dumps(state.to_dict()))  # json.dump streams through the slow pure-Python path
                self._replace(tmp, path)
                self._remember(path, state)
                state._loaded_from = self._version(path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
        finally:
            if lock is not None:
                lock.unlink(missing_ok=True)

    def delete(self, session_id: str) -> None:
        path = self._path(session_id)
        self._known.pop(path, None)
        path.unlink(missing_ok=True)


# ------------------------------------------------------------------------------------- policy
DEFAULT_SESSION_ACTIONS: dict[str, Action] = {
    "sensitive_data_egress": Action.BLOCK,
    "trifecta": Action.REVIEW,
    "after_injection": Action.REVIEW,
    # A destination argument copied from untrusted content (not from the user), without needing detection.
    "untrusted_destination": Action.REVIEW,
    # Label rules (0.7): only fire for tools declared as sinks in `sinks`.
    "untrusted_to_protected_sink": Action.REVIEW,
    "confidentiality_exceeds_sink": Action.REVIEW,
    # File labels (0.7): running a file that untrusted content could have written.
    "untrusted_file_executed": Action.REVIEW,
    # Task profiles (0.8): actions outside the task the session was given.
    "out_of_task": Action.REVIEW,
    "task_argument_not_allowed": Action.REVIEW,
    # Behavioural check (0.8): the model proposes the same action with the user's request hidden.
    "injection_driven_action": Action.REVIEW,
    "intent_check_failed": Action.LOG,
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
    * `trifecta_on_pii`: personal data found in tool output counts as sensitive for `trifecta` (as secrets always
      do). Off by default: it makes the session private instead; exact copies leaving are still caught.
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
    tasks: dict[str, Any] = field(default_factory=dict)
    trifecta_on_pii: bool = False
    # After an injection: "consequence" holds irreversible actions and outbound ones carrying values from the hostile
    # content (see guardlayer.consequence); "all" holds every action that can write, execute or reach the network.
    after_injection_scope: str = "consequence"
    # The lethal trifecta (untrusted + sensitive + a way out): "destination" holds an outbound or irreversible action
    # whose arguments carry a value from untrusted content the user didn't name (where an attacker says to send the
    # data); "all" holds every network/exec action once the session is untrusted and sensitive.
    trifecta_scope: str = "destination"
    # Declared consequence per tool (glob -> "local" | "outbound" | "irreversible"), from [tool.NAME] consequence = ...
    consequences: dict[str, str] = field(default_factory=dict)
    # Extra destination argument names per tool (beyond the built-in to/recipient/url/channel/user/...)
    destination_args: dict[str, list[str]] = field(default_factory=dict)
    # Detection-independent: hold an action whose destination argument was copied from untrusted content and never
    # named by the user. "irreversible" (payments, access changes, publishing), "outbound" (also messages and posts)
    # or "off". An injection that evades every detector still has to name its destination somewhere the agent read.
    untrusted_destination: str = "outbound"

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
        for pattern, kind in self.consequences.items():
            if kind not in ("local", "outbound", "irreversible"):
                raise ValueError(f'consequences[{pattern!r}] must be "local", "outbound" or "irreversible", not {kind!r}')
        if self.untrusted_destination not in ("off", "irreversible", "outbound"):
            raise ValueError('untrusted_destination must be "off", "irreversible" or "outbound"')
        if self.trifecta_scope not in ("destination", "all"):
            raise ValueError('trifecta_scope must be "destination" or "all"')
        if self.after_injection_scope not in ("consequence", "all"):
            raise ValueError('after_injection_scope must be "consequence" or "all"')
        if self.default_integrity not in ("trusted", "untrusted"):
            raise ValueError('default_integrity must be "trusted" or "untrusted"')
        for pattern, spec in self.sources.items():
            unknown = set(spec) - _SOURCE_KEYS
            if unknown:
                raise ValueError(f"sources[{pattern!r}]: unknown key(s) {sorted(unknown)}; use {sorted(_SOURCE_KEYS)}")
            if Integrity(spec.get("integrity", "trusted")) is Integrity.HOSTILE:
                raise ValueError(f"sources[{pattern!r}]: 'hostile' is set by detection, not declared")
            Confidentiality(spec.get("confidentiality", "public"))
        from guardlayer.tasks import TaskProfile

        self.tasks = {name: t if isinstance(t, TaskProfile) else TaskProfile.from_dict(name, t) for name, t in self.tasks.items()}
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

    def declared_consequence(self, tool: str | None) -> str | None:
        """The consequence declared for `tool` (the most severe matching glob), or None."""
        if tool is None:
            return None
        order = {"local": 0, "outbound": 1, "irreversible": 2}
        found = [k for p, k in self.consequences.items() if fnmatch.fnmatchcase(tool, p)]
        return max(found, key=order.__getitem__) if found else None

    def is_trusted(self, tool: str | None) -> bool:
        return self._matches(tool, self.trusted_tools)

    def declared_trusted(self, tool: str | None) -> bool:
        """Listed in `trusted_tools`, or declared `integrity = "trusted"` in `sources` (and nowhere untrusted)."""
        if tool is None:
            return False
        if self.is_trusted(tool):
            return True
        declared = [Integrity(s["integrity"]) for p, s in self.sources.items() if "integrity" in s and fnmatch.fnmatchcase(tool, p)]
        return bool(declared) and max(declared) is Integrity.TRUSTED

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
def record_sensitive_values(state: SessionState, text: str, result: ScanResult) -> set[str]:
    """Fingerprint secret/PII spans in `text`. Returns the categories found (`secret`, `pii`)."""
    found: set[str] = set()
    for d in result.detections:
        if d.category not in SENSITIVE_CATEGORIES or d.rule in _NOT_SENSITIVE_PII:
            continue
        found.add(d.category)
        state.sensitive_kinds = _add(state.sensitive_kinds, [d.rule], MAX_SOURCES)
        if d.span:
            token = _value_token(text[d.span[0] : d.span[1]])
            if token:
                prints = [fingerprint(token, d.rule)]
                squashed = squash(token)
                if squashed != token.strip(".=/") and len(squashed) >= _PREFIX:
                    prints.append(fingerprint(squashed, d.rule))  # matches the copy with separators stripped
                state.fingerprints = _add(state.fingerprints, prints, MAX_FINGERPRINTS)
    return found


_WRAPPED_B64 = re.compile(r"(?<=[A-Za-z0-9+/]{16})[ \t]*\r?\n[ \t]*(?=[A-Za-z0-9+/]{4})")


def _canonical(text: str) -> str:
    """The form an agent reads past: HTML entities, invisible characters, look-alike letters, s-p-a-c-e-d letters."""
    return despace(normalize(html.unescape(text), collapse_whitespace=False))


def _readable(text: str) -> str:
    """`text` plus what an agent could decode from it.

    An address hidden in base64 is still an address the agent read: the attacker can tell it to decode and use it.
    Mail and MIME wrap base64 across lines, so wrapped runs are joined before decoding. A decoded token counts when it
    is readable text or holds an identifier (a bare URL has no spaces). Transformations an agent can undo but no
    canonical form captures (an address spelled out, reversed, or split across words) are out of reach of matching;
    see docs/concepts/consequence.md.
    """
    text = text[:200_000]
    canon = _canonical(text)
    joined = _WRAPPED_B64.sub("", canon)  # may also glue a short last line to the next one: decode both forms
    views = [d for _, d in decode_payloads(joined)]
    for form in {canon, joined}:
        for token in _ENCODED.findall(form)[:16] + _HEX.findall(form)[:16]:
            decoded = _decode_token(token)
            if decoded and decoded not in views and distinctive_values(decoded):
                views.append(decoded)
    views = [v for v in (canon if canon != text else "", *views) if v]
    return "\n".join([text, *views]) if views else text


_WORD = re.compile(r"[a-z0-9]{3,40}")


def _words(text: str) -> set[str]:
    return set(_WORD.findall(unquote(text).lower()))


def _adds_nothing(arguments: Any, extra: Iterable[str], state: SessionState) -> bool:
    """True when an outbound action carries nothing an outsider didn't already have.

    Data leaves only in what an action carries: a body, message or other argument, or words in the URL. Opening a
    page at an address built only from words in content the outsider wrote (following a link, or a file listed in a
    repository) tells them nothing; appending the user's contacts or a file's contents to their URL does. (Opening an
    outsider's page brings more untrusted content in; that is judged when it is read.)
    """
    if not isinstance(arguments, Mapping) or not arguments:
        return False
    keys = DESTINATION_ARGS | set(extra)
    if any(str(k).lower() not in keys and v not in (None, "", [], {}) for k, v in arguments.items()):
        return False
    known = set(state.public_words)
    for value in destination_values(arguments, extra):
        if not (_URL_START.match(value) or ("@" not in value and " " not in value and places(value))):
            return False  # an address or account: sending to it at all is the act
        rest = re.sub(r"^\w+://", "", value)
        if any(_h(w, "word") not in known for w in _words(rest)):
            return False
    return True


_THIS_MACHINE = re.compile(
    r"^(?:file:|(?:\w+://)?(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|[\w.-]+\.localhost)(?::\d+)?(?:[/?#]|$))",
    re.IGNORECASE,
)


def _outside_place(value: str) -> bool:
    """Whether a destination value can be somewhere off this machine.

    Data sent to localhost or a local file never leaves the machine, so it can't be exfiltration (acting on a local
    service is an action risk, judged by consequence, not this check). Browser commands passed where a URL goes
    ("back", "reload") aren't addresses. A plain name is kept: it can be a recipient.
    """
    if _THIS_MACHINE.match(value):
        return False
    return not re.fullmatch(r"back|forward|reload|refresh|home|about:blank", value)


_URL_START = re.compile(r"^(?:https?|wss?|ftps?)://", re.IGNORECASE)


def _decode_token(token: str) -> str | None:
    import base64
    import binascii

    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", token):
        try:
            return _printable(bytes.fromhex(token))
        except ValueError:
            return None
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            out = _printable(decode(token + "=" * (-len(token) % 4)))
        except (binascii.Error, ValueError):
            out = None
        if out:
            return out
    return None


def observe_content(
    policy: SessionPolicy, state: SessionState, text: str, result: ScanResult, *, source: str, tool: str | None,
    can_reach_network: bool, untrusted: bool = False,
) -> None:
    """Update taint after the agent read `text` (a tool result or other third-party content)."""
    trusted = policy.is_trusted(tool)
    text = _readable(text)
    values = [fingerprint(v, "hostile") for v in distinctive_values(text)]
    injected = result.effective_verdict >= policy.hostile_min_verdict and bool(HOSTILE_CATEGORIES & set(result.categories))
    hostile = injected and not trusted
    if untrusted or policy.is_untrusted(tool, can_reach_network):
        state.untrusted_sources = _add(state.untrusted_sources, [source], MAX_SOURCES)
        state.untrusted_values = _add(state.untrusted_values, values, MAX_FINGERPRINTS)
        if policy.untrusted_destination != "off":
            state.untrusted_phrases = _add(state.untrusted_phrases, (_h(p, "phrase") for p in phrases(text)), MAX_PHRASES)
            state.untrusted_places = _add(state.untrusted_places, (_h(p, "place") for p in places(text)), MAX_PHRASES)
            state.public_words = _add(state.public_words, (_h(w, "word") for w in _words(text)), MAX_PHRASES)
    elif not injected:
        # Identifiers in trusted content (the user's own files and tools) are known context: an action using them
        # is never blamed on untrusted or hostile content that repeats them. Content holding an injection never
        # counts as known context, whatever its source (a poisoned README is a local file). A file the agent wrote
        # after reading untrusted content is read back as untrusted (see Guard.scan_tool_result `arguments`), so an
        # outsider's address can't be laundered through it.
        state.user_values = _add(state.user_values, values, MAX_FINGERPRINTS)
        state.user_places = _add(state.user_places, (_h(p, "place") for p in places(text)), MAX_PHRASES)
    if hostile:
        state.hostile_sources = _add(state.hostile_sources, [source], MAX_SOURCES)
        state.hostile_values = _add(state.hostile_values, values, MAX_FINGERPRINTS)
        state.hostile_phrases = _add(state.hostile_phrases, (_h(p, "phrase") for p in phrases(text)), MAX_PHRASES)
    found = record_sensitive_values(state, text, result)
    # Secrets make a session sensitive (restricted). Personal data makes it private: its exact values are still
    # fingerprinted (sensitive_data_egress), but it doesn't turn every later network call into a review unless
    # `trifecta_on_pii` is set (strict and airgap). Replaying ADR-Bench showed sample emails in ordinary tool output
    # interrupting one normal session in ten.
    if Category.SECRET.value in found or (found and policy.trifecta_on_pii):
        state.sensitive_sources = _add(state.sensitive_sources, [source], MAX_SOURCES)
    elif found:
        state.private_sources = _add(state.private_sources, [source], MAX_SOURCES)
    declared = policy.source_label(tool)
    if declared is not None:
        if declared.confidentiality is Confidentiality.RESTRICTED:
            state.sensitive_sources = _add(state.sensitive_sources, [source], MAX_SOURCES)
            state.sensitive_kinds = _add(state.sensitive_kinds, [f"declared:{tool}"], MAX_SOURCES)
        elif declared.confidentiality is Confidentiality.PRIVATE:
            state.private_sources = _add(state.private_sources, [source], MAX_SOURCES)
        if declared.confidentiality >= Confidentiality.PRIVATE:
            state.private_marks = _add(state.private_marks, (_h(m, "private") for m in _marks(text)), MAX_PHRASES)
    _touch(state)


def task_detections(policy: SessionPolicy, state: SessionState, tool: str, arguments: Mapping[str, Any] | str | None) -> list[Detection]:
    """`out_of_task` / `task_argument_not_allowed` when the session has a task profile."""
    if not policy.enabled or state.task_tools is None:
        return []
    out: list[Detection] = []
    if not any(fnmatch.fnmatchcase(tool, pattern) for pattern in state.task_tools):
        out.append(Detection(SCANNER, "out_of_task", Category.TOOL_MISUSE.value, 0.8,
                             f"{tool!r} is not one of the tools for the task {state.task!r}.",
                             metadata={"tool": tool, "task": state.task, "task_tools": state.task_tools[:20]},
                             action=policy.actions["out_of_task"].value))  # fmt: skip
        return out
    profile = policy.tasks.get(state.task or "")
    if profile is not None:
        for rule in profile.argument_rules(state.task_args):
            for _name, value in rule.violations(tool, arguments):
                out.append(Detection(SCANNER, "task_argument_not_allowed", Category.TOOL_MISUSE.value, 0.8,
                                     f"{tool}.{rule.argument} = {value[:120]!r} is not allowed in the task {state.task!r}.",
                                     metadata={"tool": tool, "task": state.task, "argument": rule.argument, "value": value[:200]},
                                     action=policy.actions["task_argument_not_allowed"].value))  # fmt: skip
    return out


_SHINGLE = 6
_NAME = re.compile(r"\b[A-Z][a-zA-Z-]{2,}\b")
_GROUPED = re.compile(r"\d[\d,._ ]{2,}\d")
_ID = re.compile(r"\b(?:(?=[a-z_-]*\d)(?=[\d_-]*[a-z])[a-z0-9_-]{4,}|\d{4,}|[\w.+-]+@[\w-]+(?:\.[\w-]+)+)\b")


def _marks(text: str) -> set[str]:
    """What identifies content from a private source: identifiers (IDs, numbers, addresses), names (capitalised
    words), and every run of 6 words (a verbatim copy). Plain lower-case words don't count: a status note may share them."""
    low = text.lower()[:200_000]
    words = re.findall(r"\w+", low)
    runs = {" ".join(words[i : i + _SHINGLE]) for i in range(max(0, len(words) - _SHINGLE + 1))}
    names = {w.lower() for w in _NAME.findall(text[:200_000])}
    numbers = {re.sub(r"[,._ ]", "", n) for n in _GROUPED.findall(low)}
    ids = set(_ID.findall(low)) | {n for n in numbers if len(n) >= 4}
    return set(distinctive_values(text)) | ids | names | set(list(runs)[:MAX_PHRASES])


def _carries_private(state: SessionState, arguments: Any) -> bool:
    """Whether an action carries content from a declared-private source (rather than merely following one).

    Without this, reading one private file held every later post to a public place, including "Done.". Values the
    user typed are theirs to send. Paraphrase is not detected: a summary in new words passes (documented limit).
    Private data that entered without text to mark (a labelled file) keeps the session-wide judgement.
    """
    if state.unmarked_private or (not state.private_marks and (state.private_sources or state.sensitive_sources)):
        return True
    text = arguments if isinstance(arguments, str) else json.dumps(arguments, ensure_ascii=False, default=str)
    marks, public = set(state.private_marks), set(state.public_words)
    for m in _marks(text) | set(re.findall(r"[a-z0-9-]{3,}", text.lower())):
        if _h(m, "private") in marks and not all(_h(w, "word") in public for w in _words(m)):
            return True
    return False


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
    if label.confidentiality >= Confidentiality.PRIVATE:
        state.unmarked_private = True


def file_label_detections(
    policy: SessionPolicy, tool: str, caps: frozenset[str], tagged: bool, refs: list[tuple[str, Label]]
) -> list[Detection]:
    """`untrusted_file_executed` when an exec-capable call mentions a file written in an untrusted context."""
    if not policy.enabled or policy.is_trusted(tool) or (tagged and "exec" not in caps):
        return []
    # Files written after an injection was read (hostile) are held when run. Files written after an untrusted read
    # are held under the session freeze ("all"); with consequence routing they are opened and judged by what they
    # would execute (an undetected injection may have asked for a download-and-run script; a test script is fine).
    risky = []
    for path, label in refs:
        if label.integrity >= Integrity.HOSTILE:
            risky.append((path, label))
        elif label.integrity >= Integrity.UNTRUSTED and (policy.after_injection_scope == "all" or file_consequence(path) != "local"):
            risky.append((path, label))
    if not risky:
        return []
    path, label = max(risky, key=lambda r: r[1].integrity)
    return [Detection(SCANNER, "untrusted_file_executed", Category.TOOL_MISUSE.value, 0.8,
                      f"This command uses {Path(path).name}, which was written while the session held {label.integrity.value} content.",
                      metadata={"tool": tool, "files": [p for p, _ in risky][:5], "label": label.to_dict()},
                      action=policy.actions["untrusted_file_executed"].value)]  # fmt: skip


def observe_input(state: SessionState, text: str, result: ScanResult) -> None:
    """User prompts are trusted, but secrets pasted into them are still sensitive data. Identifiers the user names
    (URLs, addresses, accounts) are remembered so a later action using them is never blamed on hostile content."""
    state.user_values = _add(state.user_values, (fingerprint(v, "hostile") for v in distinctive_values(text)), MAX_FINGERPRINTS)
    state.user_phrases = _add(state.user_phrases, (_h(p, "phrase") for p in phrases(text)), MAX_PHRASES)
    state.user_places = _add(state.user_places, (_h(p, "place") for p in places(text)), MAX_PHRASES)
    # Words the user typed are theirs to send (a search term, a repository they named): not private data. Secrets
    # pasted here are still caught by fingerprint rules.
    state.public_words = _add(state.public_words, (_h(w, "word") for w in _words(text)), MAX_PHRASES)
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


def _carried(arguments_text: str, values: list[str], user_values: list[str]) -> list[str]:
    """Distinctive values in the arguments that appeared in the given content and not in the user's messages."""
    if not values:
        return []
    seen, user = set(values), set(user_values)
    out = []
    for value in distinctive_values(arguments_text):
        fp = fingerprint(value, "hostile")
        if fp in seen and fp not in user:
            out.append(value[:80])
    return out


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
    kind = consequence(tool, caps, tagged, arguments if arguments is not None else arguments_text, remote=bool(remote),
                       declared=policy.declared_consequence(tool))
    classic = policy.trifecta_scope == "all"
    if leaves and state.fingerprints and (classic or kind != "local"):
        if contains_fingerprint(arguments_text, state.fingerprints, allowed_kinds=allowed):
            emit("sensitive_data_egress", Category.DATA_EXFILTRATION.value, 1.0,
                 "A sensitive value seen earlier in this session is being sent out of the machine by this tool call.",
                 sources=state.sensitive_sources[-5:])  # fmt: skip
    # Only allowed data types seen (and every source typed): nothing this tool may not send.
    only_allowed = bool(allowed) and bool(state.sensitive_kinds) and set(state.sensitive_kinds) <= allowed
    if (egress or (not classic and kind == "irreversible")) and state.untrusted and state.sensitive and not only_allowed:
        if policy.trifecta_scope == "all":
            emit("trifecta", Category.DATA_EXFILTRATION.value, 0.7,
                 "This session has read untrusted content and sensitive data; network/exec actions need approval.",
                 untrusted=state.untrusted_sources[-5:], sensitive=state.sensitive_sources[-5:])  # fmt: skip
        else:
            carried = _carried(arguments_text, state.untrusted_values, state.user_values) if kind != "local" else []
            if kind == "irreversible":  # publishing or sharing can expose the data with no attacker address at all
                emit("trifecta", Category.DATA_EXFILTRATION.value, 0.75,
                     "This session holds sensitive data and has read untrusted content; this action publishes or can't be undone.",
                     untrusted=state.untrusted_sources[-5:], sensitive=state.sensitive_sources[-5:], consequence=kind)  # fmt: skip
            elif carried:
                emit("trifecta", Category.DATA_EXFILTRATION.value, 0.75,
                     "This session holds sensitive data, and this action sends to a destination that came from untrusted content.",
                     untrusted=state.untrusted_sources[-5:], sensitive=state.sensitive_sources[-5:], values=carried[:5])  # fmt: skip
    if policy.untrusted_destination != "off" and state.untrusted_phrases and (
        kind == "irreversible" or (policy.untrusted_destination == "outbound" and kind == "outbound")
    ):
        seen, user_p = set(state.untrusted_phrases), set(state.user_phrases)
        dests = [v for v in destination_values(arguments, policy.destination_args.get(tool, ())) if _outside_place(v)]
        copied = [v[:80] for v in dests if _h(v, "phrase") in seen and _h(v, "phrase") not in user_p]
        # The same destination written another way (a scheme or "www." added, data appended as a query) is still the
        # same place: compare places (host/path and its parents, or an address), not text.
        outside, known = set(state.untrusted_places), set(state.user_places)
        for v in dests:
            if v[:80] in copied:
                continue
            fps = {_h(p, "place") for p in destination_places(v) | destination_places(_canonical(v))}
            if fps & outside and not fps & known:
                copied.append(v[:80])
        if copied and kind == "outbound" and _adds_nothing(arguments, policy.destination_args.get(tool, ()), state):
            copied = []
        if copied:
            emit("untrusted_destination", Category.PROMPT_INJECTION.value, 0.7,
                 f"This action sends to {', '.join(repr(v[:60]) for v in copied[:2])}, which came from content an "
                 f"outsider can write ({', '.join(str(x)[:60] for x in state.untrusted_sources[-2:]) or 'untrusted content'}), "
                 "not from you. Approve only if you meant this recipient.",
                 consequence=kind, values=copied[:5], untrusted=state.untrusted_sources[-5:])  # fmt: skip
    if acts and state.hostile:
        if policy.after_injection_scope == "all":
            emit("after_injection", Category.PROMPT_INJECTION.value, 0.7,
                 "This session read content containing a prompt injection; side-effecting actions need approval.",
                 hostile=state.hostile_sources[-5:])  # fmt: skip
        else:
            carried = _carried(arguments_text, state.hostile_values, state.user_values) if kind == "outbound" else []
            if kind == "outbound" and not carried and state.hostile_phrases:
                # a destination argument whose value was copied from the injected content, whatever its shape
                hostile_p, user_p = set(state.hostile_phrases), set(state.user_phrases)
                carried = [v[:80] for v in destination_values(arguments, policy.destination_args.get(tool, ()))
                           if _h(v, "phrase") in hostile_p and _h(v, "phrase") not in user_p]  # fmt: skip
            if kind == "irreversible":
                emit("after_injection", Category.PROMPT_INJECTION.value, 0.7,
                     "This session read content containing a prompt injection; this action can't be undone, so it needs approval.",
                     hostile=state.hostile_sources[-5:], consequence=kind)  # fmt: skip
            elif carried:
                emit("after_injection", Category.PROMPT_INJECTION.value, 0.8,
                     "This action sends a value that came from content containing a prompt injection, not from the user.",
                     hostile=state.hostile_sources[-5:], consequence=kind, values=carried[:5])  # fmt: skip
    accepts_untrusted, _ = policy.sink(tool)
    cap = policy.call_cap(tool, arguments)
    context = state.label
    if not accepts_untrusted and context.integrity >= Integrity.UNTRUSTED:
        emit("untrusted_to_protected_sink", Category.PROMPT_INJECTION.value, 0.8,
             f"This tool doesn't accept untrusted input, and the session has read {context.integrity.value} content.",
             label=context.to_dict(), untrusted=state.untrusted_sources[-5:], hostile=state.hostile_sources[-5:])  # fmt: skip
    if cap is not None and context.confidentiality > cap and _carries_private(state, arguments):
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

    # --- task profiles (guardlayer.tasks) ---------------------------------------------------------------
    def set_task(self, name: str, task_args: Mapping[str, Any] | None = None, *, approved: bool = False) -> None:
        """Put the session under the task profile `name`. Call it from trusted code with the user's request.

        Setting a first task, or a narrower one, needs nothing. Switching to a task that allows a tool the current one
        doesn't (widening) raises `PermissionError` unless `approved=True` (a human agreed), and the approval is logged.
        """
        profile = self.guard.session_policy.tasks.get(name)
        if profile is None:
            raise KeyError(f"unknown task {name!r}; define it under [tasks.{name}]")
        args = dict(task_args or {})
        profile.argument_rules(args)  # fails now, not at the first tool call, if a {task.NAME} value is missing
        state = self.state
        widening = state.task_tools is not None and not set(profile.tools) <= set(state.task_tools)
        if widening and not approved:
            raise PermissionError(f"task {name!r} allows tools the current task {state.task!r} doesn't; needs approved=True")
        entry = f"{'widened (approved)' if widening else 'set'}: {name}"
        state.task, state.task_args, state.task_tools = name, args, list(profile.tools)
        state.task_version += 1
        state.task_log = [*state.task_log, entry][-50:]
        self.guard.sessions.put(state)

    def narrow(self, tools: list[str]) -> None:
        """Keep only these of the current task's tools (never adds any). No approval needed."""
        state = self.state
        if state.task_tools is None:
            raise ValueError("no task is set; call set_task first")
        state.task_tools = [t for t in state.task_tools if t in set(tools)]
        state.task_version += 1
        state.task_log = [*state.task_log, f"narrowed: {state.task_tools}"][-50:]
        self.guard.sessions.put(state)

    def clear_task(self, *, approved: bool = False) -> None:
        """Remove the task restriction. That widens what the agent may do, so it needs `approved=True`."""
        state = self.state
        if state.task_tools is not None and not approved:
            raise PermissionError("clearing a task widens the agent's permissions; needs approved=True")
        state.task_log = [*state.task_log, f"cleared (approved): {state.task}"][-50:]
        state.task, state.task_args, state.task_tools = None, {}, None
        state.task_version += 1
        self.guard.sessions.put(state)

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

    def needs_intent_check(self, tool_name: str) -> bool:
        return self.guard.needs_intent_check(tool_name, session=self.id)

    def check_intent(self, tool_name: str, arguments: Any = None, **kwargs: Any) -> ScanResult:
        return self.guard.check_intent(tool_name, arguments, session=self.id, **kwargs)

    async def acheck_intent(self, tool_name: str, arguments: Any = None, **kwargs: Any) -> ScanResult:
        return await self.guard.acheck_intent(tool_name, arguments, session=self.id, **kwargs)

    def reset(self) -> None:
        self.guard.sessions.delete(self.id)

    def __repr__(self) -> str:
        s = self.state
        return f"GuardSession({self.id!r}, untrusted={s.untrusted}, hostile={s.hostile}, sensitive={s.sensitive})"
