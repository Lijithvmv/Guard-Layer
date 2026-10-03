"""What an action does to the world, and which of its values came from an attacker.

After a session reads content containing a prompt injection, GuardLayer used to hold every later action that could
write, execute or reach the network. On real Claude Code sessions that stopped about two thirds of all work, almost
all of it local and recoverable, while in AgentDojo every attack that got past detection did its harm through an
outbound action **carrying a value from the injected text**: the attacker's IBAN, URL, e-mail address or upload
endpoint. So after an injection GuardLayer now asks two narrower questions:

* **What is the consequence class of this action?** `outbound` (reaches another system: network, messages, payments,
  pushes), `irreversible` (local but not undoable: deletes, history rewrites, persistence) or `local` (edits, writes,
  builds, tests in the workspace).
* **Does an outbound action carry a distinctive value that appeared in hostile content and not in the user's own
  messages?** Distinctive means an identifier an attacker would plant (URL or domain, e-mail, IBAN, long number,
  long mixed token), never common words.

`irreversible` actions are held after an injection; `outbound` ones only when they carry such a value; `local` ones
run. Values are stored as salted hashes, like secret fingerprints.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from typing import Any

from guardlayer.shell import analyse

_TLDS = (
    "com org net io ai dev app co gov edu info xyz me us uk in de fr nl eu ru cn jp br au ca biz site online tech cloud "
    "page link top click shop store live pro ly sh to gg so"
).split()
_URL = re.compile(r"\b(?:https?|wss?|ftps?)://[^\s\"'<>`\\)\]]+", re.IGNORECASE)
_DOMAIN = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + "|".join(_TLDS) + r"))\b(/[^\s\"'<>`\\)\]]*)?", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]{1,64}@[\w-]+(?:\.[\w-]+)+\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_LONG_NUMBER = re.compile(r"(?<![\w.])\d[\d -]{7,}\d(?![\w.])")
_MIXED_TOKEN = re.compile(r"\b(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{12,}\b")


def distinctive_values(text: str, limit: int = 2000) -> set[str]:
    """Identifiers an attacker would plant (normalised, lower-case)."""
    found: set[str] = set()
    text = text[:200_000]
    for m in _URL.finditer(text):
        url = m.group(0).rstrip(".,;:!?").lower()
        found.add(re.sub(r"^\w+://(www\.)?", "", url).rstrip("/"))
        host = re.sub(r"^\w+://(www\.)?", "", url).split("/")[0].split(":")[0]
        if "." in host:
            found.add(host)
    for m in _DOMAIN.finditer(text):
        host = re.sub(r"^www\.", "", m.group(1).lower())
        found.add(host)
        if m.group(2) and len(m.group(2)) > 1:
            found.add((host + m.group(2)).rstrip(".,;:!?/").lower())
    for pattern in (_EMAIL, _IBAN):
        found.update(v.lower() for v in pattern.findall(text))
    for m in _LONG_NUMBER.finditer(text):
        found.add(re.sub(r"[ -]", "", m.group(0)))
    for m in _MIXED_TOKEN.finditer(text):
        found.add(m.group(0).lower())
    return set(list(found)[:limit])


# Arguments that say where data or an action goes. A value in one of these copied from injected content, whatever its
# shape (a plain name like "Fred" included), is the attacker choosing the destination.
DESTINATION_ARGS = frozenset(
    "to cc bcc recipient recipients email emails address addresses url uri link endpoint host hostname domain webhook "
    "channel channels user users username user_email member members account account_id iban phone number target "
    "destination dest repo repository owner org organization share_with assignee reviewer reviewers".split()
)
MAX_PHRASE_WORDS = 4


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def phrases(text: str, limit: int = 20_000) -> set[str]:
    """Every run of 1–4 words in `text` (normalised): what a destination argument copied from it could look like."""
    words = re.findall(r"[\w@.+:/-]+", text.lower()[:100_000])
    out: set[str] = set()
    for n in range(1, MAX_PHRASE_WORDS + 1):
        for i in range(len(words) - n + 1):
            out.add(" ".join(words[i : i + n]).strip(".:"))
            if len(out) >= limit:
                return out
    return out


def destination_values(arguments: Mapping[str, Any] | str | None, extra: Iterable[str] = ()) -> list[str]:
    """Short string values of destination arguments (normalised)."""
    if not isinstance(arguments, Mapping):
        return []
    keys = DESTINATION_ARGS | set(extra)
    out: list[str] = []
    for key, value in arguments.items():
        if key.lower() not in keys:
            continue
        for v in value if isinstance(value, (list, tuple)) else [value]:
            if isinstance(v, (str, int)) and 0 < len(str(v)) <= 200:
                out.append(_norm(str(v)).strip(".:"))
    return out


# --------------------------------------------------------------------------------------------------- consequence
_NET_PROGRAMS = {
    "curl", "wget", "fetch", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet", "ftp", "gh", "glab", "twine",
    "iwr", "irm", "Invoke-WebRequest", "Invoke-RestMethod", "Send-MailMessage", "sendmail", "mail", "mutt", "aws", "az",
    "gcloud", "gsutil", "kubectl", "helm", "terraform", "heroku", "vercel", "netlify", "fly", "wrangler",
}
_NET_SUBCOMMANDS = {
    "git": {"push", "fetch", "pull", "clone", "remote", "ls-remote", "send-email", "request-pull"},
    "npm": {"publish", "install", "i", "ci", "add", "login", "adduser", "unpublish"},
    "pnpm": {"publish", "install", "add"}, "yarn": {"publish", "add", "install"},
    "pip": {"install", "download", "upload"}, "pip3": {"install", "download"}, "uv": {"pip", "add", "sync", "publish"},
    "cargo": {"publish", "install"}, "docker": {"push", "pull", "login"}, "ollama": {"pull", "push"},
}
_IRREVERSIBLE_PROGRAMS = {"rm", "rmdir", "del", "erase", "rd", "Remove-Item", "shred", "truncate", "dd", "mkfs", "format", "srm", "unlink"}
_IRREVERSIBLE_GIT = {("reset", "--hard"), ("clean", None), ("checkout", "--"), ("restore", None), ("stash", "drop"), ("stash", "clear"), ("branch", "-D")}
# Publishing turns recoverable local changes into irreversible shared ones: after an injection, whatever the session
# changed locally becomes public at this point, so these are held like deletes.
_PUBLISH = {
    "git": {"push", "send-email", "request-pull"}, "npm": {"publish", "unpublish"}, "pnpm": {"publish"}, "yarn": {"publish"},
    "cargo": {"publish"}, "twine": {"upload"}, "docker": {"push"}, "gh": {"release", "pr", "repo", "gist"},
    "uv": {"publish"}, "poetry": {"publish"}, "vercel": {"deploy", "--prod"}, "netlify": {"deploy"}, "fly": {"deploy"},
    "kubectl": {"apply", "delete", "rollout"}, "helm": {"install", "upgrade", "uninstall"}, "terraform": {"apply", "destroy"},
}
# Effects on another system that can't be taken back: money, bookings and orders, credentials, access, deletion,
# publishing. After an injection these are held whatever their arguments, like local deletes (NCSC's
# recoverability dimension).
_IRREVERSIBLE_ACTION = re.compile(
    r"(^|[_\-.])(send_?money|transfer|pay|payment|purchase|buy|order|checkout|book|reserve|reservation|refund|withdraw"
    r"|update_?password|change_?password|reset_?password|set_?password|password|credential|token|api_?key|secret"
    r"|delete|remove|destroy|drop|revoke|ban|kick|archive|invite|grant|add_?user|add_?member|share|permission|role"
    r"|publish|deploy|release|merge|approve|sign|upload|pull_?request|pr|issue|comment|gist|push_?files?"
    r"|create_or_update_file|fork)([_\-.]|$)",
    re.IGNORECASE,
)
# Tools whose verb only reads or looks up (get_issue, list_pull_requests): the noun doesn't make them act.
_READ_VERB = re.compile(r"(^|__|[_\-.])(get|list|read|search|fetch|view|show|describe|find|query|lookup|check|count|search_?\w*)_", re.IGNORECASE)
_LOCAL_WRITE_TOOL = re.compile(r"^(Write|Edit|MultiEdit|NotebookEdit)$|(^|_)(write|edit|create|append|save|patch)_?(file|notebook)s?$", re.IGNORECASE)
_COMMAND_KEYS = ("command", "cmd", "script", "shell_command")


def _command(arguments: Mapping[str, Any] | str | None) -> str | None:
    if isinstance(arguments, Mapping):
        for key in _COMMAND_KEYS:
            if isinstance(arguments.get(key), str):
                return arguments[key]
    return None


_ORDER = {"local": 0, "outbound": 1, "irreversible": 2}


def consequence(
    tool: str,
    caps: Iterable[str],
    tagged: bool,
    arguments: Mapping[str, Any] | str | None,
    *,
    remote: bool = False,
    declared: str | None = None,
) -> str:
    """The consequence class of a call. A declared class wins over the guess from the tool's name; for a shell tool the
    parsed command is still read, and the stricter of the two counts."""
    guessed = _guess(tool, caps, tagged, arguments, remote=remote)
    if declared is None:
        return guessed
    if _command(arguments) is not None:
        return max(declared, guessed, key=_ORDER.__getitem__)
    return declared


def _guess(
    tool: str, caps: Iterable[str], tagged: bool, arguments: Mapping[str, Any] | str | None, *, remote: bool = False
) -> str:
    """`irreversible` (local or on another system), `outbound` (reaches another system, undoable or informational:
    messages, fetches, posts) or `local` for a proposed tool call."""
    caps = set(caps)
    command = _command(arguments) if "exec" in caps or not tagged else None
    if command is not None:
        view = analyse(command)
        if view is None:
            return "outbound"  # can't tell what it does: treat as the riskiest class
        result = "local"
        for pipeline in view.commands:
            for cmd in pipeline:
                if not cmd.argv:
                    continue
                prog = re.split(r"[/\\]", cmd.argv[0])[-1].removesuffix(".exe")
                args = cmd.argv[1:]
                if prog in _PUBLISH and args and args[0] in _PUBLISH[prog]:
                    return "irreversible"
                if prog in _NET_PROGRAMS or (prog in _NET_SUBCOMMANDS and args and args[0] in _NET_SUBCOMMANDS[prog]):
                    result = "outbound" if result == "local" else result
                    continue
                if prog.startswith("__") or (prog in ("python", "python3", "node") and any(a.startswith(("http://", "https://")) for a in args)):
                    result = "outbound" if result == "local" else result  # dynamic or network-capable inline code
                    continue
                if prog in _IRREVERSIBLE_PROGRAMS:
                    result = "irreversible"
                if prog == "git" and args and any(args[0] == sub and (flag is None or flag in args) for sub, flag in _IRREVERSIBLE_GIT):
                    result = "irreversible"
        return result
    if _LOCAL_WRITE_TOOL.search(tool):
        return "local"
    reads_only = bool(_READ_VERB.search(tool)) and not re.search(r"(^|_)(and|or)_", tool)
    if reads_only:
        # a search query or a fetched URL leaves the machine even though the tool only reads
        return "outbound" if remote or caps & {"network"} or not tagged else "local"
    if _IRREVERSIBLE_ACTION.search(tool) and (not tagged or caps & {"network", "write", "exec"}):
        return "irreversible"
    if caps and not (caps & {"network", "write", "exec"}) and not remote:
        return "local"  # read-only, local tools (declared or inferred from the name)
    return "outbound"  # messages, payments, posts, API calls: effects on another system


MAX_SCRIPT_BYTES = 200_000


def file_consequence(path: str) -> str:
    """The consequence class of running a script file: the most severe of the commands it would execute.

    Shell scripts are parsed with `guardlayer.shell`; Python with `ast` (network imports, or commands passed to
    `os.system`/`subprocess`). A file that can't be read or parsed counts as `outbound` (fail safe)."""
    from guardlayer.shell import _python_commands  # local import: shell owns the Python analysis

    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_SCRIPT_BYTES + 1)
    except OSError:
        return "outbound"
    if len(raw) > MAX_SCRIPT_BYTES:
        return "outbound"
    text = raw.decode("utf-8", errors="replace")
    if path.lower().endswith((".py", ".pyw")):
        found = _python_commands(text)
        if found is None:
            return "outbound"
        commands, _opened, network = found
        if network:
            return "outbound"
        worst = "local"
        for command in commands:
            kind = consequence("Bash", {"exec"}, True, {"command": command}) if command != "__DYNAMIC__" else "outbound"
            if kind == "irreversible":
                return kind
            if kind == "outbound":
                worst = kind
        return worst
    if os.path.splitext(path)[1].lower() in (".sh", ".bash", ".zsh", ""):
        return consequence("Bash", {"exec"}, True, {"command": text})
    return "outbound"  # other interpreters (node, ruby, ...) aren't analysed yet
