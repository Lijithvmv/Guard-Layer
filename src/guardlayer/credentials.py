"""Where a credential goes after an agent fetches it (credential binding).

An agent that runs `TOKEN=$(git credential fill ...)` and then `curl -H "Authorization: Bearer $TOKEN"
https://api.github.com/...` is using a credential the way it is meant to be used: the secret stays in a shell variable and
only reaches the service it belongs to. The same token printed into the transcript (where injected text can ask the
agent to repeat it) or sent to any other host is a leak. In 12 real Claude Code sessions, all 19 credential fetches were
of the first kind; GuardLayer used to hold every one of them.

This module follows the idea behind credential providers in agent sandboxes (a credential is bound to the endpoints it
is for) without a sandbox: it reads the command, finds credentials captured into variables, and checks every use of
those variables. `credential_flow()` returns `bound` (every use goes to the credential's own service), `writes` (it
does, but to change something there: a POST, PUT, PATCH or DELETE, or an upload), `printed` (fetched straight into the
output, echoed, or written to a file), `elsewhere` (sent to another host), or `unknown`.

Why `writes` is separate: binding to a host isn't binding to a task. A GitHub token bound to api.github.com still
publishes a public gist, pushes to any repo or deletes one, all "on github.com". Reads of the service are what the
recorded real uses were; a write is held for a person (or done through `guardlayer broker`, scoped per repository).
"""

from __future__ import annotations

import re

from guardlayer.shell import analyse

# The service a credential belongs to, by the command that hands it out.
_SERVICE_HOSTS: dict[str, tuple[str, ...]] = {
    "github": ("github.com", "githubusercontent.com", "ghcr.io"),
    "gitlab": ("gitlab.com",),
    "google": ("googleapis.com", "google.com", "gcr.io", "pkg.dev"),
    "azure": ("azure.com", "microsoft.com", "windows.net", "azurecr.io", "microsoftonline.com"),
    "aws": ("amazonaws.com", "aws.amazon.com"),
    "npm": ("npmjs.org", "npmjs.com"),
}
_CREDENTIAL_COMMANDS: list[tuple[re.Pattern[str], str | None]] = [
    (re.compile(r"\bgit\s+credential(-\w+)?\s+(fill|get)\b"), "git"),
    (re.compile(r"\bgh\s+auth\s+token\b"), "github"),
    (re.compile(r"\bglab\s+auth\s+status\b"), "gitlab"),
    (re.compile(r"\bgcloud\s+auth\s+(application-default\s+)?print-(access|identity)-token\b"), "google"),
    (re.compile(r"\baz\s+account\s+get-access-token\b"), "azure"),
    (re.compile(r"\baws\s+(configure\s+get|sts\s+get-session-token|ecr\s+get-login-password|codeartifact\s+get-authorization-token)\b"), "aws"),
    (re.compile(r"\bnpm\s+token\b"), "npm"),
    # password managers and OS keychains hand out secrets for anything: no service to bind to
    (re.compile(r"\b(security\s+find-(generic|internet)-password|secret-tool\s+lookup|op\s+(read|item\s+get)|bw\s+get|vault\s+(kv\s+get|read)|keyring\s+get|pass\s+show)\b"), None),
]
_ASSIGN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)=\$\(")
_URL_HOST = re.compile(r"\b(?:https?|wss?)://(?:[^@/\s\"']*@)?([^/:\s\"'?#]+)", re.IGNORECASE)
_NET = {"curl", "wget", "http", "https", "xh", "iwr", "irm", "Invoke-WebRequest", "Invoke-RestMethod", "git", "gh", "nc", "ssh", "scp"}
_PRINTERS = {"echo", "printf", "cat", "tee", "print", "Write-Output", "Write-Host"}
# Requests that change something on the service: an explicit write method, or a body/upload (curl/wget/httpie/PowerShell).
_WRITE_METHOD = re.compile(r"^(?:-X|--request|-Method|--method)$", re.IGNORECASE)
_WRITE_VERBS = {"post", "put", "patch", "delete"}
_BODY_FLAGS = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "-F", "--form", "-T",
               "--upload-file", "--post-data", "--post-file", "--body-data", "--body-file", "-Body", "-InFile"}


def _balanced(src: str, start: int) -> str | None:
    """The text inside `$( ... )` starting at `start` (the index just after `$(`)."""
    depth, i = 1, start
    while i < len(src) and depth:
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
        i += 1
    return src[start : i - 1] if depth == 0 else None


def _service(text: str) -> tuple[str, ...] | None:
    """Hosts the credential fetched in `text` belongs to; () when it has no single service; None if no credential."""
    for pattern, service in _CREDENTIAL_COMMANDS:
        if pattern.search(text):
            if service == "git":
                m = re.search(r"host=([A-Za-z0-9.-]+)", text)
                host = m.group(1).lower() if m else "github.com"
                return _SERVICE_HOSTS["github"] if host.endswith("github.com") else (host,)
            return _SERVICE_HOSTS[service] if service else ()
    return None


def _allowed(host: str, hosts: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == h or host.endswith("." + h) for h in hosts)


def credential_flow(command: str) -> str:
    """`bound`, `printed`, `elsewhere` or `unknown` for a command that fetches a credential ('' if it fetches none)."""
    if _service(command) is None:
        return ""
    captured: dict[str, tuple[str, ...]] = {}
    covered: list[tuple[int, int]] = []
    for m in _ASSIGN.finditer(command):
        inner = _balanced(command, m.end())
        if inner is None:
            return "unknown"
        hosts = _service(inner)
        if hosts is not None:
            captured[m.group(1)] = hosts
            covered.append((m.start(), m.end() + len(inner) + 1))
    # a credential command outside any captured substitution prints the secret
    rest = "".join(ch for i, ch in enumerate(command) if not any(a <= i < b for a, b in covered))
    if _service(rest) is not None:
        return "printed"
    if not captured:
        return "unknown"
    view = analyse(command, keep_data=True)
    if view is None:
        return "unknown"
    used = writes = False
    for pipeline in view.commands:
        for cmd in pipeline:
            words = cmd.argv + [t for _, t in cmd.redirects]
            for name, hosts in captured.items():
                ref = re.compile(r"\$\{?" + re.escape(name) + r"\b")
                if not any(ref.search(w) for w in words):
                    continue
                used = True
                prog = re.split(r"[/\\]", cmd.argv[0])[-1] if cmd.argv else ""
                if prog in _PRINTERS or any(ref.search(t) for _, t in cmd.redirects):
                    return "printed"
                targets = {h for w in cmd.argv for h in _URL_HOST.findall(w)}
                if targets and not all(_allowed(h, hosts) for h in targets):
                    return "elsewhere"
                if prog in _NET and not targets:
                    return "unknown"  # a network program with no visible destination
                if not hosts and targets:
                    return "elsewhere"  # a secret with no service of its own leaving the machine
                if _writes(cmd.argv):
                    writes = True
    if used and writes:
        return "writes"
    return "bound"  # every use toward its own service (or captured and never used: nothing left the variable)


def _writes(argv: list[str]) -> bool:
    """A request that changes something: an explicit POST/PUT/PATCH/DELETE, or a request body or upload."""
    for i, word in enumerate(argv):
        flag, _, inline = word.partition("=")
        if _WRITE_METHOD.match(flag) and (inline or (argv[i + 1] if i + 1 < len(argv) else "")).lower() in _WRITE_VERBS:
            return True
        if word.startswith("-X") and word[2:].lower() in _WRITE_VERBS:
            return True
        if flag in _BODY_FLAGS:
            return True
        if word.lower() in _WRITE_VERBS and i == 1 and argv[0] in ("http", "https", "xh"):
            return True
    return False
