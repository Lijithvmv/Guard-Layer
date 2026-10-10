"""A local credential broker: the agent calls a service through GuardLayer and never holds the token.

Experimental: tested end to end against a recorded upstream and on recorded real requests, not yet in live use.

The agent asks `http://127.0.0.1:47300/github/repos/OWNER/REPO/actions/runs` with no credential. The broker checks the
request against the route's allow-list, fetches the token itself (`git credential fill`, an environment variable or a
file), adds it, forwards the request, and returns the response with the token scrubbed out. Anything not allowed gets a
403 that says why. The token never enters the agent's context, so injected text can't ask the agent to print it, reuse
it elsewhere, or point it at another repository.

Binding a token to a host isn't enough: a GitHub token sent only to api.github.com still publishes a public gist,
pushes to any repository or deletes one. Routes bind to *requests*: a method and a path, where `{repo}` stands for the
repositories of the working directory (its git remotes), so the default lets the agent read its own repository's CI and
nothing else.

```toml
[broker]
port = 47300
repos = "git"                       # the working directory's git remotes, or a list: ["owner/repo"]
audit = "broker-audit.jsonl"        # one line per request, allowed or refused (never the token)

[broker.routes.github]
upstream = "https://api.github.com"
credential = "git:github.com"       # or "env:GITHUB_TOKEN", "file:/path/to/token"
allow = ["GET /repos/{repo}/**"]    # METHOD path-glob; ** crosses "/", * doesn't
```

Then: `guardlayer --config guardlayer.toml broker`. The same idea as credential proxies in managed agent sandboxes,
where the sandbox holds only a placeholder and the platform adds the real token for allowed hosts; here per request.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

DEFAULT_PORT = 47300
_FORWARD_HEADERS = ("accept", "content-type", "x-github-api-version", "user-agent")
_REMOTE = re.compile(r"github\.com[:/]+([^/\s]+)/([^/\s]+?)(?:\.git)?/?$")
_MAX_BODY = 20 * 1024 * 1024


@dataclass(frozen=True)
class Route:
    name: str
    upstream: str
    credential: str
    allow: tuple[str, ...]
    header: str = "Authorization"
    scheme: str = "Bearer"

    @classmethod
    def from_dict(cls, name: str, data: Mapping[str, Any]) -> Route:
        unknown = set(data) - {"upstream", "credential", "allow", "header", "scheme"}
        if unknown:
            raise ValueError(f"broker route {name!r}: unknown key(s) {sorted(unknown)}")
        upstream = str(data.get("upstream", "")).rstrip("/")
        if not upstream.startswith("https://"):
            raise ValueError(f"broker route {name!r}: upstream must be an https:// URL")
        credential = str(data.get("credential", ""))
        if not credential.startswith(("git:", "env:", "file:")):
            raise ValueError(f'broker route {name!r}: credential must be "git:HOST", "env:NAME" or "file:PATH"')
        allow = tuple(str(a) for a in data.get("allow", ()))
        for rule in allow:
            if len(rule.split(None, 1)) != 2:
                raise ValueError(f'broker route {name!r}: allow entries are "METHOD /path-glob", not {rule!r}')
        return cls(name, upstream, credential, allow, str(data.get("header", "Authorization")), str(data.get("scheme", "Bearer")))


@dataclass
class BrokerPolicy:
    routes: dict[str, Route]
    repos: list[str] = field(default_factory=list)  # "owner/repo", lower-case
    audit: str | None = None

    @classmethod
    def from_config(cls, config: Mapping[str, Any], cwd: str | Path = ".") -> BrokerPolicy:
        broker = dict(config.get("broker", {}))
        routes = {name: Route.from_dict(name, spec) for name, spec in dict(broker.get("routes", {})).items()}
        if not routes:
            raise ValueError("[broker] needs at least one [broker.routes.NAME]")
        repos_cfg = broker.get("repos", "git")
        repos = git_repos(cwd) if repos_cfg == "git" else [str(r).lower() for r in repos_cfg]
        return cls(routes, repos, broker.get("audit"))

    def decide(self, route: str, method: str, path: str) -> tuple[bool, str]:
        """Whether `METHOD /path` may go through `route`, and why (never mentions the credential)."""
        r = self.routes.get(route)
        if r is None:
            return False, f"no route {route!r}; configured: {', '.join(sorted(self.routes))}"
        path = "/" + path.lstrip("/").split("?", 1)[0]
        if ".." in path.split("/"):
            return False, "path traversal"
        for rule in r.allow:
            m, glob = rule.split(None, 1)
            if m.upper() not in ("*", method.upper()):
                continue
            for pattern in _expand(glob, self.repos):
                if _glob_match(pattern.lower(), path.lower()):
                    return True, f"allowed by {rule!r}"
        scope = f" (repositories: {', '.join(self.repos) or 'none found'})" if any("{repo}" in a for a in r.allow) else ""
        return False, f"{method.upper()} {path} isn't in route {route!r}'s allow-list{scope}"


def _expand(glob: str, repos: list[str]) -> list[str]:
    if "{repo}" not in glob:
        return [glob]
    return [glob.replace("{repo}", repo) for repo in repos]


def _glob_match(pattern: str, path: str) -> bool:
    """`**` matches across "/", `*` within one segment."""
    regex = re.escape(pattern).replace(r"\*\*", "\0").replace(r"\*", "[^/]*").replace("\0", ".*")
    return re.fullmatch(regex, path) is not None


def git_repos(cwd: str | Path = ".") -> list[str]:
    """"owner/repo" for every GitHub remote of the git checkout at `cwd` (lower-case)."""
    try:
        out = subprocess.run(["git", "remote", "-v"], cwd=str(cwd), capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    repos = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            m = _REMOTE.search(parts[1])
            if m:
                repos.append(f"{m.group(1)}/{m.group(2)}".lower())
    return sorted(set(repos))


class Credentials:
    """Fetches and caches tokens in the broker process only."""

    def __init__(self, ttl: float = 300.0, runner: Callable[[list[str], str], str] | None = None) -> None:
        self.ttl = ttl
        self._cache: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()
        self._run = runner or _run_git

    def get(self, spec: str) -> str:
        with self._lock:
            hit = self._cache.get(spec)
            if hit and time.monotonic() - hit[0] < self.ttl:
                return hit[1]
            kind, _, value = spec.partition(":")
            if kind == "env":
                token = os.environ.get(value, "")
            elif kind == "file":
                token = Path(value).expanduser().read_text(encoding="utf-8").strip()
            else:  # git:HOST
                answer = self._run(["git", "credential", "fill"], f"protocol=https\nhost={value}\n\n")
                token = next((ln.split("=", 1)[1] for ln in answer.splitlines() if ln.startswith("password=")), "")
            if not token:
                raise LookupError(f"no credential available from {kind}:{value if kind != 'file' else '…'}")
            self._cache[spec] = (time.monotonic(), token)
            return token


def _run_git(argv: list[str], stdin: str) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}  # never prompt: a missing credential is an error, not a dialog
    return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=20, env=env).stdout


def scrub(data: bytes, secrets: Iterable[str]) -> bytes:
    for s in secrets:
        if s:
            data = data.replace(s.encode(), b"[REDACTED:broker]")
    return data


def make_handler(policy: BrokerPolicy, credentials: Credentials,
                 opener: Callable[[urllib.request.Request], Any] | None = None) -> type[BaseHTTPRequestHandler]:
    open_ = opener or (lambda req: urllib.request.urlopen(req, timeout=60))
    audit_lock = threading.Lock()

    def audit(entry: dict[str, Any]) -> None:
        if policy.audit:
            with audit_lock, open(policy.audit, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"time": time.time(), **entry}) + "\n")

    class Handler(BaseHTTPRequestHandler):
        server_version = "guardlayer-broker"

        def log_message(self, *args: Any) -> None:
            pass

        def _reply(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle(self) -> None:
            route, _, rest = self.path.lstrip("/").partition("/")
            method = self.command
            allowed, reason = policy.decide(route, method, rest)
            entry = {"route": route, "method": method, "path": "/" + rest.split("?", 1)[0], "allowed": allowed, "reason": reason}
            if not allowed:
                audit(entry)
                self._reply(403, json.dumps({"error": "refused by guardlayer broker", "reason": reason}).encode())
                return
            r = policy.routes[route]
            try:
                token = credentials.get(r.credential)
            except (LookupError, OSError) as e:
                audit({**entry, "allowed": False, "reason": str(e)})
                self._reply(502, json.dumps({"error": "no credential", "reason": str(e)}).encode())
                return
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(min(length, _MAX_BODY)) if length else None
            headers = {k: v for k, v in self.headers.items() if k.lower() in _FORWARD_HEADERS}
            headers[r.header] = f"{r.scheme} {token}".strip()
            req = urllib.request.Request(r.upstream + "/" + rest, data=body, headers=headers, method=method)
            try:
                with open_(req) as resp:
                    status, data, ctype = resp.status, resp.read(_MAX_BODY), resp.headers.get("Content-Type", "application/octet-stream")
            except urllib.error.HTTPError as e:
                status, data, ctype = e.code, e.read(_MAX_BODY), e.headers.get("Content-Type", "application/json")
            except (urllib.error.URLError, OSError) as e:
                status, data, ctype = 502, json.dumps({"error": "upstream unreachable", "reason": str(e)}).encode(), "application/json"
            audit({**entry, "status": status})
            self._reply(status, scrub(data, [token]), ctype)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle

    return Handler


def serve(policy: BrokerPolicy, port: int = DEFAULT_PORT, credentials: Credentials | None = None) -> ThreadingHTTPServer:
    """A broker on 127.0.0.1 only (call `serve_forever()` on the result)."""
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(policy, credentials or Credentials()))
