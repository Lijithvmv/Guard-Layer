"""A long-running GuardLayer for Claude Code's HTTP hooks: no Python process started per tool call.

The command hook starts Python for every event (about 0.6 s on Windows, twice per tool call). Claude Code can instead
POST each event to a URL and read the same JSON reply. This server keeps the guard, its rules and its config loaded and
answers with exactly the same logic (`claude_code.handle_event`).

    guardlayer --config pilot.toml hook claude-code --server --print-config    # settings.json snippet

The snippet adds a `SessionStart` command hook that makes sure the server is running (`--ensure-server`), and HTTP
hooks for the tool and prompt events.

Security. It listens on 127.0.0.1 only. Requests from a browser are refused (any `Origin` header, a `Host` that isn't
a loopback name, a body that isn't JSON), so a web page can't reach it, even by DNS rebinding. An optional bearer token
(`--token-env NAME`) keeps other local users out on a shared machine. Nothing it receives is logged.

Failure mode, stated plainly: if the server isn't running when Claude Code calls it, Claude Code treats the failed
connection as a non-blocking error and the tool call goes ahead. `--ensure-server` at session start keeps that window
small and warns you when it can't start the server; the command hook has no such window.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from guardlayer.integrations import claude_code
from guardlayer.pipeline import GuardLayer

HOST = "127.0.0.1"
PATH = "/claude-code"
MAX_BODY = 16 * 1024 * 1024  # tool outputs can be large; bigger requests are refused
_LOOPBACK = {"127.0.0.1", "localhost", "[::1]"}
PORT_BASE, PORT_SPAN = 47100, 200


def default_port(config: str | None, preset: str | None) -> int:
    """A port per (config, preset), so projects with different configs don't share a server."""
    key = f"{Path(config).resolve().as_posix() if config else ''}|{preset or ''}"
    return PORT_BASE + int(hashlib.sha256(key.encode()).hexdigest(), 16) % PORT_SPAN


class HookService:
    """The guard behind the server: rebuilt when the config file changes, one event at a time."""

    def __init__(self, build: Callable[[], GuardLayer], *, config: str | None = None, preset: str | None = None,
                 block_prompts: bool = False, token: str | None = None, withhold: bool = False) -> None:  # fmt: skip
        self.build, self.config, self.preset = build, config, preset
        self.block_prompts, self.token, self.withhold = block_prompts, token, withhold
        self.started = time.time()
        self._lock = threading.Lock()
        self._mtime = self._config_mtime()
        self.guard = build()

    def _config_mtime(self) -> float | None:
        try:
            return os.stat(self.config).st_mtime if self.config else None
        except OSError:
            return None

    def handle(self, raw: bytes) -> bytes:
        with self._lock:
            mtime = self._config_mtime()
            if mtime != self._mtime:  # edited config: rebuild (a broken edit keeps the last good guard)
                try:
                    self.guard, self._mtime = self.build(), mtime
                except Exception as exc:
                    print(f"GuardLayer hook server: config reload failed, keeping the previous one: {exc}", file=sys.stderr)
            event: dict[str, Any] = {}
            try:
                event = json.loads(raw)
                output = claude_code.handle_event(event, self.guard, block_prompts=self.block_prompts, withhold=self.withhold)
            except Exception as exc:  # same contract as the command hook
                print(f"GuardLayer hook error: {type(exc).__name__}: {exc}", file=sys.stderr)
                output = claude_code.failure_output(self.guard, event, exc)
        return json.dumps(output).encode() if output is not None else b""

    def health(self) -> dict[str, Any]:
        from guardlayer import __version__

        return {"guardlayer": __version__, "pid": os.getpid(), "config": self.config, "preset": self.preset,
                "uptime_s": round(time.time() - self.started)}  # fmt: skip


def _make_handler(service: HookService) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "guardlayer-hook"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - nothing about requests is logged
            pass

        def _reply(self, status: int, body: bytes = b"", content_type: str = "application/json") -> None:
            self.send_response(status)
            if body:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _refused(self) -> int | None:
            """Status to refuse with, or None. Browsers always send Origin on cross-site POSTs; Host defeats DNS rebinding."""
            if self.headers.get("Origin") is not None:
                return 403
            host = (self.headers.get("Host") or "").lower()
            name = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
            if name not in _LOOPBACK:
                return 403
            if service.token is not None:
                given = self.headers.get("Authorization") or ""
                if not hmac.compare_digest(given.encode(), f"Bearer {service.token}".encode()):
                    return 401
            return None

        def do_GET(self) -> None:  # noqa: N802 - http.server's naming
            status = self._refused()
            if status:
                return self._reply(status)
            if self.path != "/health":
                return self._reply(404)
            self._reply(200, json.dumps(service.health()).encode())

        def do_POST(self) -> None:  # noqa: N802
            status = self._refused()
            if status:
                return self._reply(status)
            if self.path == "/shutdown":
                self._reply(200)
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return None
            if self.path != PATH:
                return self._reply(404)
            if not (self.headers.get("Content-Type") or "").lower().startswith("application/json"):
                return self._reply(415)
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                return self._reply(400)
            if length <= 0 or length > MAX_BODY:
                return self._reply(413 if length > MAX_BODY else 400)
            self._reply(200, service.handle(self.rfile.read(length)))
            return None

    return Handler


def make_server(service: HookService, port: int, host: str = HOST) -> ThreadingHTTPServer:
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError("the hook server only listens on a loopback address")
    server = ThreadingHTTPServer((host, port), _make_handler(service))
    server.daemon_threads = True
    return server


# ---------------------------------------------------------------------------------------------- client side
def _request(port: int, path: str, *, method: str = "GET", token: str | None = None, timeout: float = 1.0) -> dict | None:
    req = urllib.request.Request(f"http://{HOST}:{port}{path}", method=method, data=b"" if method == "POST" else None)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed loopback URL
            body = resp.read()
            return json.loads(body) if body else {}
    except (OSError, ValueError):
        return None


def ensure_server(port: int, start_command: list[str], *, config: str | None, preset: str | None, token: str | None = None,
                  log_path: Path | None = None, wait_s: float = 8.0) -> tuple[bool, str]:  # fmt: skip
    """Make sure a server with this config is answering on `port`. Returns (ok, message)."""
    want = Path(config).resolve().as_posix() if config else None
    health = _request(port, "/health", token=token)
    if health is not None:
        have = Path(health["config"]).resolve().as_posix() if health.get("config") else None
        if have == want and health.get("preset") == preset:
            return True, "running"
        _request(port, "/shutdown", method="POST", token=token)  # a server with another config: replace it
        time.sleep(0.3)
    log_path = log_path or Path("~/.guardlayer/hookserver.log").expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    flags: dict[str, Any] = {}
    if os.name == "nt":
        flags["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    else:
        flags["start_new_session"] = True
    with open(log_path, "ab") as log:
        subprocess.Popen(start_command, stdin=subprocess.DEVNULL, stdout=log, stderr=log, close_fds=True, **flags)  # noqa: S603
    deadline = time.time() + wait_s
    while time.time() < deadline:
        if _request(port, "/health", token=token) is not None:
            return True, "started"
        time.sleep(0.1)
    return False, f"couldn't start the GuardLayer hook server on port {port}; see {log_path}"


def settings_snippet(port: int, ensure_command: str, *, token_env: str | None = None, timeout: int = 30) -> dict[str, Any]:
    http: dict[str, Any] = {"type": "http", "url": f"http://{HOST}:{port}{PATH}", "timeout": timeout}
    if token_env:
        http["headers"] = {"Authorization": f"Bearer ${token_env}"}
        http["allowedEnvVars"] = [token_env]
    return {
        "hooks": {
            "SessionStart": [{"hooks": [{"type": "command", "command": ensure_command, "timeout": 20}]}],
            "PreToolUse": [{"matcher": "*", "hooks": [http]}],
            "PostToolUse": [{"matcher": "*", "hooks": [http]}],
            "UserPromptSubmit": [{"hooks": [http]}],
        }
    }
