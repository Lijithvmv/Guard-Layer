"""The credential broker: the agent calls through GuardLayer and never holds the token."""

from __future__ import annotations

import json
import subprocess
import threading
import urllib.error
import urllib.request

import pytest

from guardlayer.broker import BrokerPolicy, Credentials, git_repos, make_handler
from guardlayer.cli import main

TOKEN = "ghs_brokertest0000000000000000000000000"
CONFIG = {"broker": {"repos": ["acme/app"], "routes": {"github": {
    "upstream": "https://api.github.com", "credential": "env:GL_TEST_TOKEN", "allow": ["GET /repos/{repo}/**"]}}}}


def test_routes_bind_to_requests_not_hosts():
    p = BrokerPolicy.from_config(CONFIG)
    assert p.decide("github", "GET", "repos/acme/app/actions/runs?per_page=5")[0]
    assert p.decide("github", "GET", "repos/ACME/App/actions/jobs/1/logs")[0]  # GitHub names aren't case-sensitive
    for method, path in [("GET", "repos/acme/other/actions/runs"),   # another repository of the same account
                         ("POST", "gists"),                           # publishing: the exfiltration a host binding allows
                         ("DELETE", "repos/acme/app"),                # a write on the bound repository itself
                         ("GET", "repos/acme/app/../other/actions")]:  # traversal
        ok, reason = p.decide("github", method, path)
        assert not ok and "allow-list" in reason or reason == "path traversal", (method, path, reason)
    assert not p.decide("gitlab", "GET", "x")[0]


def test_config_is_validated():
    with pytest.raises(ValueError, match="https"):
        BrokerPolicy.from_config({"broker": {"routes": {"x": {"upstream": "http://a", "credential": "env:A", "allow": []}}}})
    with pytest.raises(ValueError, match="credential"):
        BrokerPolicy.from_config({"broker": {"routes": {"x": {"upstream": "https://a", "credential": "plain", "allow": []}}}})
    with pytest.raises(ValueError, match="METHOD"):
        BrokerPolicy.from_config({"broker": {"routes": {"x": {"upstream": "https://a", "credential": "env:A", "allow": ["/x"]}}}})


class _Upstream:
    """Records what the broker would send to the service; echoes the token back to test scrubbing."""

    def __init__(self):
        self.requests: list[urllib.request.Request] = []

    def __call__(self, req):
        self.requests.append(req)

        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def read(self, n=-1):
                return json.dumps({"seen_auth": req.get_header("Authorization"), "runs": 3}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return Resp()


@pytest.fixture
def broker(monkeypatch, tmp_path):
    from http.server import ThreadingHTTPServer

    monkeypatch.setenv("GL_TEST_TOKEN", TOKEN)
    policy = BrokerPolicy.from_config(CONFIG)
    policy.audit = str(tmp_path / "broker-audit.jsonl")
    upstream, fetched = _Upstream(), []

    class Counting(Credentials):
        def get(self, spec):
            fetched.append(spec)
            return super().get(spec)

    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(policy, Counting(), opener=upstream))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", upstream, fetched, policy
    server.shutdown()


def _call(url, method="GET"):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method=method), timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_the_agent_never_sees_the_token(broker):
    base, upstream, fetched, policy = broker
    status, body = _call(base + "/github/repos/acme/app/actions/runs?per_page=5")
    assert status == 200
    assert upstream.requests[0].full_url == "https://api.github.com/repos/acme/app/actions/runs?per_page=5"
    assert upstream.requests[0].get_header("Authorization") == f"Bearer {TOKEN}"  # added by the broker
    assert TOKEN not in body and "[REDACTED:broker]" in body                       # scrubbed on the way back

    status, body = _call(base + "/github/gists", method="POST")
    assert status == 403 and "allow-list" in json.loads(body)["reason"]
    assert len(upstream.requests) == 1 and fetched == ["env:GL_TEST_TOKEN"]  # a refused request fetches nothing
    log = [json.loads(line) for line in open(policy.audit, encoding="utf-8")]
    assert [e["allowed"] for e in log] == [True, False] and TOKEN not in json.dumps(log)


def test_git_credentials_are_fetched_without_prompting():
    calls = []

    def runner(argv, stdin):
        calls.append((argv, stdin))
        return "protocol=https\nhost=github.com\nusername=x\npassword=" + TOKEN + "\n"

    creds = Credentials(runner=runner)
    assert creds.get("git:github.com") == TOKEN and creds.get("git:github.com") == TOKEN
    assert calls == [(["git", "credential", "fill"], "protocol=https\nhost=github.com\n\n")]  # cached after the first
    with pytest.raises(LookupError):
        Credentials(runner=lambda a, s: "").get("git:github.com")


def test_repositories_come_from_the_working_directorys_remotes(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "remote", "add", "origin", "https://github.com/Acme/App.git"], cwd=tmp_path, check=True)
    subprocess.run(["git", "remote", "add", "fork", "git@github.com:me/app"], cwd=tmp_path, check=True)
    assert git_repos(tmp_path) == ["acme/app", "me/app"]


def test_cli_check(tmp_path, capsys):
    cfg = tmp_path / "g.toml"
    cfg.write_text('[broker]\nrepos = ["acme/app"]\n[broker.routes.github]\nupstream = "https://api.github.com"\n'
                   'credential = "env:X"\nallow = ["GET /repos/{repo}/**"]\n', encoding="utf-8")
    assert main(["--config", str(cfg), "broker", "--check", "GET /github/repos/acme/app/actions/runs"]) == 0
    assert main(["--config", str(cfg), "broker", "--check", "POST /github/gists"]) == 1
    assert "refuse" in capsys.readouterr().out
