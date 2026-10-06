"""`guardlayer policy check`: per-tool assumptions and configuration gaps."""

import json

from guardlayer.cli import main
from guardlayer.config import build_guard
from guardlayer.policycheck import check_policy, configured_tools

GOOD = {
    "guard": {"fail_closed": True},
    "tools": {"egress_allowlist": ["api.mycompany.com"],
              "capabilities": {"send_email": ["network"], "get_customer": ["read"], "read_file": ["read"]},
              "arguments": [{"tool": "send_email", "argument": "to", "allow": ["*@mycompany.com"]}]},
    "labels": {"default_integrity": "untrusted",
               "sources": {"get_customer": {"integrity": "trusted", "confidentiality": "private"}},
               "sinks": {"send_email": {"max_confidentiality": "private"}}},
}  # fmt: skip


def _warnings(config, tools):
    reports, global_warnings = check_policy(build_guard(config), tools)
    return {r.tool: r.warnings for r in reports}, global_warnings


def test_default_configuration_warns_about_each_gap():
    per_tool, global_warnings = _warnings(None, ["send_email", "read_file", "mystery_tool"])
    assert any("send data anywhere" in w for w in per_tool["send_email"])
    assert not any("assumed trusted" in w for w in per_tool["read_file"])  # undeclared: untrusted by default now
    assert any("capabilities unknown" in w for w in per_tool["mystery_tool"])
    assert any("fails open" in w for w in global_warnings) and not any("default_integrity" in w for w in global_warnings)


def test_well_configured_policy_is_clean():
    per_tool, global_warnings = _warnings(GOOD, ["send_email", "get_customer", "read_file"])
    assert per_tool == {"send_email": [], "get_customer": [], "read_file": []} and global_warnings == []


def test_private_sources_need_capped_sinks():
    config = {**GOOD, "labels": {**GOOD["labels"], "sinks": {}}}
    per_tool, _ = _warnings(config, ["send_email"])
    assert any("max_confidentiality" in w for w in per_tool["send_email"])


def test_trusted_network_tool_is_flagged():
    per_tool, _ = _warnings({"session": {"trusted_tools": ["fetch"]}}, ["fetch"])
    assert any("marked trusted" in w for w in per_tool["fetch"])


def test_configured_tools_skip_globs():
    guard = build_guard({"labels": {"sources": {"get_customer": {"confidentiality": "private"}, "mcp__*": {"integrity": "untrusted"}}}})
    assert configured_tools(guard) == ["get_customer"]


def test_cli(tmp_path, capsys):
    cfg = tmp_path / "g.json"
    cfg.write_text(json.dumps(GOOD))
    assert main(["--config", str(cfg), "policy", "check", "--strict"]) == 0  # tools from the config, all clean
    assert "No warnings." in capsys.readouterr().out
    assert main(["policy", "check", "--tools", "send_email", "--strict"]) == 1
    capsys.readouterr()
    assert main(["policy", "check", "--tools", "send_email", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["tools"][0]["tool"] == "send_email" and data["tools"][0]["warnings"] and data["warnings"]
    assert main(["policy", "check", "--claude-code"]) == 0
    out = capsys.readouterr().out
    assert "Bash" in out and "WebFetch" in out
    assert main(["policy", "check"]) == 2  # nothing to check
