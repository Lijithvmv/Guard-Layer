"""`[tool.NAME]`: everything about one tool in one place, equivalent to the lower-level sections."""

from __future__ import annotations

import pytest

from guardlayer import Verdict
from guardlayer.config import build_guard, expand_tool_declarations
from guardlayer.labels import Confidentiality

DECLARED = {
    "tool": {
        "read_email": {"capabilities": ["read"], "output": "untrusted", "output_data": "private"},
        "read_docs": {"output": "trusted"},
        "send_email": {
            "capabilities": ["network"],
            "accepts_untrusted": False,
            "max_data": "private",
            "may_send": ["email"],
            "arguments": [{"argument": "to", "allow": ["*@mycompany.com"], "action": "review"}],
            "destinations": [{"argument": "to", "match": "*@mycompany.com", "max_data": "private"}],
        },
        "kb_search": {"capabilities": ["read"], "remote": True},
    }
}
LOW_LEVEL = {
    "tools": {
        "capabilities": {"read_email": ["read"], "send_email": ["network"], "kb_search": ["read"]},
        "arguments": [{"tool": "send_email", "argument": "to", "allow": ["*@mycompany.com"], "action": "review"}],
        "remote_tools": ["kb_search"],
    },
    "session": {"trusted_tools": ["read_docs"], "untrusted_tools": ["read_email"], "allow_egress": {"send_email": ["email"]}},
    "labels": {
        "sources": {"read_email": {"confidentiality": "private"}},
        "sinks": {"send_email": {"accepts_untrusted": False, "max_confidentiality": "private"}},
        "destinations": [{"tool": "send_email", "argument": "to", "match": "*@mycompany.com", "max_confidentiality": "private"}],
    },
}


def test_expands_to_the_lower_level_sections():
    assert expand_tool_declarations(DECLARED) == LOW_LEVEL


def test_declared_and_low_level_configs_behave_the_same():
    for config in (DECLARED, LOW_LEVEL):
        guard = build_guard(config)
        s = guard.session("s")
        s.scan_tool_result("read_email", "Hi, the invoice is attached.")
        assert s.state.untrusted and s.state.label.confidentiality is Confidentiality.PRIVATE
        assert s.scan_tool_call("send_email", {"to": "x@elsewhere.com", "body": "hi"}).verdict >= Verdict.REVIEW
        assert guard.session_policy.is_trusted("read_docs")
        assert guard.tool_policy.is_remote("kb_search")


def test_merges_with_existing_low_level_settings():
    config = {"tool": {"a": {"output": "untrusted"}}, "session": {"untrusted_tools": ["b"], "store": "memory"}}
    assert expand_tool_declarations(config)["session"] == {"untrusted_tools": ["b", "a"], "store": "memory"}


def test_globs_work_as_names():
    guard = build_guard({"tool": {"mcp__github__*": {"output": "untrusted"}}})
    s = guard.session("g")
    s.scan_tool_result("mcp__github__get_issue", "An issue body.")
    assert s.state.untrusted


def test_unknown_key_explains_the_known_ones():
    with pytest.raises(ValueError, match=r"(?s)unknown key\(s\) \['trusted'\].*output:"):
        build_guard({"tool": {"x": {"trusted": True}}})


def test_bad_output_value():
    with pytest.raises(ValueError, match='output must be "trusted" or "untrusted"'):
        build_guard({"tool": {"x": {"output": "private"}}})


def test_no_declarations_leaves_the_config_alone():
    assert expand_tool_declarations({"guard": {"mode": "observe"}}) == {"guard": {"mode": "observe"}}
