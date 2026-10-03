"""Preset settings that change behaviour beyond thresholds."""

from guardlayer import GuardLayer


def test_strict_presets_treat_tool_results_as_untrusted():
    # An undeclared tool's output is untrusted under every preset: its name can't establish trust.
    for name, expected in (("balanced", True), ("strict", True), ("airgap", True)):
        session = GuardLayer.from_preset(name).session(f"p-{name}")
        session.scan_tool_result("get_balance", "Balance: 120")
        assert session.state.untrusted is expected, name
