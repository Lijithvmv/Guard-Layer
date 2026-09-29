"""Preset settings that change behaviour beyond thresholds."""

from guardlayer import GuardLayer


def test_strict_presets_treat_tool_results_as_untrusted():
    for name, expected in (("balanced", False), ("strict", True), ("airgap", True)):
        session = GuardLayer.from_preset(name).session(f"p-{name}")
        session.scan_tool_result("get_balance", "Balance: 120")
        assert session.state.untrusted is expected, name
