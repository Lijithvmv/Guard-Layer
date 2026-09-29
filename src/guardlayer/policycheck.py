"""`guardlayer policy check`: what GuardLayer will assume about each tool, and where the configuration leaves a gap.

Most containment gaps are closable by configuration: marking a tool untrusted, a source private, a sink capped, a
recipient restricted. A new user doesn't know which ones apply to them. This check lists, per tool:

* its **capabilities** (declared, inferred from the name, or unknown),
* its **source label** (is its output trusted or untrusted? public, private or restricted?),
* its **sink policy** (may untrusted content drive it? how sensitive may the data it receives be?),
* how **egress** is limited (allow-list, argument rules),

and warns about the gaps that matter, in plain words. Run it in CI with `--strict` to fail on warnings.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from guardlayer.labels import Confidentiality, Integrity

if TYPE_CHECKING:  # pragma: no cover
    from guardlayer.pipeline import GuardLayer


@dataclass
class ToolReport:
    tool: str
    capabilities: list[str]
    capabilities_from: str  # "declared", "inferred" or "unknown"
    output_integrity: str
    output_confidentiality: str
    accepts_untrusted: bool
    max_confidentiality: str | None
    argument_rules: int
    egress_limited: bool
    reaches_out: bool = True
    warnings: list[str] = field(default_factory=list)


def configured_tools(guard: GuardLayer) -> list[str]:
    """Tool names (not globs) mentioned anywhere in the configuration."""
    sp, tp = guard.session_policy, guard.tool_policy
    names: set[str] = set(tp.capabilities)
    names |= set(sp.sources) | set(sp.sinks) | set(sp.allow_egress) | set(sp.trusted_tools) | set(sp.untrusted_tools)
    names |= {r.tool for r in tp.argument_rules} | {d["tool"] for d in sp.destinations}
    return sorted(n for n in names if not any(ch in n for ch in "*?["))


def check_policy(guard: GuardLayer, tools: Iterable[str]) -> tuple[list[ToolReport], list[str]]:
    """Per-tool reports and global warnings."""
    sp, tp = guard.session_policy, guard.tool_policy
    private_sources = any(Confidentiality(s.get("confidentiality", "public")) > Confidentiality.PUBLIC for s in sp.sources.values())
    reports = []
    for tool in tools:
        caps, tagged = tp.resolve(tool)
        declared = any(fnmatch.fnmatchcase(tool, p) for p in tp.capabilities)
        source = "declared" if declared else "inferred" if tagged else "unknown"
        remote = tp.is_remote(tool)
        reaches_out = (not tagged) or bool(caps & {"network", "exec"})
        untrusted = sp.is_untrusted(tool, can_reach_network=remote)
        label = sp.source_label(tool)
        confidentiality = label.confidentiality.value if label else "public (detections can raise it)"
        accepts, cap = sp.sink(tool)
        arg_rules = sum(1 for r in tp.argument_rules if fnmatch.fnmatchcase(tool, r.tool))
        egress_limited = tp.egress_allowlist is not None or arg_rules > 0
        warnings = []
        if source == "unknown":
            warnings.append("capabilities unknown: treated as able to do anything (read, write, network, exec); declare them "
                            "in [tools] capabilities")  # fmt: skip
        if reaches_out and not egress_limited:
            warnings.append("can send data anywhere: no egress allow-list and no argument rule limits where it sends")
        if not untrusted and not sp.is_trusted(tool) and ("read" in caps or not tagged) and label is None:
            warnings.append("its output is assumed trusted: confirm outsiders can't write this data, or declare it "
                            "untrusted (or set default_integrity = \"untrusted\")")  # fmt: skip
        if reaches_out and cap is None and private_sources:
            warnings.append("private data is declared elsewhere but this tool has no max_confidentiality: it could carry it out")
        if sp.is_trusted(tool) and remote:
            warnings.append("marked trusted but can reach the network or runs remotely: its output will never count as untrusted")
        reports.append(ToolReport(tool, sorted(caps) or ["(any)"], source,
                                  Integrity.UNTRUSTED.value if untrusted else Integrity.TRUSTED.value, confidentiality,
                                  accepts, cap.value if cap else None, arg_rules, egress_limited, reaches_out, warnings))  # fmt: skip
    global_warnings = []
    if not guard.policy.fail_closed:
        global_warnings.append("fails open: if a scanner errors, traffic passes (set [guard] fail_closed = true, or use the strict preset)")
    if sp.default_integrity == "trusted":
        global_warnings.append("default_integrity = \"trusted\": undeclared local tools' output is trusted; consider \"untrusted\"")
    if not sp.enabled:
        global_warnings.append("session rules are disabled: no taint, label or file-label protection")
    return reports, global_warnings


def format_report(reports: list[ToolReport], global_warnings: list[str]) -> str:
    lines = []
    for r in reports:
        sink = []
        if not r.accepts_untrusted:
            sink.append("refuses untrusted context")
        if r.max_confidentiality:
            sink.append(f"accepts at most {r.max_confidentiality} data")
        lines.append(f"{r.tool}")
        lines.append(f"  capabilities  {', '.join(r.capabilities)} ({r.capabilities_from})")
        lines.append(f"  output        {r.output_integrity}, {r.output_confidentiality}")
        lines.append(f"  as a sink     {'; '.join(sink) or 'no restrictions beyond the session rules'}")
        egress = ("limited" if r.egress_limited else "not limited") if r.reaches_out else "n/a (can't send data out)"
        lines.append(f"  egress        {egress}{f' ({r.argument_rules} argument rule(s))' if r.argument_rules else ''}")
        lines += [f"  ! {w}" for w in r.warnings]
    if global_warnings:
        lines += ["", "Configuration:"] + [f"  ! {w}" for w in global_warnings]
    count = sum(len(r.warnings) for r in reports) + len(global_warnings)
    lines += ["", f"{count} warning(s)" if count else "No warnings."]
    return "\n".join(lines)


def to_json(reports: list[ToolReport], global_warnings: list[str]) -> dict[str, Any]:
    return {"tools": [asdict(r) for r in reports], "warnings": global_warnings}
