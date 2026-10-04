"""Draft `[tool.NAME]` declarations from what an agent actually did (`guardlayer policy draft`).

Declaring tools is where most of GuardLayer's protection comes from, and the step people skip. This reads audit logs,
finds every tool the agent used and what was seen in its output, and writes a starter config with a reason next to every
suggestion. It is a draft: GuardLayer can only guess from names and from what it saw. The person who knows the tools
has to check each line, especially for MCP servers they didn't write.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from guardlayer.consequence import consequence
from guardlayer.session import HOSTILE_CATEGORIES

if TYPE_CHECKING:  # pragma: no cover
    from guardlayer.pipeline import GuardLayer

_MCP_RE = re.compile(r"^mcp__([^_]+(?:_[^_]+)*?)__")
_ACTING = {"write", "network", "exec"}


@dataclass
class ToolUsage:
    name: str
    calls: int = 0
    results: int = 0
    injections: int = 0  # results with a likely injection
    secrets: int = 0  # results with secrets
    personal: int = 0  # results with personal data
    reviewed_or_blocked: int = 0
    rules: set[str] = field(default_factory=set)


def tool_usage(audit_paths: Iterable[str | Path]) -> dict[str, ToolUsage]:
    """Per tool: calls, results, and what was found in its output, from GuardLayer audit logs."""
    usage: dict[str, ToolUsage] = {}
    for path in audit_paths:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                meta = entry.get("metadata") or {}
                source = str(meta.get("source") or "")
                name = meta.get("tool") if entry.get("direction") == "output" else None
                if name is None and source.startswith("tool:"):
                    name = source[5:]
                if not name:
                    continue
                u = usage.setdefault(name, ToolUsage(name))
                detections = entry.get("detections") or []
                if entry.get("direction") == "output":
                    u.calls += 1
                    if (entry.get("shadow_verdict") or entry.get("verdict")) in ("review", "block"):
                        u.reviewed_or_blocked += 1
                    u.rules |= {d.get("rule", "") for d in detections if d.get("action") in ("review", "block")}
                else:
                    u.results += 1
                    categories = {d.get("category") for d in detections}
                    u.injections += bool(categories & HOSTILE_CATEGORIES)
                    u.secrets += "secret" in categories
                    u.personal += any(d.get("category") == "pii" and d.get("rule") != "ip_address" for d in detections)
    return usage


def mcp_server(name: str) -> str | None:
    match = _MCP_RE.match(name)
    return match.group(1) if match else None


def _key(name: str) -> str:
    return name if re.fullmatch(r"[A-Za-z0-9_-]+", name) else json.dumps(name)


def draft(usage: dict[str, ToolUsage], guard: GuardLayer, *, known: Iterable[str] = (), source: str = "") -> str:
    """A starter TOML config with one table per tool (one per MCP server for trust), each line explained."""
    known = set(known)
    lines = [
        f"# Tool declarations drafted by `guardlayer policy draft`{f' from {source}' if source else ''}.",
        "# Every line is a guess from the tool's name and from what GuardLayer saw in its output. Check each one:",
        "# this is what GuardLayer will believe about your tools. Lines marked CHECK need your judgement most.",
        "# Then: guardlayer --config <this file> policy check",
        "",
    ]
    servers: dict[str, list[ToolUsage]] = {}
    plain: list[ToolUsage] = []
    for u in sorted(usage.values(), key=lambda u: (-(u.calls + u.results), u.name)):
        if u.name in known:
            continue
        server = mcp_server(u.name)
        (servers.setdefault(server, []) if server else plain).append(u)

    for server, tools in sorted(servers.items()):
        seen = [t for t in tools if t.injections]
        lines += [
            f"# ---- MCP server {server!r}: {len(tools)} tool(s) used. Whoever runs this server writes what it returns.",
            "#      If you don't know who that is, remove the server rather than trusting it.",
            f"[tool.{_key(f'mcp__{server}__*')}]",
            'output = "untrusted"                # CHECK: only "trusted" if you or your company write and run this server',
        ]
        if seen:
            lines.append(f"# an injection was seen in the output of {', '.join(t.name for t in seen)}")
        lines.append("")
        for u in tools:
            lines += _tool_table(u, guard, trust=False)

    for u in plain:
        lines += _tool_table(u, guard, trust=True)

    if known:
        lines += ["# Already known to GuardLayer (Claude Code built-ins or your config), not redeclared:",
                  "#   " + ", ".join(sorted(n for n in known if n in usage)), ""]  # fmt: skip
    return "\n".join(lines).rstrip() + "\n"


def _tool_table(u: ToolUsage, guard: GuardLayer, *, trust: bool) -> list[str]:
    caps, tagged = guard.tool_policy.resolve(u.name)
    remote = guard.tool_policy.is_remote(u.name)
    acts = not tagged or bool(caps & _ACTING)
    out = [f"[tool.{_key(u.name)}]                # used {u.calls} time(s), {u.results} result(s) seen"]
    if tagged:
        out.append(f"capabilities = {json.dumps(sorted(caps))}   # inferred from the name: CHECK (what it can do; who writes its output is set below)")
    else:
        out.append('capabilities = ["read", "write", "network", "exec"]   # CHECK: unknown, so assumed able to do anything')
    if remote and tagged and not caps & {"network", "exec"}:
        # Explicit capabilities override the built-in remote patterns (mcp__*, *search*), so say it, or declaring
        # ["read"] would quietly stop treating its arguments as leaving the machine.
        out.append("remote = true                       # its arguments leave the machine (a remote service)")
    if trust:
        if u.injections:
            out.append(f'output = "untrusted"                # an injection was seen in its output {u.injections} time(s)')
        elif remote:
            out.append('output = "untrusted"                # reaches outside the machine, so others can write what it returns')
        else:
            out.append('# output = "trusted"              # CHECK: uncomment only if nobody outside can write what it reads')
    if u.secrets:
        out.append(f'output_data = "restricted"          # secrets were seen in its output {u.secrets} time(s)')
    elif u.personal:
        out.append(f'output_data = "private"             # personal data was seen in its output {u.personal} time(s)')
    if acts:
        out.append("# accepts_untrusted = false        # CHECK: uncomment if content from outside must never drive this tool")
        kind = consequence(u.name, caps, tagged, None, remote=remote)
        why = {"local": "recoverable on this machine", "outbound": "reaches another system",
               "irreversible": "can't be taken back (payments, deletion, publishing, access changes)"}[kind]  # fmt: skip
        out.append(f'consequence = "{kind}"{" " * (14 - len(kind))}# CHECK: guessed from the name: {why}')
    if u.reviewed_or_blocked:
        out.append(f"# held for review or refused {u.reviewed_or_blocked} time(s): {', '.join(sorted(u.rules)) or 'see the audit report'}")
    return [*out, ""]
