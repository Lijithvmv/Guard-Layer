"""MkDocs hook: generate reference tables from the code, so the docs can't drift from it.

Markers replaced in any page:
    <!-- gen:rules -->        content rules and tool-call rules
    <!-- gen:session-rules --> session taint rules and their default actions
    <!-- gen:cli -->          `--help` of every CLI command
    <!-- gen:compliance -->   frameworks, controls and the category/rule mappings
    <!-- gen:presets -->      presets and their residual risk
"""

from __future__ import annotations

import contextlib
import io

from guardlayer import compliance
from guardlayer.cli import main as cli_main
from guardlayer.models import Action
from guardlayer.presets import PRESETS
from guardlayer.rules import DEFAULT_RULES
from guardlayer.session import SessionPolicy
from guardlayer.tools import DEFAULT_TOOL_RULES


def _esc(text: str) -> str:
    return text.replace("|", "\\|")


def _rules() -> str:
    out = ["### Content rules", "", "| Rule | Category | Severity | Directions | What it catches |", "|---|---|---|---|---|"]
    for r in DEFAULT_RULES:
        out.append(f"| `{r.name}` | {r.category} | {r.severity:.2f} | {', '.join(sorted(r.directions))} | {_esc(r.message)} |")
    out += ["", "### Tool-call rules", "", "| Rule | Category | Default action | Applies to | What it catches |", "|---|---|---|---|---|"]
    for t in DEFAULT_TOOL_RULES:
        caps = ", ".join(sorted(t.capabilities)) if t.capabilities else "any tool"
        out.append(f"| `{t.name}` | {t.category} | {Action(t.action).value} | {caps} | {_esc(t.message)} |")
    return "\n".join(out)


def _session_rules() -> str:
    out = ["| Rule | Default action |", "|---|---|"]
    for name, action in SessionPolicy().actions.items():
        out.append(f"| `{name}` | {Action(action).value} |")
    return "\n".join(out)


_COMMANDS = [
    ["--help"], ["scan", "--help"], ["tool-call", "--help"], ["batch", "--help"], ["eval", "--help"], ["canary", "--help"],
    ["audit", "verify", "--help"], ["audit", "keygen", "--help"], ["evidence", "export", "--help"],
    ["evidence", "controls", "--help"], ["hook", "claude-code", "--help"], ["serve", "--help"],
]  # fmt: skip


def _cli() -> str:
    out = []
    for argv in _COMMANDS:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
            cli_main(argv)
        title = "guardlayer " + " ".join(a for a in argv if a != "--help")
        out += [f"### `{title.strip()}`", "", "```text", buf.getvalue().rstrip().replace("usage: ", "usage: ", 1), "```", ""]
    return "\n".join(out)


def _compliance() -> str:
    out = []
    for fw, title in compliance.FRAMEWORKS.items():
        out += [f"### {title}", "", "| Control | Title |", "|---|---|"]
        out += [f"| {c.id} | {c.title} |" for c in compliance.CONTROLS.values() if c.framework == fw]
        out.append("")
    out += ["### Which decisions map to which controls", "",
            "Every audited entry is evidence for: " + ", ".join(f"`{k}`" for k in compliance.BASELINE) + ".",
            "Any detection adds: " + ", ".join(f"`{k}`" for k in compliance.ON_DETECTION) + ".",
            "A REVIEW verdict adds: " + ", ".join(f"`{k}`" for k in compliance.ON_REVIEW) + ".", "",
            "| Category | Controls |", "|---|---|"]  # fmt: skip
    for cat, keys in compliance.CATEGORY_CONTROLS.items():
        out.append(f"| `{cat}` | {', '.join(f'`{k}`' for k in keys) or '(baseline only)'} |")
    out += ["", "| Rule | Extra controls |", "|---|---|"]
    for rule, keys in compliance.RULE_CONTROLS.items():
        out.append(f"| `{rule}` | {', '.join(f'`{k}`' for k in keys)} |")
    out += ["", f"Mapping version `{compliance.MAPPING_VERSION}`. {compliance.DISCLAIMER}"]
    return "\n".join(out)


def _presets() -> str:
    out = []
    for p in PRESETS.values():
        out += [f"### `{p.name}`", "", p.description, "", "Residual risk:", ""]
        out += [f"- {risk}" for risk in p.residual_risk]
        out.append("")
    return "\n".join(out)


_GENERATORS = {
    "<!-- gen:rules -->": _rules,
    "<!-- gen:session-rules -->": _session_rules,
    "<!-- gen:cli -->": _cli,
    "<!-- gen:compliance -->": _compliance,
    "<!-- gen:presets -->": _presets,
}


def on_page_markdown(markdown: str, **_: object) -> str:
    for marker, generate in _GENERATORS.items():
        if marker in markdown:
            markdown = markdown.replace(marker, generate())
    return markdown
