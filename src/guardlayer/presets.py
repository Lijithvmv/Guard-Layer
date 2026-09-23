"""Named security postures: a starting config plus an honest statement of what it leaves open.

    guard = GuardLayer.from_preset("strict")
    # or in guardlayer.toml:   preset = "strict"   (your own settings override the preset)
    # or on the CLI:           guardlayer --preset strict scan "..."

| preset     | for                                   | enforcement |
|------------|---------------------------------------|-------------|
| `observe`  | rolling out: measure before you block | nothing — every verdict is a shadow verdict |
| `balanced` | most apps (the default)               | blocks clear attacks, holds risky agent commands for review |
| `strict`   | agents with real credentials or prod access | lower thresholds, fail-closed, every shell/write call reviewed |
| `airgap`   | regulated or offline workloads        | no network or shell tools at all, fail-closed |

No preset makes prompt injection impossible; each lists its residual risk so the choice is explicit.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Preset:
    name: str
    description: str
    residual_risk: tuple[str, ...]
    config: dict[str, Any] = field(default_factory=dict)


PRESETS: dict[str, Preset] = {
    p.name: p
    for p in (
        Preset(
            "observe",
            "Shadow mode: every scanner and tool rule runs and is logged with the verdict it would have produced, "
            "but nothing is blocked, held or redacted. Use it to measure false positives on real traffic first.",
            (
                "Nothing is stopped: attacks, leaks and dangerous tool calls all go through.",
                "Secrets and PII are NOT redacted while observing.",
            ),
            {"guard": {"mode": "observe"}},
        ),
        Preset(
            "balanced",
            "The defaults. Blocks high-confidence attacks, redacts secrets everywhere and PII in outputs, blocks "
            "destructive commands, credential-file access and exfiltration endpoints, and holds risky commands "
            "(force-push, sudo, DROP TABLE, persistence, .env access) for human review. In a session, a secret "
            "seen earlier being sent out is blocked, and actions after untrusted + sensitive reads or an injection need review.",
            (
                "Paraphrased injections that avoid known phrasing can pass (add the classifier or an LLM judge).",
                "Shell and network tools run without review unless a rule matches their arguments.",
                "Taint tracking only works when you pass a session; encoded or split copies of secrets are not matched.",
                "Fail-open: if a scanner errors, the text is still allowed.",
                "Egress to ordinary domains is allowed; only tunnels, capture services and metadata endpoints are blocked.",
            ),
            {},
        ),
        Preset(
            "strict",
            "For agents that hold real credentials or touch production. Lower thresholds, fail-closed, every shell "
            "and write-capable tool call held for review, raw-IP egress and .env access blocked, unknown "
            "suspicious content flagged sooner, and any action after reading an injection blocked.",
            (
                "Review fatigue: approvers see every shell/write call; rubber-stamping defeats the control.",
                "More false positives than 'balanced' (thresholds 0.3 / 0.6).",
                "Egress to ordinary domains is still allowed unless you set tools.egress_allowlist.",
                "Paraphrased injections can still pass the rule-based layers.",
            ),
            {
                "guard": {"flag_threshold": 0.3, "block_threshold": 0.6, "fail_closed": True},
                "tools": {
                    "capability_actions": {"exec": "review", "write": "review"},
                    "rule_actions": {"egress_raw_ip": "block", "dotenv_file": "block", "persistence": "block"},
                },
                "session": {"actions": {"after_injection": "block"}},
            },
        ),
        Preset(
            "airgap",
            "For regulated or offline workloads. Network- and shell-capable tools are blocked outright, writes are "
            "reviewed, any scanner error blocks, thresholds match 'strict', and tainted sessions cannot act.",
            (
                "Agents lose all network and shell access; tasks that need them will fail by design.",
                "Tools mis-tagged as read-only bypass the capability block: tag every tool explicitly in tools.capabilities.",
                "Read-capable tools can still surface sensitive data into the model's context.",
            ),
            {
                "guard": {"flag_threshold": 0.3, "block_threshold": 0.6, "fail_closed": True},
                "tools": {
                    "capability_actions": {"network": "block", "exec": "block", "write": "review"},
                    "rule_actions": {"egress_raw_ip": "block", "dotenv_file": "block", "persistence": "block"},
                },
                "session": {"actions": {"after_injection": "block", "trifecta": "block"}},
            },
        ),
    )
}


def get_preset(name: str) -> Preset:
    try:
        return PRESETS[name]
    except KeyError:
        raise ValueError(f"unknown preset {name!r}; available: {sorted(PRESETS)}") from None


def deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    """Merge nested dicts; values in `override` win, lists are replaced rather than concatenated."""
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out
