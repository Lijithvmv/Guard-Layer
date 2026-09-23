"""Agent tool-call policy: decide what an agent may *do*, not just what text says.

Content scanners look at words. An agent turns words into actions, so a tool call also
needs a policy over the action itself:

* **capabilities** — every tool is tagged `read`, `write`, `network` and/or `exec`, either
  explicitly (`capabilities={"run_sql": ["write"]}`, glob patterns allowed) or inferred from
  its name (`bash` → exec, `http_get` → network + read). Actions can be attached to a
  capability, e.g. `capability_actions={"exec": "review"}` holds every shell call for a human;
* **allow/deny lists** of tool names (glob patterns);
* **argument rules** — built-in and custom regex rules over the call's arguments, scoped
  by capability: destructive and risky shell commands, persistence, credential files;
* **egress control** — every destination in a network or exec call is checked for cloud
  metadata endpoints, tunnel and request-capture services, raw public IPs, and (optionally)
  a domain allow-list.

Untagged tools (no explicit or inferred capability) are treated as able to do anything,
so every rule applies to them. `ToolPolicy.evaluate` returns `Detection`s that carry
their own `action`, so a rule can force BLOCK or REVIEW regardless of the score.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from guardlayer.models import Action, Category, Detection

SCANNER = "tool_policy"
CAPABILITIES = ("read", "write", "network", "exec")

_NAME_HINTS: dict[str, frozenset[str]] = {
    "exec": frozenset(
        "shell bash sh zsh fish terminal exec execute command cmd powershell pwsh subprocess interpreter eval repl".split()
    ),
    "network": frozenset(
        "http https fetch request requests curl wget url web browse browser download upload api webhook email mail send post slack sms".split()
    ),
    "write": frozenset(
        "write save create delete remove rm edit update move rename put patch insert drop append mkdir commit push deploy".split()
    ),
    "read": frozenset("read get list search query find open cat view lookup ls load retrieve".split()),
}


def infer_capabilities(tool_name: str) -> frozenset[str]:
    """Guess a tool's capabilities from its name (`runShellCommand` → exec, `http_get` → network + read)."""
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", tool_name).lower()
    tokens = set(re.split(r"[^a-z0-9]+", words)) - {""}
    return frozenset(cap for cap, hints in _NAME_HINTS.items() if tokens & hints)


# ---------------------------------------------------------------------------------------- rules
@dataclass(frozen=True)
class ToolRule:
    """A rule over tool calls.

    Fires when the tool matches `tools` (glob patterns; None = any tool), the tool has one of
    `capabilities` (None = any; untagged tools always match), and `pattern` (a regex over the
    call's argument text; None = always) is found.
    """

    name: str
    action: Action | str = Action.BLOCK
    pattern: str | None = None
    tools: tuple[str, ...] | None = None
    capabilities: frozenset[str] | None = None
    category: str = Category.TOOL_MISUSE.value
    severity: float = 0.9
    message: str = ""
    flags: int = re.IGNORECASE
    _regex: re.Pattern[str] | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", Action(self.action))
        if self.tools is not None:
            object.__setattr__(self, "tools", tuple(self.tools))
        if self.capabilities is not None:
            caps = frozenset(self.capabilities)
            unknown = caps - set(CAPABILITIES)
            if unknown:
                raise ValueError(f"rule {self.name!r}: unknown capabilities {sorted(unknown)}; use {CAPABILITIES}")
            object.__setattr__(self, "capabilities", caps)
        if self.pattern is not None:
            object.__setattr__(self, "_regex", re.compile(self.pattern, self.flags))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ToolRule:
        data = dict(data)
        for key in ("tools", "capabilities"):
            if isinstance(data.get(key), str):
                data[key] = [data[key]]
        if data.get("capabilities") is not None:
            data["capabilities"] = frozenset(data["capabilities"])
        return cls(**data)

    def applies_to(self, tool: str, caps: frozenset[str], tagged: bool = True) -> bool:
        if self.tools is not None and not any(fnmatch.fnmatchcase(tool, p) for p in self.tools):
            return False
        return self.capabilities is None or not tagged or bool(caps & self.capabilities)

    def match(self, text: str) -> re.Match[str] | None | bool:
        return True if self._regex is None else self._regex.search(text)


_EXEC = frozenset({"exec"})
_WRITE_EXEC = frozenset({"write", "exec"})
_STOP = r"(?=\s|$|[;&|'\"])"

DEFAULT_TOOL_RULES: tuple[ToolRule, ...] = (
    ToolRule(
        "destructive_command",
        Action.BLOCK,
        r"\brm(?=[^;&|\n]*\s-{1,2}[a-z-]*r)\s+[^;&|\n]*?\s(?:/|/\*|~/?|\$HOME/?|\*|\.)" + _STOP
        + r"|\bmkfs(\.\w+)?\s|\bdd\b[^\n]*\bof=/dev/(sd|hd|nvme|xvd|disk|mmcblk)|>\s*/dev/(sd|nvme)[a-z0-9]*\b"
        + r"|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\bformat(\.com)?\s+[a-z]:"
        + r"|\b(rd|rmdir)\s+/s\s+/q\s+[a-z]:\\?" + _STOP + r"|\bRemove-Item\b[^\n]*-Recurse[^\n]*\s[a-z]:\\?" + _STOP
        + r"|\bchmod\s+-R\s+0?777\s+/" + _STOP,
        capabilities=_EXEC,
        severity=1.0,
        message="Destructive command (recursive delete of a root/home directory, disk wipe or fork bomb).",
    ),
    ToolRule(
        "risky_command",
        Action.REVIEW,
        r"\bgit\s+push\b[^;&|\n]*\s(--force(-with-lease)?|-f)\b|\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f)"
        r"|\b(drop\s+(database|schema|table)|truncate\s+table)\b|\bdelete\s+from\s+\w+\s*(;|$)"
        r"|(^|[;&|]\s*|\s)(sudo|doas|runas)\s|\bsu\s+-|\bchmod\s+[ug]?\+s\b"
        r"|\b(shutdown|reboot|halt|poweroff)\b|\bkill(all)?\s+-9\b|\bStop-Computer\b|\bRestart-Computer\b"
        r"|\b(npm|yarn|pnpm)\s+publish\b|\btwine\s+upload\b|\bterraform\s+(apply|destroy)\b[^;&|\n]*-auto-approve",
        capabilities=_EXEC,
        severity=0.7,
        message="Risky command (history rewrite, data deletion, privilege escalation, publishing or shutdown).",
    ),
    ToolRule(
        "persistence",
        Action.REVIEW,
        r"\bcrontab\b|(^|[/\\\s\"'])\.(bashrc|bash_profile|zshrc|profile)\b|/etc/(systemd|init\.d|cron)|\bsystemctl\s+enable\b"
        r"|LaunchAgents|LaunchDaemons|CurrentVersion\\Run|\bschtasks\b[^\n]*/create|\bNew-ScheduledTask|\bRegister-ScheduledTask",
        capabilities=_WRITE_EXEC,
        severity=0.7,
        message="Persistence mechanism (startup files, cron, services or scheduled tasks).",
    ),
    ToolRule(
        "credential_file",
        Action.BLOCK,
        r"\.ssh[/\\](id_[a-z0-9]+|authorized_keys|config)\b|\bid_(rsa|dsa|ecdsa|ed25519)\b|\.aws[/\\](credentials|config)\b"
        r"|\.azure[/\\]|\.config[/\\]gcloud\b|\.kube[/\\]config\b|\.docker[/\\]config\.json|\.git-credentials\b|(^|[/\\\s\"'])\.netrc\b"
        r"|(^|[/\\\s\"'])\.(npmrc|pypirc)\b|\.gnupg[/\\]|\.password-store\b|\.vault-token\b|\.terraform\.d[/\\]credentials"
        r"|/etc/(shadow|gshadow|sudoers)\b|\\config\\(SAM|SECURITY|SYSTEM)\b|\bwallet\.dat\b|\bLogin Data\b|\bkeychain(-db)?\b",
        severity=0.95,
        message="Access to a credential store (SSH keys, cloud credentials, password stores or system secrets).",
    ),
    ToolRule(
        "dotenv_file",
        Action.REVIEW,
        r"(^|[/\\\s\"'=@])\.env(\.(?!example\b|sample\b|template\b|dist\b)[a-z0-9_-]+)?" + _STOP,
        severity=0.6,
        message="Access to a .env file, which usually holds secrets.",
    ),
)

# Services built to receive data from the outside: tunnels, request catchers, out-of-band
# interaction servers and anonymous file drops. Legitimate agent tasks rarely need them.
EXFIL_SERVICES: frozenset[str] = frozenset(
    """
    ngrok.io ngrok.app ngrok-free.app ngrok.dev trycloudflare.com loca.lt localtunnel.me serveo.net localhost.run
    pinggy.io bore.pub pipedream.net webhook.site requestbin.com requestbin.net beeceptor.com hookbin.com
    requestcatcher.com interact.sh oast.fun oast.pro oast.live oast.site oast.online oast.me oastify.com
    burpcollaborator.net canarytokens.com dnslog.cn ceye.io transfer.sh file.io 0x0.st temp.sh paste.ee
    """.split()
)
METADATA_HOSTS: frozenset[str] = frozenset(
    {"169.254.169.254", "169.254.170.2", "metadata.google.internal", "metadata", "100.100.100.200", "fd00:ec2::254"}
)

_URL_RE = re.compile(r"\b(?:https?|wss?|ftps?)://[^\s\"'<>`\\]+", re.IGNORECASE)
_NET_CMD_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|ftp|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|nslookup|dig|ping)\b"
    r"((?:\s+-{1,2}[\w-]+(?:[= ](?!-)[^\s-][^\s]*)?)*)\s+([^\s;&|<>'\"`]+)",
    re.IGNORECASE,
)


def _host(target: str) -> str | None:
    """Extract a host from a URL or a `user@host:port/path` command target."""
    if "://" in target:
        try:
            host = urlsplit(target).hostname
        except ValueError:
            return None
        return host.lower().rstrip(".") if host else None
    target = target.split("@", 1)[-1]
    if target.startswith("["):  # [ipv6]:port
        return target[1:].split("]", 1)[0].lower()
    host = target.split("/", 1)[0].split(":", 1)[0].lower().rstrip(".")
    return host if host and ("." in host or host in METADATA_HOSTS) else None


def extract_hosts(text: str) -> list[str]:
    """Destinations named in tool-call arguments: URL hosts and targets of network commands."""
    hosts: list[str] = []
    for m in _URL_RE.finditer(text):
        h = _host(m.group(0).rstrip(").,;]}"))
        if h:
            hosts.append(h)
    for m in _NET_CMD_RE.finditer(text):
        h = _host(m.group(2))
        if h:
            hosts.append(h)
    return list(dict.fromkeys(hosts))


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _domain_match(host: str, domains: Iterable[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def flatten_arguments(arguments: Mapping[str, Any] | str | None) -> str:
    """All string leaves of the arguments (keys excluded), newline-joined, so rules see raw commands."""
    if arguments is None:
        return ""
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except (ValueError, TypeError):
            return arguments
        if isinstance(arguments, str):
            return arguments
    parts: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            for v in value.values():
                walk(v)
        elif isinstance(value, (list, tuple, set)):
            for v in value:
                walk(v)
        elif value is not None:
            parts.append(str(value))

    walk(arguments)
    return "\n".join(parts)


# --------------------------------------------------------------------------------------- policy
class ToolPolicy:
    """Evaluate a proposed tool call against allow/deny lists, capability actions, argument rules and egress rules."""

    def __init__(
        self,
        *,
        allowlist: Iterable[str] | None = None,
        denylist: Iterable[str] = (),
        capabilities: Mapping[str, Iterable[str]] | None = None,
        capability_actions: Mapping[str, Action | str] | None = None,
        rules: Iterable[ToolRule | Mapping[str, Any]] = (),
        include_default_rules: bool = True,
        disabled_rules: Iterable[str] = (),
        rule_actions: Mapping[str, Action | str] | None = None,
        egress_allowlist: Iterable[str] | None = None,
        block_exfil_services: bool = True,
        flag_raw_ips: bool = True,
        infer: bool = True,
    ) -> None:
        self.allowlist = set(allowlist) if allowlist is not None else None
        self.denylist = set(denylist)
        self.capabilities = {k: frozenset(v) for k, v in (capabilities or {}).items()}
        for tool, caps in self.capabilities.items():
            unknown = caps - set(CAPABILITIES)
            if unknown:
                raise ValueError(f"tool {tool!r}: unknown capabilities {sorted(unknown)}; use {CAPABILITIES}")
        self.capability_actions = {k: Action(v) for k, v in (capability_actions or {}).items()}
        unknown = set(self.capability_actions) - set(CAPABILITIES)
        if unknown:
            raise ValueError(f"capability_actions: unknown capabilities {sorted(unknown)}; use {CAPABILITIES}")
        disabled = set(disabled_rules)
        custom = [r if isinstance(r, ToolRule) else ToolRule.from_dict(r) for r in rules]
        self.rules: list[ToolRule] = [r for r in (*(DEFAULT_TOOL_RULES if include_default_rules else ()), *custom) if r.name not in disabled]
        self.rule_actions = {k: Action(v) for k, v in (rule_actions or {}).items()}
        self.egress_allowlist = {d.lower().lstrip(".") for d in egress_allowlist} if egress_allowlist is not None else None
        self.block_exfil_services = block_exfil_services
        self.flag_raw_ips = flag_raw_ips
        self.infer = infer

    def resolve(self, tool: str) -> tuple[frozenset[str], bool]:
        """(capabilities, tagged). An explicit empty list tags a tool as harmless; untagged tools match every rule."""
        if tool in self.capabilities:
            return self.capabilities[tool], True
        for pattern, caps in self.capabilities.items():
            if fnmatch.fnmatchcase(tool, pattern):
                return caps, True
        caps = infer_capabilities(tool) if self.infer else frozenset()
        return caps, bool(caps)

    def capabilities_of(self, tool: str) -> frozenset[str]:
        return self.resolve(tool)[0]

    def can_act(self, tool: str) -> bool:
        """True if the tool may have side effects or reach the network (anything beyond reading)."""
        caps, tagged = self.resolve(tool)
        return not tagged or bool(caps - {"read"})

    def _detection(self, rule: str, category: str, severity: float, message: str, action: Action, **metadata: Any) -> Detection:
        final = self.rule_actions.get(rule, action)
        return Detection(SCANNER, rule, category, severity, message, metadata=metadata, action=final.value)

    def evaluate(self, tool: str, arguments: Mapping[str, Any] | str | None = None) -> list[Detection]:
        caps, tagged = self.resolve(tool)
        out: list[Detection] = []

        if any(fnmatch.fnmatchcase(tool, p) for p in self.denylist):
            out.append(self._detection("tool_denied", Category.POLICY.value, 1.0, f"Tool {tool!r} is on the deny-list.", Action.BLOCK, tool=tool))
        if self.allowlist is not None and not any(fnmatch.fnmatchcase(tool, p) for p in self.allowlist):
            # No explicit action: scored at 1.0, so it blocks by default and `[actions] policy = ...` can soften it.
            det = Detection(SCANNER, "tool_not_allowed", Category.POLICY.value, 1.0, f"Tool {tool!r} is not in the allow-list.", metadata={"tool": tool})
            if "tool_not_allowed" in self.rule_actions:
                det = self._detection("tool_not_allowed", Category.POLICY.value, 1.0, det.message, Action.BLOCK, tool=tool)
            out.append(det)

        for cap in sorted(caps):
            action = self.capability_actions.get(cap)
            if action is not None:
                out.append(
                    self._detection(f"capability_{cap}", Category.POLICY.value, 0.5, f"Tool {tool!r} has the {cap!r} capability.", action, tool=tool)
                )

        text = flatten_arguments(arguments)
        if not text:
            return out

        for rule in self.rules:
            if not rule.applies_to(tool, caps, tagged):
                continue
            m = rule.match(text)
            if not m:
                continue
            matched = m.group(0)[:200] if isinstance(m, re.Match) else None
            out.append(
                self._detection(rule.name, rule.category, rule.severity, rule.message or f"Tool rule {rule.name!r} matched.", rule.action, tool=tool, matched=matched)  # type: ignore[arg-type]
            )

        if not tagged or caps & {"network", "exec"}:
            out.extend(self._egress(tool, text))
        return out

    def _egress(self, tool: str, text: str) -> list[Detection]:
        out: list[Detection] = []
        for host in extract_hosts(text):
            ip = _ip(host)
            if host in METADATA_HOSTS or (ip is not None and ip.is_link_local):
                out.append(
                    self._detection("egress_metadata_endpoint", Category.EGRESS.value, 1.0, f"Request to a cloud metadata / link-local endpoint ({host}).", Action.BLOCK, tool=tool, host=host)
                )
                continue
            if self.block_exfil_services and _domain_match(host, EXFIL_SERVICES):
                out.append(
                    self._detection("egress_exfil_service", Category.EGRESS.value, 0.95, f"Request to a tunnel or data-capture service ({host}).", Action.BLOCK, tool=tool, host=host)
                )
                continue
            if self.egress_allowlist is not None and not _domain_match(host, self.egress_allowlist):
                if ip is None or not (ip.is_private or ip.is_loopback):
                    out.append(
                        self._detection("egress_not_allowed", Category.EGRESS.value, 0.9, f"Destination {host} is not in the egress allow-list.", Action.BLOCK, tool=tool, host=host)
                    )
                    continue
            if self.flag_raw_ips and ip is not None and ip.is_global:
                out.append(
                    self._detection("egress_raw_ip", Category.EGRESS.value, 0.6, f"Request to a raw public IP address ({host}).", Action.FLAG, tool=tool, host=host)
                )
        return out
