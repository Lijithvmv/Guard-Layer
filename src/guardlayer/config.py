"""Declarative configuration: build a guard from a TOML/JSON file, a dict, or environment variables.

Example `guardlayer.toml`:

    preset = "balanced"            # observe | balanced | strict | airgap — the settings below override it

    [guard]
    flag_threshold = 0.4
    block_threshold = 0.8
    fail_closed = false
    auto_learn = true
    mode = "enforce"               # or "observe": log what would happen, enforce nothing
    observe = ["egress_raw_ip"]    # only observe these rules/categories (globs), even in enforce mode
    enforce = []                   # keep enforcing these in observe mode

    [actions]                      # category or "direction:category" -> score|block|flag|review|redact|log
    secret = "redact"
    "output:pii" = "redact"
    policy = "block"

    [tools]                        # agent tool-call policy (see guardlayer.tools)
    allowlist = ["search", "bash", "mcp__github__*"]
    denylist = ["delete_repo"]
    egress_allowlist = ["api.github.com"]
    remote_tools = ["kb_*"]         # + defaults (mcp__*, *search*, ...): results untrusted, args leave the machine
    capabilities = { run_sql = ["write"], lookup = ["read"] }
    capability_actions = { exec = "review" }
    rule_actions = { egress_raw_ip = "block" }
    disabled_rules = []
    rules = [{ name = "no_prod", pattern = "prod-db", action = "block" }]

    [session]                      # taint tracking across a conversation (see guardlayer.session)
    actions = { trifecta = "review", after_injection = "review", sensitive_data_egress = "block" }
    trusted_tools = ["read_docs"]  # results never count as untrusted or hostile
    untrusted_tools = ["read_email"]
    store = "memory"               # or "file" with dir = "..." (one process per check, e.g. hooks)

    [audit]                        # tamper-evident JSONL audit log
    path = "guardlayer-audit.jsonl"
    min_verdict = "flag"
    signing_key = "audit.key"      # optional Ed25519 PEM (needs the `signing` extra)

    [scanners.heuristics]
    disabled_rules = ["fake_role_header"]
    rules_file = "my_rules.toml"

    [scanners.similarity]
    threshold = 0.55               # ngram embedder; semantic embedders need their own tuning
    corpus_file = "attacks.txt"

    [scanners.pii]
    entities = ["email", "credit_card", "aadhaar"]

    [scanners.links]
    allowed_domains = ["example.com"]

    [scanners.denylist]
    terms = ["project nightingale"]

    [scanners.classifier]          # optional, needs the `ml` extra
    threshold = 0.8

Every scanner section accepts `enabled` and `directions`. The default ensemble is on unless
disabled; the opt-in scanners (`denylist`, `classifier`, `relevance`) switch on when their
section is present. Environment variables override the file: GUARDLAYER_PRESET,
GUARDLAYER_MODE, GUARDLAYER_FLAG_THRESHOLD, GUARDLAYER_BLOCK_THRESHOLD, GUARDLAYER_FAIL_CLOSED,
GUARDLAYER_AUTO_LEARN.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from guardlayer.audit import AuditLogger
from guardlayer.canary import CanaryManager
from guardlayer.models import Action, Verdict
from guardlayer.pipeline import DEFAULT_ACTIONS, GuardLayer, Policy
from guardlayer.presets import deep_merge, get_preset
from guardlayer.scanners.base import Scanner
from guardlayer.scanners.heuristics import HeuristicScanner
from guardlayer.scanners.leakage import CanaryScanner, PromptLeakScanner
from guardlayer.scanners.links import LinkScanner
from guardlayer.scanners.ml import ClassifierScanner
from guardlayer.scanners.obfuscation import ObfuscationScanner
from guardlayer.scanners.pii import PIIScanner
from guardlayer.scanners.policy import DenyListScanner, LimitsScanner
from guardlayer.scanners.relevance import RelevanceScanner
from guardlayer.scanners.secrets import SecretsScanner
from guardlayer.scanners.similarity import SimilarityScanner
from guardlayer.session import FileSessionStore, MemorySessionStore, SessionPolicy, SessionStore
from guardlayer.tools import ToolPolicy
from guardlayer.vectorstore import Embedder, NgramEmbedder, SentenceTransformerEmbedder

ENV_PREFIX = "GUARDLAYER_"


def load_toml(path: str | Path) -> dict[str, Any]:
    if sys.version_info >= (3, 11):
        import tomllib
    else:  # pragma: no cover - Python 3.10
        try:
            import tomli as tomllib
        except ModuleNotFoundError as exc:
            raise ModuleNotFoundError("Reading TOML on Python 3.10 needs: pip install tomli (or use a JSON config)") from exc
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def load_config(source: str | Path | Mapping[str, Any] | None) -> dict[str, Any]:
    if source is None:
        return {}
    if isinstance(source, Mapping):
        return dict(source)
    path = Path(source)
    if path.suffix == ".toml":
        return load_toml(path)
    return json.loads(path.read_text(encoding="utf-8"))


def _embedder(spec: str | None) -> Embedder:
    if not spec or spec == "ngram":
        return NgramEmbedder()
    if spec.startswith(("st:", "sentence-transformers:")):
        return SentenceTransformerEmbedder(spec.split(":", 1)[1])
    raise ValueError(f"unknown embedder {spec!r}; use 'ngram' or 'st:<model-name>'")


def _resolve(base: Path | None, value: Any) -> Any:
    if value and base and not Path(value).is_absolute():
        return str(base / value)
    return value


# name -> (enabled by default, factory(options, canaries, base_dir))
_Factory = Callable[[dict[str, Any], CanaryManager, "Path | None"], Scanner]
SCANNER_REGISTRY: dict[str, tuple[bool, _Factory]] = {
    "heuristics": (True, lambda o, c, b: HeuristicScanner(**{**o, "rules_file": _resolve(b, o.get("rules_file"))})),
    "obfuscation": (True, lambda o, c, b: ObfuscationScanner(**o)),
    "similarity": (
        True,
        lambda o, c, b: SimilarityScanner(
            embedder=_embedder(o.pop("embedder", None)), **{**o, "corpus_file": _resolve(b, o.get("corpus_file"))}
        ),
    ),
    "secrets": (True, lambda o, c, b: SecretsScanner(**o)),
    "pii": (True, lambda o, c, b: PIIScanner(**o)),
    "limits": (True, lambda o, c, b: LimitsScanner(**o)),
    "canary": (True, lambda o, c, b: CanaryScanner(c, **o)),
    "prompt_leak": (True, lambda o, c, b: PromptLeakScanner(**o)),
    "links": (True, lambda o, c, b: LinkScanner(**o)),
    "denylist": (False, lambda o, c, b: DenyListScanner(**o)),
    "classifier": (False, lambda o, c, b: ClassifierScanner(**o)),
    "relevance": (False, lambda o, c, b: RelevanceScanner(_embedder(o.pop("embedder", "st:sentence-transformers/all-MiniLM-L6-v2")), **o)),
}


def _env_overrides(guard_cfg: dict[str, Any]) -> dict[str, Any]:
    out = dict(guard_cfg)
    for key, cast in (("flag_threshold", float), ("block_threshold", float), ("fail_closed", _bool), ("auto_learn", _bool), ("mode", str)):
        raw = os.environ.get(ENV_PREFIX + key.upper())
        if raw is not None:
            out[key] = cast(raw)
    return out


def _bool(raw: str | bool) -> bool:
    return raw if isinstance(raw, bool) else raw.strip().lower() in {"1", "true", "yes", "on"}


def build_guard(source: str | Path | Mapping[str, Any] | None = None) -> GuardLayer:
    """Construct a `GuardLayer` from a config file/dict (None = defaults + env overrides)."""
    config = load_config(source)
    base_dir = Path(source).parent if isinstance(source, (str, Path)) else None
    preset = os.environ.get(ENV_PREFIX + "PRESET") or config.get("preset") or config.get("guard", {}).get("preset")
    if preset:
        config = deep_merge(get_preset(preset).config, config)
    guard_cfg = _env_overrides(config.get("guard", {}))

    actions = dict(DEFAULT_ACTIONS)
    actions.update({k: Action(v) for k, v in config.get("actions", {}).items()})
    policy = Policy(
        flag_threshold=float(guard_cfg.get("flag_threshold", 0.4)),
        block_threshold=float(guard_cfg.get("block_threshold", 0.8)),
        actions=actions,
        fail_closed=_bool(guard_cfg.get("fail_closed", False)),
        redaction_format=guard_cfg.get("redaction_format", "[REDACTED:{rule}]"),
        mode=guard_cfg.get("mode", "enforce"),
        observe=list(guard_cfg.get("observe", [])),
        enforce=list(guard_cfg.get("enforce", [])),
    )

    canaries = CanaryManager(prefix=guard_cfg.get("canary_prefix", "gl"))
    scanner_cfg: dict[str, Any] = config.get("scanners", {})
    unknown = set(scanner_cfg) - set(SCANNER_REGISTRY)
    if unknown:
        raise ValueError(f"unknown scanner(s) in config: {sorted(unknown)}; available: {sorted(SCANNER_REGISTRY)}")

    scanners: list[Scanner] = []
    for name, (enabled_by_default, factory) in SCANNER_REGISTRY.items():
        options = dict(scanner_cfg.get(name, {}))
        # Opt-in scanners switch on as soon as their section appears.
        if not _bool(options.pop("enabled", enabled_by_default or name in scanner_cfg)):
            continue
        scanners.append(factory(options, canaries, base_dir))

    session_policy, session_store = _session(config.get("session", {}), base_dir)
    guard = GuardLayer(
        scanners,
        policy=policy,
        canaries=canaries,
        auto_learn=_bool(guard_cfg.get("auto_learn", False)),
        tool_policy=_tool_policy(config.get("tools", {}), guard_cfg, base_dir),
        session_policy=session_policy,
        sessions=session_store,
    )
    guard.preset = preset
    audit_cfg = config.get("audit")
    if audit_cfg:
        guard.add_hook(_audit_logger(audit_cfg, base_dir))
    return guard


def _tool_policy(tools_cfg: Mapping[str, Any], guard_cfg: Mapping[str, Any], base_dir: Path | None) -> ToolPolicy:
    options = dict(tools_cfg)
    allowlist = options.pop("allowlist", guard_cfg.get("tool_allowlist"))  # [guard] tool_allowlist: pre-0.3 location
    rules = list(options.pop("rules", []))
    rules_file = options.pop("rules_file", None)
    if rules_file:
        rules.extend(load_config(_resolve(base_dir, rules_file)).get("rules", []))
    try:
        return ToolPolicy(allowlist=allowlist, rules=rules, **options)
    except TypeError as exc:
        raise ValueError(f"invalid [tools] config: {exc}") from exc


def _session(session_cfg: Mapping[str, Any], base_dir: Path | None) -> tuple[SessionPolicy, SessionStore | None]:
    options = dict(session_cfg)
    store_kind = options.pop("store", "memory")
    directory = options.pop("dir", None)
    ttl = options.pop("ttl_seconds", None)
    max_sessions = options.pop("max_sessions", 10_000)
    if "enabled" in options:
        options["enabled"] = _bool(options["enabled"])
    try:
        policy = SessionPolicy(**options)
    except TypeError as exc:
        raise ValueError(f"invalid [session] config: {exc}") from exc
    if store_kind == "memory":
        return policy, MemorySessionStore(max_sessions=int(max_sessions), **({"ttl_seconds": float(ttl)} if ttl else {}))
    if store_kind == "file":
        if not directory:
            raise ValueError('[session] store = "file" needs a dir')
        return policy, FileSessionStore(_resolve(base_dir, directory), **({"ttl_seconds": float(ttl)} if ttl else {}))
    raise ValueError(f"[session] store must be 'memory' or 'file', not {store_kind!r}")


def _audit_logger(audit_cfg: Mapping[str, Any], base_dir: Path | None) -> AuditLogger:
    options = dict(audit_cfg)
    if "path" not in options:
        raise ValueError("[audit] needs a path")
    return AuditLogger(
        _resolve(base_dir, options["path"]),
        min_verdict=Verdict(options.get("min_verdict", "allow")),
        include_text=_bool(options.get("include_text", False)),
        chain=_bool(options.get("chain", True)),
        signer=_resolve(base_dir, options.get("signing_key")),
    )
