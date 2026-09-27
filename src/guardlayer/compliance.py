"""Compliance evidence: turn a GuardLayer audit log into a control-mapped evidence pack.

Every audited decision (a blocked injection, a tool call held for review, a redacted secret)
is mapped to the framework controls it is *evidence for*, and exported in a form a GRC team
can file: JSONL (machine-readable, with a header and per-control summary), CSV (one row per
entry x control, for spreadsheets and GRC tools) or a plain-text summary.

    guardlayer evidence export audit.jsonl --format csv -o evidence.csv
    guardlayer evidence controls                # the mapping catalog

Frameworks mapped (see `CONTROLS`):
    owasp-llm-2026      OWASP Top 10 for LLM Applications 2026
    owasp-llm-2025      OWASP Top 10 for LLM Applications 2025
    owasp-agentic-2026  OWASP Top 10 for Agentic Applications 2026
    mitre-atlas         MITRE ATLAS techniques
    iso-42001           ISO/IEC 42001:2023 Annex A
    nist-ai-rmf         NIST AI RMF 1.0 subcategories
    eu-ai-act           EU AI Act articles (obligations for high-risk AI systems)

**What a mapping means.** A mapped entry is evidence *relevant to* a control: it shows the
control's runtime safeguard operating. It is not an attestation that the control, or the
framework, is satisfied; that judgement belongs to the organisation and its auditors.

**Integrity.** The source log's hash chain (and signatures, with `public_key`) is verified
first and the result travels in the pack, with the source file's SHA-256 and head hash, so
each evidence record traces back to an `entry_hash` in a log that can be re-verified.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardlayer.audit import AuditVerification, verify_audit_log

MAPPING_VERSION = "2026.09"

DISCLAIMER = (
    "Control mappings identify runtime evidence relevant to each control. They do not certify compliance "
    "with any framework; EU AI Act obligations apply according to the system's risk classification."
)


@dataclass(frozen=True)
class Control:
    framework: str
    id: str
    title: str

    @property
    def key(self) -> str:
        return f"{self.framework}:{self.id}"


FRAMEWORKS: dict[str, str] = {
    "owasp-llm-2026": "OWASP Top 10 for LLM Applications 2026",
    "owasp-llm-2025": "OWASP Top 10 for LLM Applications 2025",
    "owasp-agentic-2026": "OWASP Top 10 for Agentic Applications 2026",
    "mitre-atlas": "MITRE ATLAS",
    "iso-42001": "ISO/IEC 42001:2023 Annex A",
    "nist-ai-rmf": "NIST AI RMF 1.0",
    "eu-ai-act": "EU AI Act (Regulation (EU) 2024/1689)",
}

_CATALOG: list[tuple[str, str, str]] = [
    ("owasp-llm-2026", "LLM01", "Prompt Injection"),
    ("owasp-llm-2026", "LLM02", "Sensitive Information Disclosure"),
    ("owasp-llm-2026", "LLM03", "Excessive Agency"),
    ("owasp-llm-2026", "LLM06", "Unbounded Consumption"),
    ("owasp-llm-2026", "LLM08", "Hidden Context Exposure"),
    ("owasp-llm-2026", "LLM10", "Improper Output Handling"),
    ("owasp-llm-2025", "LLM01", "Prompt Injection"),
    ("owasp-llm-2025", "LLM02", "Sensitive Information Disclosure"),
    ("owasp-llm-2025", "LLM05", "Improper Output Handling"),
    ("owasp-llm-2025", "LLM06", "Excessive Agency"),
    ("owasp-llm-2025", "LLM07", "System Prompt Leakage"),
    ("owasp-llm-2025", "LLM10", "Unbounded Consumption"),
    ("owasp-agentic-2026", "ASI01", "Agent Goal Hijack"),
    ("owasp-agentic-2026", "ASI02", "Tool Misuse and Exploitation"),
    ("owasp-agentic-2026", "ASI03", "Identity and Privilege Abuse"),
    ("owasp-agentic-2026", "ASI05", "Unexpected Code Execution"),
    ("owasp-agentic-2026", "ASI06", "Memory and Context Poisoning"),
    ("mitre-atlas", "AML.T0051", "LLM Prompt Injection"),
    ("mitre-atlas", "AML.T0054", "LLM Jailbreak"),
    ("mitre-atlas", "AML.T0056", "Extract LLM System Prompt"),
    ("mitre-atlas", "AML.T0057", "LLM Data Leakage"),
    ("iso-42001", "A.6.2.6", "AI system operation and monitoring"),
    ("iso-42001", "A.6.2.8", "AI system recording of event logs"),
    ("nist-ai-rmf", "MEASURE 2.4", "Functionality and behavior of the AI system are monitored in production"),
    ("nist-ai-rmf", "MEASURE 2.7", "AI system security and resilience are evaluated and documented"),
    ("nist-ai-rmf", "MANAGE 4.1", "Post-deployment monitoring plans are implemented"),
    ("eu-ai-act", "Art. 12", "Record-keeping (automatic logging of events)"),
    ("eu-ai-act", "Art. 14", "Human oversight"),
    ("eu-ai-act", "Art. 15", "Accuracy, robustness and cybersecurity"),
]

CONTROLS: dict[str, Control] = {f"{fw}:{cid}": Control(fw, cid, title) for fw, cid, title in _CATALOG}

# Every audited decision is a logged, monitored runtime event.
BASELINE: tuple[str, ...] = (
    "iso-42001:A.6.2.6", "iso-42001:A.6.2.8",
    "nist-ai-rmf:MEASURE 2.4", "nist-ai-rmf:MANAGE 4.1",
    "eu-ai-act:Art. 12",
)  # fmt: skip
# Any detection: a security safeguard acted (or, in observe mode, would have).
ON_DETECTION: tuple[str, ...] = ("nist-ai-rmf:MEASURE 2.7", "eu-ai-act:Art. 15")
# REVIEW: a human decides before the action proceeds.
ON_REVIEW: tuple[str, ...] = ("eu-ai-act:Art. 14",)

_INJECTION = ("owasp-llm-2026:LLM01", "owasp-llm-2025:LLM01", "mitre-atlas:AML.T0051")
_DISCLOSURE = ("owasp-llm-2026:LLM02", "owasp-llm-2025:LLM02", "mitre-atlas:AML.T0057")
_AGENCY = ("owasp-llm-2026:LLM03", "owasp-llm-2025:LLM06", "owasp-agentic-2026:ASI02")

CATEGORY_CONTROLS: dict[str, tuple[str, ...]] = {
    "prompt_injection": (*_INJECTION, "owasp-agentic-2026:ASI01"),
    "jailbreak": ("owasp-llm-2026:LLM01", "owasp-llm-2025:LLM01", "mitre-atlas:AML.T0054"),
    "goal_hijack": (*_INJECTION, "owasp-agentic-2026:ASI01"),
    "obfuscation": _INJECTION,
    "known_attack": _INJECTION,
    "system_prompt_leak": ("owasp-llm-2026:LLM08", "owasp-llm-2025:LLM07", "mitre-atlas:AML.T0056"),
    "data_exfiltration": (*_DISCLOSURE, "owasp-agentic-2026:ASI02"),
    "secret": _DISCLOSURE,
    "pii": _DISCLOSURE,
    "egress": (*_DISCLOSURE, "owasp-agentic-2026:ASI02"),
    "unsafe_link": ("owasp-llm-2026:LLM10", "owasp-llm-2025:LLM05", *_DISCLOSURE),
    "unsafe_command": (*_AGENCY, "owasp-agentic-2026:ASI05"),
    "tool_misuse": _AGENCY,
    "resource_abuse": ("owasp-llm-2026:LLM06", "owasp-llm-2025:LLM10"),
    "policy": (),
}

RULE_CONTROLS: dict[str, tuple[str, ...]] = {
    "credential_file": ("owasp-agentic-2026:ASI03", *_DISCLOSURE),
    "dotenv_file": ("owasp-agentic-2026:ASI03", *_DISCLOSURE),
    "destructive_command": ("owasp-agentic-2026:ASI05",),
    "persistence": ("owasp-agentic-2026:ASI05",),
    "risky_command": ("owasp-agentic-2026:ASI03", "owasp-agentic-2026:ASI05"),  # includes privilege escalation
    "egress_metadata_endpoint": ("owasp-agentic-2026:ASI03",),  # cloud instance credentials
    "capability_exec": ("owasp-agentic-2026:ASI05",),
    "tool_not_allowed": _AGENCY,
    "tool_denied": _AGENCY,
    "after_injection": ("owasp-agentic-2026:ASI01", "owasp-agentic-2026:ASI06"),
    "trifecta": ("owasp-agentic-2026:ASI02",),
    "sensitive_data_egress": ("owasp-agentic-2026:ASI02",),
    "secret_in_egress": ("owasp-agentic-2026:ASI02",),
}

_RULE_PREFIX_CONTROLS: dict[str, tuple[str, ...]] = {"capability_": _AGENCY}


def detection_controls(detection: Mapping[str, Any], direction: str | None = None) -> list[str]:
    """Control keys a single audited detection is evidence for (framework-specific ones only)."""
    rule, category = str(detection.get("rule", "")), str(detection.get("category", ""))
    keys = list(CATEGORY_CONTROLS.get(category, ()))
    keys += RULE_CONTROLS.get(rule, ())
    for prefix, extra in _RULE_PREFIX_CONTROLS.items():
        if rule.startswith(prefix):
            keys += extra
    if direction == "context" and category in {"prompt_injection", "goal_hijack", "known_attack"}:
        keys.append("owasp-agentic-2026:ASI06")  # indirect injection through RAG, web or tool results
    return _unique(keys)


def entry_controls(entry: Mapping[str, Any]) -> list[str]:
    """Control keys one audit entry is evidence for."""
    keys = list(BASELINE)
    detections = entry.get("detections") or []
    if detections:
        keys += ON_DETECTION
    if "review" in {entry.get("verdict"), entry.get("shadow_verdict")}:
        keys += ON_REVIEW
    for d in detections:
        keys += detection_controls(d, entry.get("direction"))
    return _unique(keys)


def _unique(keys: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(keys))


def _iso(ts: Any) -> str | None:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


# --------------------------------------------------------------------------------------- pack
@dataclass
class EvidencePack:
    source: str
    source_sha256: str
    verification: AuditVerification
    frameworks: list[str]
    records: list[dict[str, Any]] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))

    @property
    def header(self) -> dict[str, Any]:
        from guardlayer import __version__

        v = self.verification
        return {
            "type": "evidence_pack",
            "generated_at": self.generated_at,
            "generator": f"guardlayer {__version__}",
            "mapping_version": MAPPING_VERSION,
            "source": self.source,
            "source_sha256": self.source_sha256,
            "verification": {
                "ok": v.ok, "entries": v.entries, "head_hash": v.head_hash,
                "signatures_valid": v.signed, "error": v.error, "line": v.line,
            },
            "frameworks": {fw: FRAMEWORKS[fw] for fw in self.frameworks},
            "entries": len(self.records),
            "disclaimer": DISCLAIMER,
        }  # fmt: skip

    def control_summary(self) -> list[dict[str, Any]]:
        """Per control: how many entries evidence it, by verdict, and the time range covered."""
        rows: dict[str, dict[str, Any]] = {}
        for rec in self.records:
            for key in rec["controls"]:
                c = CONTROLS[key]
                row = rows.setdefault(key, {
                    "type": "control_summary", "framework": c.framework, "control_id": c.id, "title": c.title,
                    "entries": 0, "verdicts": {"allow": 0, "flag": 0, "review": 0, "block": 0},
                    "rules": {}, "first_seen": None, "last_seen": None,
                })  # fmt: skip
                row["entries"] += 1
                if rec["verdict"] in row["verdicts"]:
                    row["verdicts"][rec["verdict"]] += 1
                for rule in rec["rules"]:
                    row["rules"][rule] = row["rules"].get(rule, 0) + 1
                ts = rec["timestamp"]
                if ts:
                    row["first_seen"] = min(filter(None, [row["first_seen"], ts]))
                    row["last_seen"] = max(filter(None, [row["last_seen"], ts]))
        order = {key: i for i, key in enumerate(CONTROLS)}
        return [rows[k] for k in sorted(rows, key=order.__getitem__)]

    # ------------------------------------------------------------------------------ formats
    def to_jsonl(self) -> str:
        lines = [self.header, *self.records, *self.control_summary()]
        return "".join(json.dumps(line, ensure_ascii=False) + "\n" for line in lines)

    def to_csv(self) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow([
            "framework", "control_id", "control_title", "seq", "entry_id", "timestamp", "verdict", "shadow_verdict",
            "direction", "rules", "categories", "tool", "session_id", "entry_hash",
        ])  # fmt: skip
        for rec in self.records:
            for key in rec["controls"]:
                c = CONTROLS[key]
                writer.writerow([
                    c.framework, c.id, c.title, rec["seq"], rec["entry_id"], rec["timestamp"], rec["verdict"],
                    rec["shadow_verdict"] or "", rec["direction"], ";".join(rec["rules"]), ";".join(rec["categories"]),
                    rec["tool"] or "", rec["session_id"] or "", rec["entry_hash"] or "",
                ])  # fmt: skip
        return buf.getvalue()

    def summary(self) -> str:
        v = self.verification
        status = f"chain intact, head {v.head_hash}" if v.ok else f"NOT VERIFIED: {v.error} (line {v.line})"
        if v.ok and v.signed:
            status += f", {v.signed} signatures valid"
        out = [
            f"GuardLayer evidence pack: {self.source}",
            f"  source sha256 {self.source_sha256}",
            f"  {len(self.records)} entries; {status}",
            f"  mapping {MAPPING_VERSION}; generated {self.generated_at}",
            "",
        ]
        current = None
        for row in self.control_summary():
            if row["framework"] != current:
                current = row["framework"]
                out.append(FRAMEWORKS[current])
            vc = row["verdicts"]
            counts = f"{row['entries']:>5} entries (block {vc['block']}, review {vc['review']}, flag {vc['flag']})"
            out.append(f"  {row['control_id']:<12} {counts:<44} {row['title']}")
        out += ["", DISCLAIMER]
        return "\n".join(out)

    def render(self, fmt: str) -> str:
        if fmt == "jsonl":
            return self.to_jsonl()
        if fmt == "csv":
            return self.to_csv()
        if fmt == "summary":
            return self.summary() + "\n"
        raise ValueError(f"unknown format {fmt!r}; use jsonl, csv or summary")


def build_evidence(
    path: str | Path,
    *,
    public_key: Any | str | Path | bytes | None = None,
    expected_head: str | None = None,
    frameworks: Iterable[str] | None = None,
) -> EvidencePack:
    """Verify an audit log and map each entry to framework controls.

    Always returns a pack; check `pack.verification.ok` before relying on it (the CLI refuses
    unverified logs unless told otherwise). `frameworks` limits the controls to those frameworks.
    """
    selected = list(frameworks) if frameworks else list(FRAMEWORKS)
    unknown = set(selected) - set(FRAMEWORKS)
    if unknown:
        raise ValueError(f"unknown frameworks {sorted(unknown)}; use {list(FRAMEWORKS)}")
    path = Path(path)
    raw = path.read_bytes()
    verification = verify_audit_log(path, public_key=public_key, expected_head=expected_head)
    pack = EvidencePack(str(path), hashlib.sha256(raw).hexdigest(), verification, selected)

    for lineno, line in enumerate(raw.decode("utf-8").split("\n"), 1):  # not splitlines(): JSON may hold U+2028
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue  # reported by verification
        if not isinstance(entry, dict):
            continue
        controls = [k for k in entry_controls(entry) if CONTROLS[k].framework in selected]
        metadata = entry.get("metadata") or {}
        detections = entry.get("detections") or []
        pack.records.append({
            "type": "entry",
            "line": lineno,
            "seq": entry.get("seq"),
            "entry_id": entry.get("id"),
            "entry_hash": entry.get("entry_hash"),
            "timestamp": _iso(entry.get("timestamp")),
            "verdict": entry.get("verdict"),
            "shadow_verdict": entry.get("shadow_verdict"),
            "direction": entry.get("direction"),
            "rules": sorted({str(d.get("rule")) for d in detections}),
            "categories": sorted({str(d.get("category")) for d in detections}),
            "tool": metadata.get("tool"),
            "session_id": metadata.get("session_id"),
            "controls": controls,
        })  # fmt: skip
    return pack
