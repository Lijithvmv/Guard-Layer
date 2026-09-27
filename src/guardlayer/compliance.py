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
    csa-aicm            CSA AI Controls Matrix v1.1.1 (IDs and titles referenced with attribution)
    mitre-atlas-mitigations  MITRE ATLAS mitigations (v2026.09)
    owasp-aisvs-1.0     OWASP AI Security Verification Standard 1.0 requirements
    uk-ai-cop           UK Code of Practice for the Cyber Security of AI (2025) provisions
    etsi-en-304-223     ETSI EN 304 223 V2.1.1 (supersedes TS 104 223) provision numbers
    nist-sp-800-53      NIST SP 800-53 Rev. 5.2.0 controls
    nist-csf-2.0        NIST Cybersecurity Framework 2.0 subcategories
    iso-27001           ISO/IEC 27001:2022 Annex A controls
    soc2-tsc            SOC 2: AICPA Trust Services Criteria (2017) criteria
    hipaa-security      HIPAA Security Rule standards and implementation specifications
    gdpr                GDPR articles (where personal data is processed)

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

MAPPING_VERSION = "2026.09.11"

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
    "csa-aicm": "CSA AI Controls Matrix v1.1.1",
    "mitre-atlas-mitigations": "MITRE ATLAS mitigations (v2026.09)",
    "owasp-aisvs-1.0": "OWASP AI Security Verification Standard (AISVS) 1.0",
    "uk-ai-cop": "UK Code of Practice for the Cyber Security of AI (2025)",
    "etsi-en-304-223": "ETSI EN 304 223 V2.1.1 (2025-12), baseline cyber security for AI",
    "nist-sp-800-53": "NIST SP 800-53 Rev. 5.2.0",
    "nist-csf-2.0": "NIST Cybersecurity Framework (CSF) 2.0",
    "iso-27001": "ISO/IEC 27001:2022 Annex A",
    "soc2-tsc": "SOC 2: AICPA Trust Services Criteria (2017, points of focus revised 2022)",
    "hipaa-security": "HIPAA Security Rule (45 CFR Part 164, Subpart C)",
    "gdpr": "GDPR (Regulation (EU) 2016/679)",
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
    # CSA AI Controls Matrix v1.1.1 (c) Cloud Security Alliance, all rights reserved: control IDs and titles are
    # referenced with attribution; no control text is reproduced. Verified against the official spreadsheet 2026-09-27.
    ("csa-aicm", "AIS-09", "Input Validation"),
    ("csa-aicm", "AIS-10", "Output Validation"),
    ("csa-aicm", "AIS-11", "Agents Security Boundaries"),
    ("csa-aicm", "AIS-15", "Prompt Differentiation"),
    ("csa-aicm", "DSP-10", "Sensitive Data Transfer"),
    ("csa-aicm", "DSP-17", "Sensitive Data Protection"),
    ("csa-aicm", "GRC-15", "Human supervision"),
    ("csa-aicm", "IAM-14", "Credentials Management"),
    ("csa-aicm", "IAM-18", "Agent Access Restriction"),
    ("csa-aicm", "LOG-02", "Audit Logs Protection"),
    ("csa-aicm", "LOG-08", "Audit Logs Sanitization"),
    ("csa-aicm", "LOG-09", "Log Records"),
    ("csa-aicm", "LOG-15", "Input Monitoring"),
    ("csa-aicm", "LOG-16", "Output Monitoring"),
    ("csa-aicm", "TVM-13", "Guardrails"),
    # MITRE ATLAS mitigations, names as in atlas-data v2026.09 (Apache-2.0, (c) MITRE).
    ("mitre-atlas-mitigations", "AML.M0020", "Generative AI Guardrails"),
    ("mitre-atlas-mitigations", "AML.M0024", "AI Telemetry Logging"),
    ("mitre-atlas-mitigations", "AML.M0028", "AI Agent Tools Permissions Configuration"),
    ("mitre-atlas-mitigations", "AML.M0029", "Human In-the-Loop for AI Agent Actions"),
    ("mitre-atlas-mitigations", "AML.M0030", "Restrict AI Agent Tool Invocation on Untrusted Data"),
    ("mitre-atlas-mitigations", "AML.M0033", "Input and Output Validation for AI Agent Components"),
    ("mitre-atlas-mitigations", "AML.M0036", "Limit AI Workload Resource Consumption"),
    # OWASP AISVS 1.0 (CC BY-SA 4.0). Requirements have no titles: these are GuardLayer's own short summaries, not
    # AISVS text. Cite as "v1.0-C<id>".
    ("owasp-aisvs-1.0", "C2.1.2", "Encoded or smuggled input is detected"),
    ("owasp-aisvs-1.0", "C2.1.3", "Untrusted input is screened for prompt injection; flagged input is blocked"),
    ("owasp-aisvs-1.0", "C2.1.4", "Input length limits are enforced"),
    ("owasp-aisvs-1.0", "C2.1.7", "Reserved special tokens can't be injected"),
    ("owasp-aisvs-1.0", "C2.1.8", "Many-shot jailbreak patterns are detected"),
    ("owasp-aisvs-1.0", "C7.3.2", "Output disclosing the system prompt or backend data is blocked"),
    ("owasp-aisvs-1.0", "C7.3.3", "Model output can't trigger outbound requests"),
    ("owasp-aisvs-1.0", "C7.3.4", "Hidden or encoded content in output is checked"),
    ("owasp-aisvs-1.0", "C9.2.1", "High-impact agent actions wait for human approval"),
    ("owasp-aisvs-1.0", "C9.3.5", "Processing of untrusted data can't trigger tool calls"),
    ("owasp-aisvs-1.0", "C9.5.1", "Agent tool use is restricted by runtime policy"),
    ("owasp-aisvs-1.0", "C9.5.3", "Access decisions are made by a policy engine, not the model"),
    ("owasp-aisvs-1.0", "C9.5.4", "Secrets are kept out of the model's context"),
    ("owasp-aisvs-1.0", "C12.1.2", "Guardrail decisions are recorded for audit"),
    ("owasp-aisvs-1.0", "C12.2.1", "Known jailbreak and injection attempts are detected and alerted"),
    ("owasp-aisvs-1.0", "C12.2.3", "Custom rules detect injection and prompt-extraction attempts"),
    # UK Code of Practice for the Cyber Security of AI (DSIT/NCSC, January 2025), Crown copyright, Open Government
    # Licence v3.0. Provision numbers as published on gov.uk; descriptions are GuardLayer's own ("shall"/"should" kept).
    ("uk-ai-cop", "2.6", "AI system permissions on other systems limited to what's required (shall)"),
    ("uk-ai-cop", "4.1", "Capabilities that enable human oversight (should)"),
    ("uk-ai-cop", "4.3", "Technical measures where human oversight is a risk control (shall)"),
    ("uk-ai-cop", "5.4", "Sensitive data protected against unauthorised access (shall)"),
    ("uk-ai-cop", "5.4.1", "Checks and sanitisation applied to data and inputs (shall)"),
    ("uk-ai-cop", "12.1", "System and user actions logged for security compliance and investigations (shall)"),
    ("uk-ai-cop", "12.2", "Behaviour analysed to detect breaches and unexpected behaviour (should)"),
    # ETSI EN 304 223 V2.1.1 (2025-12), which supersedes TS 104 223 and builds on the UK Code; (c) ETSI, all rights
    # reserved. Provision numbers only, checked against the official PDF; descriptions are GuardLayer's own.
    ("etsi-en-304-223", "5.1.2-2", "AI system built to withstand adversarial attacks and unexpected input (shall)"),
    ("etsi-en-304-223", "5.1.2-6", "AI system permissions on other systems limited to what's required (shall)"),
    ("etsi-en-304-223", "5.1.4-1", "Capabilities that enable human oversight (should)"),
    ("etsi-en-304-223", "5.1.4-3", "Technical measures where human oversight is a risk control (shall)"),
    ("etsi-en-304-223", "5.2.1-4", "Sensitive data protected against unauthorised access (shall)"),
    ("etsi-en-304-223", "5.2.1-4.1", "Checks and sanitisation applied to data and inputs (shall)"),
    ("etsi-en-304-223", "5.4.2-1", "System and user actions logged for security compliance and investigations (shall)"),
    ("etsi-en-304-223", "5.4.2-2", "Behaviour analysed to detect breaches and unexpected behaviour (should)"),
    # NIST SP 800-53 Rev. 5.2.0 (public domain), titles from NIST's OSCAL catalog (last modified 2026-05-11).
    ("nist-sp-800-53", "AC-3", "Access Enforcement"),
    ("nist-sp-800-53", "AC-4", "Information Flow Enforcement"),
    ("nist-sp-800-53", "AC-6", "Least Privilege"),
    ("nist-sp-800-53", "AU-2", "Event Logging"),
    ("nist-sp-800-53", "AU-3", "Content of Audit Records"),
    ("nist-sp-800-53", "AU-9", "Protection of Audit Information"),
    ("nist-sp-800-53", "AU-9(3)", "Protection of Audit Information | Cryptographic Protection"),
    ("nist-sp-800-53", "AU-10", "Non-repudiation"),
    ("nist-sp-800-53", "AU-12", "Audit Record Generation"),
    ("nist-sp-800-53", "SC-5", "Denial-of-service Protection"),
    ("nist-sp-800-53", "SC-7", "Boundary Protection"),
    ("nist-sp-800-53", "SC-7(5)", "Boundary Protection | Deny by Default — Allow by Exception"),
    ("nist-sp-800-53", "SI-4", "System Monitoring"),
    ("nist-sp-800-53", "SI-10", "Information Input Validation"),
    ("nist-sp-800-53", "SI-15", "Information Output Filtering"),
    # NIST CSF 2.0 (public domain), subcategory text from NIST's CSF 2.0 reference export.
    ("nist-csf-2.0", "DE.AE-06", "Information on adverse events is provided to authorized staff and tools"),
    ("nist-csf-2.0", "DE.CM-09", "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events"),
    ("nist-csf-2.0", "PR.AA-05", "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties"),
    ("nist-csf-2.0", "PR.DS-01", "The confidentiality, integrity, and availability of data-at-rest are protected"),
    ("nist-csf-2.0", "PR.DS-02", "The confidentiality, integrity, and availability of data-in-transit are protected"),
    ("nist-csf-2.0", "PR.DS-10", "The confidentiality, integrity, and availability of data-in-use are protected"),
    ("nist-csf-2.0", "PR.PS-04", "Log records are generated and made available for continuous monitoring"),
    ("nist-csf-2.0", "PR.PS-05", "Installation and execution of unauthorized software are prevented"),
    # ISO/IEC 27001:2022 Annex A (c) ISO: control numbers and short titles referenced, as for ISO/IEC 42001.
    ("iso-27001", "A.5.15", "Access control"),
    ("iso-27001", "A.5.33", "Protection of records"),
    ("iso-27001", "A.5.34", "Privacy and protection of PII"),
    ("iso-27001", "A.8.3", "Information access restriction"),
    ("iso-27001", "A.8.11", "Data masking"),
    ("iso-27001", "A.8.12", "Data leakage prevention"),
    ("iso-27001", "A.8.15", "Logging"),
    ("iso-27001", "A.8.16", "Monitoring activities"),
    ("iso-27001", "A.8.23", "Web filtering"),
    # AICPA 2017 Trust Services Criteria (c) AICPA: criterion IDs checked against the 2022 revised edition;
    # descriptions are GuardLayer's own.
    ("soc2-tsc", "C1.1", "Confidential information is identified and protected"),
    ("soc2-tsc", "CC6.1", "Logical access security over protected assets"),
    ("soc2-tsc", "CC6.3", "Access granted by role, with least privilege"),
    ("soc2-tsc", "CC6.6", "Protection against threats from outside the system boundary"),
    ("soc2-tsc", "CC6.7", "Movement of information restricted to authorised recipients"),
    ("soc2-tsc", "CC6.8", "Unauthorised or malicious software prevented or detected"),
    ("soc2-tsc", "CC7.2", "Components monitored for anomalies indicating malicious acts"),
    ("soc2-tsc", "CC7.3", "Security events evaluated and acted on"),
    # HIPAA Security Rule (US federal regulation, public domain), titles as in the eCFR current on 2026-09-24.
    # Relevant only where the AI system creates, receives, maintains or transmits ePHI.
    ("hipaa-security", "164.308(a)(1)(ii)(D)", "Information system activity review"),
    ("hipaa-security", "164.308(a)(5)(ii)(B)", "Protection from malicious software (addressable)"),
    ("hipaa-security", "164.308(a)(6)(ii)", "Security incident procedures: response and reporting"),
    ("hipaa-security", "164.312(a)(1)", "Access control"),
    ("hipaa-security", "164.312(b)", "Audit controls"),
    ("hipaa-security", "164.312(e)(1)", "Transmission security"),
    # GDPR (EU law; EUR-Lex reuse with attribution). Claimed only where personal data is involved.
    ("gdpr", "Art. 5(1)(c)", "Data minimisation"),
    ("gdpr", "Art. 5(1)(f)", "Integrity and confidentiality"),
    ("gdpr", "Art. 25(1)", "Data protection by design"),
    ("gdpr", "Art. 25(2)", "Data protection by default"),
    ("gdpr", "Art. 32(1)(b)", "Security of processing: ongoing confidentiality and integrity"),
]

CONTROLS: dict[str, Control] = {f"{fw}:{cid}": Control(fw, cid, title) for fw, cid, title in _CATALOG}

# Every audited decision is a logged, monitored runtime event.
BASELINE: tuple[str, ...] = (
    "iso-42001:A.6.2.6", "iso-42001:A.6.2.8",
    "nist-ai-rmf:MEASURE 2.4", "nist-ai-rmf:MANAGE 4.1",
    "eu-ai-act:Art. 12", "csa-aicm:LOG-09",
    "mitre-atlas-mitigations:AML.M0024", "owasp-aisvs-1.0:C12.1.2", "uk-ai-cop:12.1",
    "etsi-en-304-223:5.4.2-1", "nist-sp-800-53:AU-2", "nist-sp-800-53:AU-3", "nist-sp-800-53:AU-12",
    "nist-csf-2.0:PR.PS-04", "nist-csf-2.0:DE.CM-09", "iso-27001:A.8.15", "iso-27001:A.8.16",
    "soc2-tsc:CC7.2", "hipaa-security:164.312(b)",
)  # fmt: skip
# By direction: what was monitored.
ON_DIRECTION: dict[str, tuple[str, ...]] = {
    "input": ("csa-aicm:LOG-15",), "context": ("csa-aicm:LOG-15",), "output": ("csa-aicm:LOG-16",),
}  # fmt: skip
# Claimed only when the log's hash chain (and signatures, if checked) verified: the log itself is protected.
ON_VERIFIED: tuple[str, ...] = ("csa-aicm:LOG-02", "nist-sp-800-53:AU-9", "nist-sp-800-53:AU-9(3)", "nist-csf-2.0:PR.DS-01",
    "iso-27001:A.5.33",
)
# Claimed only when every entry's Ed25519 signature verified: origin can't be repudiated.
ON_SIGNED: tuple[str, ...] = ("nist-sp-800-53:AU-10",)
# The entry holds hashes, not the scanned text: the log is sanitized by design.
ON_SANITIZED: tuple[str, ...] = ("csa-aicm:LOG-08", "gdpr:Art. 5(1)(c)", "gdpr:Art. 25(2)")
# Any detection: a security safeguard acted (or, in observe mode, would have).
ON_DETECTION: tuple[str, ...] = (
    "nist-ai-rmf:MEASURE 2.7", "eu-ai-act:Art. 15", "csa-aicm:TVM-13", "mitre-atlas-mitigations:AML.M0020",
    "uk-ai-cop:12.2", "etsi-en-304-223:5.4.2-2", "nist-sp-800-53:SI-4", "soc2-tsc:CC7.3",
    "hipaa-security:164.308(a)(6)(ii)", "hipaa-security:164.308(a)(1)(ii)(D)",
)  # fmt: skip
# REVIEW: a human decides before the action proceeds.
ON_REVIEW: tuple[str, ...] = ("eu-ai-act:Art. 14", "csa-aicm:GRC-15", "uk-ai-cop:4.1", "uk-ai-cop:4.3",
    "etsi-en-304-223:5.1.4-1", "etsi-en-304-223:5.1.4-3",
    "nist-csf-2.0:DE.AE-06",
)
# REVIEW of an agent's tool call specifically.
ON_TOOL_REVIEW: tuple[str, ...] = ("mitre-atlas-mitigations:AML.M0029", "owasp-aisvs-1.0:C9.2.1")
# A detection on a tool call or tool result: the agent's tool inputs/outputs are validated.
ON_TOOL_DETECTION: tuple[str, ...] = ("mitre-atlas-mitigations:AML.M0033",)
# By the component that decided.
SCANNER_CONTROLS: dict[str, tuple[str, ...]] = {
    "tool_policy": ("mitre-atlas-mitigations:AML.M0028", "owasp-aisvs-1.0:C9.5.1", "owasp-aisvs-1.0:C9.5.3", "uk-ai-cop:2.6",
                    "etsi-en-304-223:5.1.2-6", "nist-sp-800-53:AC-3", "nist-sp-800-53:AC-6",
                    "nist-csf-2.0:PR.AA-05", "iso-27001:A.5.15", "soc2-tsc:CC6.1", "soc2-tsc:CC6.3",
                    "hipaa-security:164.312(a)(1)"),
    "session": ("mitre-atlas-mitigations:AML.M0030", "owasp-aisvs-1.0:C9.3.5", "owasp-aisvs-1.0:C9.5.3",
                "nist-sp-800-53:AC-4", "nist-csf-2.0:PR.DS-02", "iso-27001:A.8.12", "soc2-tsc:CC6.7",
                "hipaa-security:164.312(e)(1)"),
}  # fmt: skip

_INJECTION = ("owasp-llm-2026:LLM01", "owasp-llm-2025:LLM01", "mitre-atlas:AML.T0051")
_DISCLOSURE = ("owasp-llm-2026:LLM02", "owasp-llm-2025:LLM02", "mitre-atlas:AML.T0057", "csa-aicm:DSP-17", "uk-ai-cop:5.4",
               "etsi-en-304-223:5.2.1-4")
_AGENCY = ("owasp-llm-2026:LLM03", "owasp-llm-2025:LLM06", "owasp-agentic-2026:ASI02", "csa-aicm:AIS-11", "csa-aicm:IAM-18")
_OUTPUT = ("csa-aicm:AIS-10",)

CATEGORY_CONTROLS: dict[str, tuple[str, ...]] = {
    "prompt_injection": (*_INJECTION, "owasp-agentic-2026:ASI01"),
    "jailbreak": ("owasp-llm-2026:LLM01", "owasp-llm-2025:LLM01", "mitre-atlas:AML.T0054"),
    "goal_hijack": (*_INJECTION, "owasp-agentic-2026:ASI01"),
    "obfuscation": _INJECTION,
    "known_attack": _INJECTION,
    "system_prompt_leak": ("owasp-llm-2026:LLM08", "owasp-llm-2025:LLM07", "mitre-atlas:AML.T0056", *_OUTPUT),
    "data_exfiltration": (*_DISCLOSURE, "owasp-agentic-2026:ASI02", "csa-aicm:DSP-10"),
    "secret": _DISCLOSURE,
    "pii": _DISCLOSURE,
    "egress": (*_DISCLOSURE, "owasp-agentic-2026:ASI02", "csa-aicm:DSP-10", "nist-sp-800-53:SC-7", "nist-csf-2.0:PR.DS-02",
               "iso-27001:A.8.12", "iso-27001:A.8.23", "soc2-tsc:CC6.7", "hipaa-security:164.312(e)(1)"),
    "unsafe_link": ("owasp-llm-2026:LLM10", "owasp-llm-2025:LLM05", *_DISCLOSURE, *_OUTPUT),
    "unsafe_command": (*_AGENCY, "owasp-agentic-2026:ASI05"),
    "tool_misuse": _AGENCY,
    "resource_abuse": ("owasp-llm-2026:LLM06", "owasp-llm-2025:LLM10", "mitre-atlas-mitigations:AML.M0036", "nist-sp-800-53:SC-5"),
    "policy": (),
}

RULE_CONTROLS: dict[str, tuple[str, ...]] = {
    "credential_file": ("owasp-agentic-2026:ASI03", *_DISCLOSURE, "csa-aicm:IAM-14", "iso-27001:A.8.3"),
    "dotenv_file": ("owasp-agentic-2026:ASI03", *_DISCLOSURE, "csa-aicm:IAM-14", "iso-27001:A.8.3"),
    "destructive_command": ("owasp-agentic-2026:ASI05",),
    "persistence": ("owasp-agentic-2026:ASI05", "nist-csf-2.0:PR.PS-05", "soc2-tsc:CC6.8", "hipaa-security:164.308(a)(5)(ii)(B)"),  # e.g. a curl | sh line in ~/.bashrc
    "risky_command": ("owasp-agentic-2026:ASI03", "owasp-agentic-2026:ASI05"),  # includes privilege escalation
    "egress_metadata_endpoint": ("owasp-agentic-2026:ASI03",),  # cloud instance credentials
    "capability_exec": ("owasp-agentic-2026:ASI05",),
    "tool_not_allowed": _AGENCY,
    "tool_denied": _AGENCY,
    "after_injection": ("owasp-agentic-2026:ASI01", "owasp-agentic-2026:ASI06"),
    "trifecta": ("owasp-agentic-2026:ASI02",),
    "egress_not_allowed": ("nist-sp-800-53:SC-7(5)",),  # fires only when an egress allow-list is set
    "sensitive_data_egress": ("owasp-agentic-2026:ASI02", "nist-sp-800-53:AC-4", "nist-csf-2.0:PR.DS-02", "iso-27001:A.8.12",
                              "soc2-tsc:CC6.7", "hipaa-security:164.312(e)(1)"),
    "secret_in_egress": ("owasp-agentic-2026:ASI02", "nist-sp-800-53:AC-4", "nist-csf-2.0:PR.DS-02", "iso-27001:A.8.12",
                         "soc2-tsc:CC6.7", "hipaa-security:164.312(e)(1)"),
    "fake_special_tokens": ("owasp-aisvs-1.0:C2.1.7",),
    "many_shot_pattern": ("owasp-aisvs-1.0:C2.1.8",),
    "oversized_input": ("owasp-aisvs-1.0:C2.1.4",),
    "token_flooding": ("owasp-aisvs-1.0:C2.1.4",),
    "character_flooding": ("owasp-aisvs-1.0:C2.1.4",),
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
    keys += SCANNER_CONTROLS.get(str(detection.get("scanner", "")), ())
    injection = category in {"prompt_injection", "jailbreak", "goal_hijack", "known_attack", "obfuscation"}
    incoming = direction in {"input", "context"}
    if injection and incoming:
        keys += ["csa-aicm:AIS-09", "owasp-aisvs-1.0:C2.1.3", "owasp-aisvs-1.0:C12.2.1", "uk-ai-cop:5.4.1",
                 "etsi-en-304-223:5.2.1-4.1", "etsi-en-304-223:5.1.2-2", "nist-sp-800-53:SI-10"]  # input screened
        if detection.get("scanner") == "heuristics":
            keys.append("owasp-aisvs-1.0:C12.2.3")  # custom detection rules
    if injection and direction == "context":
        keys += ["owasp-agentic-2026:ASI06", "csa-aicm:AIS-15", "soc2-tsc:CC6.6"]  # indirect injection from outside
    if category == "obfuscation":
        keys.append("owasp-aisvs-1.0:C2.1.2" if incoming else "owasp-aisvs-1.0:C7.3.4")
    if direction == "output" and category in {"system_prompt_leak", "unsafe_link", "pii", "secret", "data_exfiltration"}:
        keys += ["nist-sp-800-53:SI-15", "iso-27001:A.8.12"]  # output filtered before it left
    if category == "system_prompt_leak":
        keys.append("owasp-aisvs-1.0:C7.3.2" if direction == "output" else "owasp-aisvs-1.0:C12.2.3")
    if category == "unsafe_link" and direction == "output":
        keys.append("owasp-aisvs-1.0:C7.3.3")
    if category == "secret" and direction == "context":
        keys.append("owasp-aisvs-1.0:C9.5.4")  # a secret in retrieved or tool content was redacted before the model
    if category in {"secret", "pii"} and incoming:
        keys.append("nist-csf-2.0:PR.DS-10")  # sensitive data redacted before the model used it
    if category in {"secret", "pii"}:
        keys += ["iso-27001:A.8.11", "soc2-tsc:C1.1"]  # data masking (redaction); confidential data identified
    if category == "pii":
        keys += ["iso-27001:A.5.34", "gdpr:Art. 5(1)(f)", "gdpr:Art. 25(1)", "gdpr:Art. 32(1)(b)"]
    return _unique(keys)


def entry_controls(entry: Mapping[str, Any]) -> list[str]:
    """Control keys one audit entry is evidence for."""
    keys = [*BASELINE, *ON_DIRECTION.get(str(entry.get("direction")), ())]
    if "text" not in entry:
        keys += ON_SANITIZED
    detections = entry.get("detections") or []
    if detections:
        keys += ON_DETECTION
    tool_call = bool((entry.get("metadata") or {}).get("tool"))
    if "review" in {entry.get("verdict"), entry.get("shadow_verdict")}:
        keys += ON_REVIEW
        if tool_call:
            keys += ON_TOOL_REVIEW
    if detections and tool_call:
        keys += ON_TOOL_DETECTION
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
        keys = entry_controls(entry)
        if verification.ok and entry.get("entry_hash"):
            keys = _unique([*keys, *ON_VERIFIED])  # the log is protected, so this entry is evidence for that too
            if verification.signed and entry.get("signature"):
                keys = _unique([*keys, *ON_SIGNED])
        controls = [k for k in keys if CONTROLS[k].framework in selected]
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
