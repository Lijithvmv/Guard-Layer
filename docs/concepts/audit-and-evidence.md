# Audit log and evidence

## A tamper-evident audit log

```py
from guardlayer import AuditLogger, Verdict

guard.add_hook(AuditLogger("audit.jsonl", min_verdict=Verdict.FLAG, signer="audit.key"))   # signer is optional
```

Each line is one decision. It stores the verdict, the rules and categories, timings, and the **SHA-256 of the scanned
text**, never the text itself (unless you set `include_text=True`). Matched secrets are stripped from detection metadata.

Each line also carries `seq`, `prev_hash` and `entry_hash`: a SHA-256 over the entry, chained to the line before it.

- Editing, deleting, inserting or reordering any line breaks the chain, and `guardlayer audit verify` names the first bad
  line.
- With a signing key (`guardlayer audit keygen audit`, needs the `signing` extra), each entry hash is also signed with
  Ed25519, so forging a consistent chain needs the private key.
- A chain alone can't show that lines were cut from the **end**. Record the reported `head_hash` somewhere else (a
  ticket, a SIEM, git) and pass it back with `--expected-head`.

```bash
guardlayer audit keygen audit                                   # audit.key (keep private) + audit.pub
guardlayer audit verify audit.jsonl --public-key audit.pub
# OK: 1284 entries, chain intact, 1284 signatures valid. head 8e52f749…
```

One logger must own a file: two writers appending to the same file fork the chain. With several processes, put
`{hostname}` and `{pid}` in the path (`audit-{hostname}-{pid}.jsonl`).

## From log to evidence

A GRC or audit team doesn't want JSON lines; they want to know which **controls** the runtime safeguards evidence.
`guardlayer evidence export` verifies the log first, then maps every decision to the controls it is evidence for:

```bash
guardlayer evidence export audit.jsonl --public-key audit.pub                 # summary per framework and control
guardlayer evidence export audit.jsonl --format csv -o evidence.csv           # one row per entry × control
guardlayer evidence export audit.jsonl --format jsonl --framework iso-42001   # machine-readable pack
```

| Framework | What GuardLayer decisions evidence |
|---|---|
| OWASP Top 10 for LLM Applications 2026 (and 2025 IDs) | the risk each detection addresses |
| OWASP Top 10 for Agentic Applications 2026 | goal hijack, tool misuse, identity and privilege abuse, unexpected code execution, memory and context poisoning |
| MITRE ATLAS | prompt injection, jailbreak, system-prompt extraction, data leakage |
| ISO/IEC 42001 Annex A | A.6.2.6 operation and monitoring, A.6.2.8 recording of event logs |
| NIST AI RMF | MEASURE 2.4, MEASURE 2.7, MANAGE 4.1 |
| EU AI Act | Art. 12 record-keeping, Art. 14 human oversight (every review), Art. 15 robustness and cybersecurity |
| CSA AI Controls Matrix v1.1.1 | input and output monitoring, log records, sanitized logs, guardrails, input/output validation, prompt differentiation, agent boundaries and access, sensitive data, credentials, human supervision; log protection only when the log verifies |
| MITRE ATLAS mitigations (v2026.09) | guardrails, telemetry logging, agent tool permissions, human in the loop, restricting tool calls on untrusted data, tool input/output validation, resource limits |
| OWASP AISVS 1.0 | injection screening and detection, smuggling, input limits, output leakage, human approval of high-impact actions, runtime tool policy, secrets kept out of context, decision logging |
| UK Code of Practice for the Cyber Security of AI (2025) | logging, behaviour analysis, human oversight, least-privilege permissions, sensitive-data protection, input checks |

Every record carries the audit entry's `seq` and `entry_hash`, and the pack header carries the verification result, the
source file's SHA-256 and the head hash, so an auditor can re-verify any row against the original log. The export
**refuses** a log that fails verification unless you pass `--allow-unverified`, and then the pack says so. The full
mapping is in the [reference](../reference/compliance.md).

!!! note "Evidence, not certification"
    A mapping means the entry is evidence *relevant to* a control: it shows the runtime safeguard operating. It doesn't
    certify compliance with any framework; that judgement belongs to you and your auditors. EU AI Act obligations depend
    on your system's risk classification.
