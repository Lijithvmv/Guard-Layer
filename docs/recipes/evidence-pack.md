# Produce an evidence pack for auditors

Your AI governance team needs to show that runtime safeguards exist *and operate*: ISO/IEC 42001 asks for operation
monitoring and event logs, the EU AI Act for record-keeping and human oversight of high-risk systems, NIST AI RMF for
production monitoring. GuardLayer's audit log already records every decision; this recipe turns it into evidence.

## 1. Log, signed, from day one

```bash
guardlayer audit keygen audit            # audit.key (keep it in a secret store) + audit.pub (give to auditors)
```

```toml
[audit]
path = "/var/log/guardlayer/audit-{hostname}.jsonl"
min_verdict = "allow"                    # log every decision, not only the flagged ones: coverage is evidence too
signing_key = "/etc/guardlayer/audit.key"
```

## 2. Anchor the head

At the end of each period, verify the log and record the head hash somewhere the log's writer can't change (a ticket, a
SIEM, a git commit). This is what detects a truncated log.

```bash
guardlayer audit verify audit-host1.jsonl --public-key audit.pub
# OK: 18342 entries, chain intact, 18342 signatures valid. head 5b0e…
```

## 3. Export

```bash
guardlayer evidence export audit-host1.jsonl --public-key audit.pub --expected-head 5b0e… \
    --format csv -o evidence-2026-Q3.csv
guardlayer evidence export audit-host1.jsonl --public-key audit.pub --format summary
```

The CSV has one row per entry × control: framework, control, entry sequence number and hash, timestamp, verdict, rules,
tool, session. Auditors can filter by control and trace any row back to a verifiable line. Limit to the frameworks you
report against with `--framework iso-42001 --framework eu-ai-act`.

In Python:

```py
from guardlayer import build_evidence

pack = build_evidence("audit-host1.jsonl", public_key="audit.pub", frameworks=["iso-42001", "nist-ai-rmf"])
assert pack.verification.ok
for row in pack.control_summary():
    print(row["framework"], row["control_id"], row["entries"], row["verdicts"])
```

## What to tell the auditor

- **What it shows:** each mapped entry is evidence that a runtime safeguard ran and what it decided. REVIEW entries are
  records of human oversight.
- **What it doesn't:** compliance with the framework. That depends on your policies, processes and risk classification.
- **Integrity:** hash chain plus Ed25519 signatures; head anchored externally; the export refuses unverified logs.
- **Privacy:** the log holds hashes of scanned text, not the text.

The full mapping is in the [reference](../reference/compliance.md).
