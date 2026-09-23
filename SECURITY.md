# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Report them privately through
[GitHub Security Advisories](https://github.com/Lijithvmv/Guard-Layer/security/advisories/new).
Include a description, a minimal reproduction, and the impact you expect.

You can expect an acknowledgement within 5 working days. Fixes are released as patch versions
and credited in the changelog unless you prefer otherwise.

## Scope

In scope:
- A crash, hang or catastrophic regex backtracking (ReDoS) that input text can trigger.
- Bypasses of the REST API's authentication.
- Leaks of scanned text or secrets through logs, audit records or error messages.
- Redaction that fails to mask a span the scanner reported.

Detection bypasses (a prompt that gets past the rules) are expected for any heuristic system.
Please report them as regular issues or pull requests with the sample added to a dataset, so the
fix can be measured.

## Deployment guidance

- GuardLayer is one layer of defense in depth. Keep agent tools least-privilege and require human
  approval for high-impact actions.
- Set `GUARDLAYER_API_KEY` whenever the REST API is reachable beyond localhost, and put it behind TLS.
- Use `fail_closed = true` when a scanner outage should stop traffic rather than let it through.
- `AuditLogger` stores hashes rather than raw text by default. Enable `include_text` only if your
  data-handling policy allows it.
