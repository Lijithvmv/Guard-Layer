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

## Threat model

What GuardLayer protects, what it assumes and what it can't stop: [THREAT_MODEL.md](https://github.com/Lijithvmv/Guard-Layer/blob/main/THREAT_MODEL.md).

## How releases are built

- Releases are published to PyPI by GitHub Actions with **trusted publishing** (OIDC): no PyPI token is stored anywhere.
  PyPI records the workflow that built each file.
- Every third-party action is pinned to a full commit SHA, workflows get a read-only token by default, checkouts don't keep
  credentials, and release tooling is version-pinned. A CI job audits the workflows with zizmor on every push.
- Dependabot proposes updates to actions and Python tooling only after a release is at least 7 days old.
- The core package has no runtime dependencies.

## Deployment guidance

- GuardLayer is one layer of defense in depth. Keep agent tools least-privilege and require human
  approval for high-impact actions.
- Set `GUARDLAYER_API_KEY` whenever the REST API is reachable beyond localhost, and put it behind TLS.
- Use `fail_closed = true` when a scanner outage should stop traffic rather than let it through.
- Session state (`~/.guardlayer/sessions` with the file store) holds keyed hashes of the phrases, places and words a
  session saw (the key is `~/.guardlayer/hash.key`; someone who can read both can test guesses); unkeyed truncated
  SHA-256 fingerprints of identifiers and secrets (URLs, addresses, keys), which are matched inside other text; and the
  **last 500 characters of untrusted content in clear**, secrets redacted, to catch an instruction split across two
  tool results. Sessions expire after 7 days by default.
- `AuditLogger` stores hashes rather than raw text by default. Enable `include_text` only if your
  data-handling policy allows it.
