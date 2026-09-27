# GuardLayer threat model

What GuardLayer protects, what it assumes, what it can't stop, and how GuardLayer itself could be attacked.
Read this before relying on it. GuardLayer lowers risk; it does not make prompt injection impossible.

## 1. What GuardLayer protects

| Asset | Threat | GuardLayer control |
|---|---|---|
| The model's instructions | Direct prompt injection and jailbreaks in user input | `scan_input`: signature rules, de-obfuscated views, similarity, optional classifier / LLM judge |
| The agent's context | **Indirect** injection in RAG chunks, web pages, emails, tool results | `scan_context`, `scan_tool_result`; session marked untrusted or hostile |
| Secrets and personal data | Leaks in prompts, outputs, tool arguments | Secrets + PII scanners (redaction), `secret_in_egress`, `sensitive_data_egress` |
| The system prompt | Extraction and leakage | Canary tokens, prompt-leak overlap scanner |
| The host and its data | Destructive or persistent commands, credential-file access | Tool-call policy: capabilities, destructive / risky / persistence / credential rules |
| The network boundary | Exfiltration to tunnels, request catchers, metadata endpoints, raw IPs | Egress rules + optional egress allow-list |
| The user (in chat UIs) | Markdown-image and link exfiltration | Link scanner on output |
| Decisions after the fact | Silent tampering with the record | Hash-chained, optionally Ed25519-signed audit log; `guardlayer audit verify` |

## 2. Trust boundaries and assumptions

- **Trusted:** the application code that calls GuardLayer, GuardLayer's configuration, and the operator who approves REVIEW verdicts.
- **Untrusted:** everything the model reads from outside (user input when not trusted, web, email, RAG, tool and MCP results) and
  everything the model *decides* (tool calls are judged before they run).
- **Assumptions GuardLayer depends on:**
  1. The application actually calls the scan functions on every edge, and **passes a session** where taint tracking is wanted.
  2. Tools are tagged with correct capabilities. An untagged tool is assumed able to do anything, but a tool *mis-tagged as read-only*
     skips rules that would otherwise apply.
  3. Human approvers read REVIEW requests. Rubber-stamping defeats the control ("review fatigue"). Measured in the agentic
     evaluation: with every review approved, 4 of 30 attacks succeeded (destructive and persistence actions), against 0 with
     reviews denied. Exfiltration stayed at 0 either way, because secrets are redacted and fingerprinted before egress.
  4. The configuration file and the process environment are not attacker-writable.

## 3. What GuardLayer can't stop (residual risk)

| Gap | Why | Mitigation |
|---|---|---|
| **Paraphrased injections** | Signature and similarity layers catch known and near-known phrasing; held-out recall is ~0.23 rules-only, ~0.47 with the classifier | Architecture first: least-privilege tools, egress allow-list, REVIEW for consequential actions, decisions that don't read free text |
| **Encoded or split secrets** | `sensitive_data_egress` matches verbatim copies (including embedded ones), not base64 or split values | `trifecta` rule escalates untrusted + sensitive + outbound regardless of value matching |
| **Semantic leaks** | Summarised or paraphrased sensitive *information* isn't fingerprintable | Keep secrets out of the context; restrict what the agent can read |
| **Cross-process taint** | Session state is per store; separate processes need a shared `FileSessionStore` | Use the file store (or equivalent) when checks run in separate processes |
| **Ordinary-domain egress** | Without `egress_allowlist`, only known-dangerous destinations are blocked | Set `tools.egress_allowlist` for agents with sensitive access (or use `airgap`) |
| **Fail-open by default** | In `balanced`, a scanner error lets text through | `fail_closed = true` (set by `strict` and `airgap`) |
| **Audit truncation** | A hash chain can't show lines removed from the *end* | Store the reported head hash elsewhere; verify with `--expected-head` |
| **Observe mode** | Nothing is enforced or redacted | Use only while measuring false positives |

Each preset states its own residual risk: `guardlayer presets`.

## 4. Attacks on GuardLayer itself

| Threat | Status |
|---|---|
| **ReDoS** (catastrophic regex backtracking from input) | In scope for security reports. Inputs are size-limited by the `limits` scanner (50,000 chars by default); fingerprint matching is linear in argument length |
| **Supply chain** | Core has **zero runtime dependencies**. Optional extras (`ml`, `embeddings`, `api`, `signing`, integrations) pull third-party packages, so install only what you use |
| **Model tampering** (optional classifier) | The default model's upstream project is archived; GuardLayer **pins it to an exact revision** so a changed upstream can't silently alter verdicts. Each detection records model + revision. Pin custom models with `revision` |
| **Leaking scanned text** | Audit log stores hashes by default (`include_text` opt-in); session state stores fingerprints (length, prefix check, truncated SHA-256), not values |
| **REST API abuse** | Set `GUARDLAYER_API_KEY` beyond localhost and run behind TLS |
| **Claude Code hook** | The hook can only tighten: it returns `deny` or `ask`, **never `allow`**, so it can't widen Claude Code's own permissions. It fails open unless `fail_closed` is set |
| **Rule-pack poisoning** | Custom rule packs and configs are trusted input; protect them like code |

## 5. Reporting

See [SECURITY.md](SECURITY.md). Detection bypasses are expected for heuristic layers; report them as issues with the sample added
to a dataset so the fix can be measured. Crashes, ReDoS, authentication bypasses and data leaks are security reports.
