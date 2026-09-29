# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.6.1] - 2026-09-29

First release published to PyPI (0.5.0 and 0.6.0 were tagged on GitHub only; their publish step failed before trusted publishing was set up).

### Security
- **Hardened the project's own build pipeline:** every GitHub Action pinned to a full commit SHA; read-only default token
  in all workflows; `persist-credentials: false` on checkouts; release tooling pinned (`build`, `twine`); the third-party
  release action replaced with the runner's `gh`; concurrency limits; Dependabot for actions and pip with a 7-day cooldown;
  a `workflow-security` CI job running zizmor. Documented in SECURITY.md ("How releases are built").

### Added
- **`benchmarks/llmail_eval.py`**: a held-out test on Microsoft's LLMail-Inject (phase 2, 38,014 unique real attacker emails,
  MIT). GuardLayer detects 17.4% of the attacks that hijacked the model with rules only and 47.0% with the classifier (50.4% of those
  that also evaded the challenge's defenses); no false positives on 238 benign emails. Never used for tuning.
- AgentDojo banking with `allow_egress` for the payment tools: benign utility 4 -> 5 / 10, no benign blocks, attack success still 0 / 10.
- **`[session] allow_egress`**: tool-name glob -> data types that tool may send out (`{ send_money = ["iban"] }`). Those types,
  for that tool only, no longer trigger `sensitive_data_egress`, nor `trifecta` when they are the only sensitive data in the
  session; `after_injection` still applies. Fingerprints now carry the rule that found the value (`<len>:<prefix>:<sha>:<kind>`)
  and sessions record `sensitive_kinds`; untyped fingerprints from older session files are never exempt. Found by AgentDojo:
  legitimate payments to an IBAN from a bill were blocked.

## [0.6.0] - 2026-09-27

### Added
- **Control-mapped compliance evidence** (`guardlayer.compliance`, `guardlayer evidence export | controls`). Verifies a hash-chained
  audit log, then maps every entry to the controls it evidences: OWASP Top 10 for LLM Applications 2026 (and 2025 IDs), OWASP Top 10
  for Agentic Applications 2026, MITRE ATLAS, ISO/IEC 42001 Annex A (A.6.2.6, A.6.2.8), NIST AI RMF (MEASURE 2.4, 2.7, MANAGE 4.1)
  and EU AI Act Art. 12, 14 and 15. Exports JSONL (header with verification result, source SHA-256 and head hash; one record per entry;
  per-control summary), CSV (one row per entry x control) or a text summary. Refuses unverified logs unless `--allow-unverified`.
  Mapping version `2026.09`. 13 tests in `tests/test_compliance.py`.
- **`benchmarks/perf.py`**: latency (p50/p95/p99) for every guard edge at 200 to 48,000 characters, multi-process throughput,
  memory, and a REST API load test (`--api`). Standard library only; deterministic payloads. Results in `benchmarks/results/`.
- **`DEPLOYMENT.md`** and **`deploy/`**: deployment shapes, a hardened Compose file, Kubernetes manifests (ConfigMap, Deployment
  with non-root/read-only/no-capabilities, Service, deny-egress NetworkPolicy, HPA, PodDisruptionBudget; strict-validated against
  Kubernetes 1.31), sizing, sessions across replicas, audit-log storage, rollout, and measured performance.
- `[audit] path` accepts `{hostname}` and `{pid}`, so each worker or pod owns its own hash-chained file.
- **CSA AI Controls Matrix v1.1.1 in the evidence export** (`--framework csa-aicm`, mapping version `2026.09.2`), verified
  against CSA's official spreadsheet: log records (LOG-09), input and output monitoring (LOG-15/16), sanitized logs
  (LOG-08, when the entry holds hashes only), guardrails (TVM-13), input/output validation (AIS-09/10), prompt
  differentiation (AIS-15), agent boundaries and access (AIS-11, IAM-18), sensitive data (DSP-10/17), credentials
  (IAM-14), human supervision (GRC-15); audit log protection (LOG-02) only when the log verifies. IDs and titles are
  referenced with attribution; no control text is included.
- **NYDFS 23 NYCRR Part 500 in the evidence export** (mapping version `2026.09.17`), from DFS's published amended text:
  500.6(a)(2) on every entry, 500.14(a)(2) for injections in content the agent reads (web, email, tool results),
  500.14(a)(1) and 500.7(a)(1) for tool policy and session taint.
- **DORA in the evidence export** (mapping version `2026.09.16`), from the Commission's adopted RTS text: RTS 2024/1774
  Art. 12(1) on every entry, Art. 12(2)(d) when the log verifies, DORA Art. 10(1) on detections, RTS Art. 21(a)/(d) for tool
  policy, RTS Art. 11(2)(i) wherever data leaving is blocked.
- **NIS2 in the evidence export** (mapping version `2026.09.15`): Implementing Regulation 2024/2690 annex 3.2.1 on every
  entry and 3.2.5 when the log verifies; Directive Art. 21(2)(b) on detections; Art. 21(2)(i) and annex 11.1.1 for tool
  policy. Numbers checked against ENISA's Technical Implementation Guidance.
- **FedRAMP 20x Key Security Indicators in the evidence export** (mapping version `2026.09.14`), from FedRAMP's
  Consolidated Rules 2026.09.13.02: KSI-MLA-LET on every entry, KSI-IAM-ELP for tool policy, KSI-CNA-RNT for egress rules.
  Process KSIs (reviews, SIEM operation, incident response) aren't claimed. Rev. 5 authorisations use the SP 800-53 evidence.
- **CMMC 2.0 Level 2 in the evidence export** (mapping version `2026.09.13`), practice IDs and titles from the DoD CMMC
  Assessment Guide Level 2 v2.13: AU.L2-3.3.1 on every entry, AU.L2-3.3.8 when the log verifies, SI.L2-3.14.6 on
  detections, AC.L2-3.1.1/3.1.2/3.1.5 for tool policy, AC.L2-3.1.3 for session taint and data leaving, SC.L2-3.13.1 for
  egress rules and SC.L2-3.13.6 for allow-list blocks, SI.L2-3.14.2 for blocked persistence.
- **PCI DSS v4.0.1 in the evidence export** (mapping version `2026.09.12`): 10.2.1 on every entry, 10.3.4 when the log
  verifies, 3.4.1 for card numbers masked in output, 7.2.5 for tool policy, 1.3.2 for allow-list egress blocks. 3.5.1 is
  deliberately not claimed (the log's text hash is unkeyed).
- **GDPR in the evidence export** (mapping version `2026.09.11`), only where personal data is involved: Art. 5(1)(f),
  25(1) and 32(1)(b) for detected and redacted personal data; Art. 5(1)(c) and 25(2) for audit entries that keep hashes
  rather than text (not claimed with `include_text=True`). Art. 32(1)(a) is not claimed: a hash isn't pseudonymisation.
- **HIPAA Security Rule in the evidence export** (mapping version `2026.09.10`): 164.312(b) audit controls on every entry,
  164.312(a)(1) access control for tool policy (the rule covers software programs), 164.312(e)(1) transmission security
  for blocked data leaving, 164.308(a)(6)(ii) and 164.308(a)(1)(ii)(D) on detections, 164.308(a)(5)(ii)(B) for blocked
  persistence. Checked against the eCFR (2026-09-24). Relevant only where ePHI is handled.
- **SOC 2 (AICPA Trust Services Criteria 2017) in the evidence export** (mapping version `2026.09.9`): CC7.2 on every
  entry, CC7.3 on detections, CC6.1/CC6.3 for tool policy, CC6.6 for injections in outside content, CC6.7 for blocked
  data movement, CC6.8 for blocked persistence, C1.1 for secrets and personal data. Criterion IDs checked against the
  AICPA's 2022 revised edition; descriptions are GuardLayer's own.
- **ISO/IEC 27001:2022 Annex A in the evidence export** (mapping version `2026.09.8`): A.8.15 Logging and A.8.16
  Monitoring activities on every entry, A.5.33 Protection of records when the log verifies, A.8.11 Data masking and
  A.5.34 for redacted PII, A.8.12 Data leakage prevention for blocked egress and output leaks, A.5.15 Access control for
  tool policy, A.8.3 for credential files, A.8.23 Web filtering for egress rules. No input-validation or human-oversight
  claim: the 2022 Annex A has no such control.
- **NIST CSF 2.0 in the evidence export** (mapping version `2026.09.7`): PR.PS-04 and DE.CM-09 on every entry,
  PR.DS-01 when the log verifies, PR.AA-05 for tool policy, PR.DS-02 for data leaving (egress rules, session taint),
  PR.DS-10 for secrets and personal data redacted before the model, PR.PS-05 for blocked persistence, DE.AE-06 for
  reviews. Subcategory text from NIST's CSF 2.0 export, matched exactly.
- **NIST SP 800-53 Rev. 5.2.0 in the evidence export** (mapping version `2026.09.6`), titles from NIST's OSCAL catalog:
  AU-2/AU-3/AU-12 on every entry; AU-9 and AU-9(3) only when the hash chain verifies and AU-10 (non-repudiation) only when
  Ed25519 signatures verify; SI-4 on detections; SI-10 input validation; SI-15 output filtering; AC-3/AC-6 for tool
  policy; AC-4 for session taint and secrets leaving; SC-7 for egress rules and SC-7(5) when an allow-list blocks; SC-5
  for size limits. AC-3(2) dual authorization is deliberately not claimed for single-approver reviews.
- **ETSI EN 304 223 V2.1.1 in the evidence export** (mapping version `2026.09.5`): the European Standard (2025-12) that
  supersedes ETSI TS 104 223. It renumbers the UK Code's provisions (5.4.2-1/-2 logging and analysis, 5.1.4-1/-3 human
  oversight, 5.1.2-6 permissions, 5.2.1-4 and 5.2.1-4.1 sensitive data and input checks) and adds 5.1.2-2 (withstanding
  adversarial attacks), mapped to blocked injections and jailbreaks. Provision numbers only, checked against ETSI's PDF.
- **UK Code of Practice for the Cyber Security of AI (2025) in the evidence export** (mapping version `2026.09.4`,
  Open Government Licence v3.0): 12.1 logging, 12.2 behaviour analysis, 4.1/4.3 human oversight, 2.6 least-privilege
  permissions for the AI system, 5.4 sensitive data, 5.4.1 input checks and sanitisation.
- **MITRE ATLAS mitigations and OWASP AISVS 1.0 in the evidence export** (mapping version `2026.09.3`). ATLAS
  mitigations (v2026.09): M0020, M0024, M0028, M0029, M0030, M0033, M0036. AISVS 1.0: C2.1.2–C2.1.8, C7.3.2–C7.3.4,
  C9.2.1, C9.3.5, C9.5.1/C9.5.3/C9.5.4, C12.1.2, C12.2.1, C12.2.3. Human-in-the-loop mappings apply only to reviews of
  agent tool calls. IDs verified against the official sources; AISVS descriptions are GuardLayer's own.
- **Two more held-out datasets** in `benchmarks/public_eval.py`: Lakera's Gandalf injections (1,000, recall 0.57) and SPML
  (16,011 prompts: precision 1.00, recall 0.21, no false positives on 3,470 benign prompts). Downloads are now atomic, retry
  with back-off, and skip empty rows.
- `benchmarks/agentdojo_eval.py`: GuardLayer as a defense on AgentDojo (ETH Zurich's third-party agent benchmark), with a local model;
  `guardlayer-untrusted` defense (every tool result untrusted), `--max-iters`, and the GuardLayer commit recorded with each result.
  **Results** (qwen2.5-coder 7B, banking and Slack, 10 attacks each): attacks succeeded 7 → 6 (banking) and 4 → 3 (Slack) with 0.5.0,
  and 0 / 10 in both after the detection rules below, **measured after seeing the attacks**. Benign utility drops by 2 of 10 tasks per
  suite; in banking, legitimate payments to an IBAN were blocked as personal data leaving the machine (the tools are untagged).
- **Detection rules from AgentDojo's attack families**: typo-tolerant "ignore previous instructions", content addressed to "the AI",
  instructions posed as a precondition of the user's task, fake system markers in content. 4 of AgentDojo's 5 families detected
  at text level (was 1); no false positives on 4,509 benign prompts and 1,006 benign AgentDojo environment texts.
- **Agentic evaluation** (`benchmarks/agentic_eval.py`): 30 injection attacks (5 attacker goals x 3 injection styles) and 8
  benign tasks in a simulated workspace, run by a real model through Ollama or by a scripted worst-case agent that obeys every
  injection. Scores executed actions (hijacked / succeeded / utility / approvals asked), with and without GuardLayer, with
  reviews denied or rubber-stamped. The scripted suite runs in CI (`tests/test_agentic_scripted.py`).

### Fixed
- **Prefixed secret names weren't redacted.** The generic assignment rule needed a word boundary before the name, so the usual
  `.env` forms (`DB_PASSWORD=`, `POSTGRES_PASSWORD=`, `AWS_SECRET_ACCESS_KEY=`, `GITHUB_TOKEN=`) were missed and could be sent out.
  Found by the agentic evaluation: it was the only way a secret leaked when every review was rubber-stamped.
- **GuardLayer's own redaction marker was re-flagged as a secret** (`DB_PASSWORD=[REDACTED:GENERIC_SECRET]`), so an agent
  forwarding redacted text raised a redundant `secret_in_egress` review.
- **`read_email`-style tools were inferred as network-capable**, so reading a mailbox after PII had entered the session raised a
  false `trifecta` review (5 approval requests on 8 benign tasks in the agentic evaluation, down to 1). Read verbs on messaging
  nouns (email, mail, inbox, slack, sms, message) now infer `read` only; their results still count as untrusted. URL, web and API
  tools keep `network`, and `webpage`/`website`/`uri` names now infer `network` too (`get_webpage(url)` can carry data out).
- **Similarity scanner coverage of long texts.** Its window budget stopped at the first 64 windows (about 4,000 characters), so
  a known attack in the middle or at the end of a long page or document was never compared. Windows are now spread across the
  whole text (overlapping by one sentence), and the default budget is 256. On known attacks inserted at five positions in
  benign documents, similarity-layer recall went from 45/75 to 75/75 at 8,000 characters, 27/75 to 72/75 at 20,000 and 15/75
  to 58/75 at 48,000. Costs up to ~80 ms more on the longest inputs. Public benchmark results are unchanged.

### Changed
- README speed claim corrected from "~1 ms per scan" to measured figures: ~1.4 ms for a 200-character prompt, ~0.2 ms for a
  shell tool call, and roughly 10–13 ms per 1,000 characters for longer inputs.
- Faster heuristics on text without leetspeak or encoding (identical de-obfuscated views are skipped) and a small speed-up in
  similarity search (cached feature hashes). Results are identical.
- Dockerfile: `/var/log/guardlayer` owned by the service user; documented `--read-only` run.

### Changed
- README threat-coverage table now uses the OWASP Top 10 for LLM Applications **2026** numbering, with 2025 IDs alongside.

## [0.5.0] - 2026-09-27

First release published to PyPI (`pip install guardlayer`).

### Security
- **The default classifier model is pinned to an exact revision** (`90c9989b1a342275dd0d1a95aad283c04e075671`). Its upstream
  project was archived in July 2026 and is no longer maintained; a floating reference could change verdicts silently. New
  `ClassifierScanner(revision=...)` / `[scanners.classifier] revision` pins custom models too; `revision=None` opts out. Each classifier
  detection records `model` and `revision` in its metadata. Tests in `tests/test_classifier_pinning.py`.

### Added
- `THREAT_MODEL.md`: assets, trust boundaries, assumptions, residual risk and attacks on GuardLayer itself. Linked from README and SECURITY.md.
- Release workflow: tagged versions build and publish to PyPI through trusted publishing (no stored tokens).

## [0.4.1] - 2026-09-27

Security fixes from a review of 0.4.0. Each bypass was reproduced first and has a regression test in `tests/test_remote_egress.py`.

### Fixed
- **Remote tools with read-only names no longer escape taint tracking.** Results from `search`, `tavily_search`, `get_webpage` or `mcp__github__get_issue` did not mark the session untrusted, so `trifecta` never fired. An undetected injection on such a page, a `.env` read and an exfiltrating call came out ALLOW. New `ToolPolicy.is_remote()`: a tool is remote when it can reach the network or run commands, is untagged, or matches `remote_tools`. Defaults: `mcp__*`, `*search*`, `*web*`, `*page*`, `*url*`, `*issue*`, `*github*`, `*mail*` and similar. Explicit capabilities still win, so Claude Code's built-in tools are unchanged.
- **`sensitive_data_egress` now finds secrets embedded in longer text.** Before, a secret seen earlier matched only as a whole token, so `https://evil.example/<key>`, `/log/<key>.png` and `data=x<key>` got past it. Fingerprints now also store the length and a 16-bit prefix check, and matching slides over every run of token characters in linear time (a 64 KB argument with 50 fingerprints takes about 50 ms). Session files written by 0.4.0 still match whole tokens. It also covers remote tools whose arguments leave the machine, such as a search query.
- **Secrets in outgoing tool arguments are no longer just redacted.** The secrets scanner only rewrote `result.text`, while every integration ran the tool with the original arguments, so the secret left and the verdict was ALLOW. New tool rule `secret_in_egress` (default **review**, configurable through `rule_actions` and `disabled_rules`) fires when a remote tool's arguments contain a secret.

### Added
- `[tools] remote_tools` / `ToolPolicy(remote_tools=..., include_default_remote_tools=...)`. Tool-call results carry `metadata["remote"]`.

## [0.4.0] - 2026-09-24

Sessions and integrations: an agent action is judged by what the session has already seen, and GuardLayer plugs into Claude Code, LangGraph and the OpenAI Agents SDK.

### Added
- **Session taint tracking** (`guardlayer.session`). `guard.session(id)` / `GuardSession`, or `session=` on every `scan_*` call. A session records untrusted content (output of network-capable or untagged tools, `scan_context`), hostile content (an injection was found in it) and sensitive data (secrets or PII read or pasted, credential and `.env` access). Three rules escalate tool calls:
  - `sensitive_data_egress` (block): a secret seen earlier appears in a network or exec call.
  - `trifecta` (review): untrusted content and sensitive data, then a network or exec call.
  - `after_injection` (review): an injection was read, then a write, network or exec call.
- Sensitive values are kept only as truncated SHA-256 fingerprints.
- **`SessionPolicy`**: `trusted_tools`, `untrusted_tools`, per-rule `actions`, `enabled`.
- **Session stores**: `MemorySessionStore` (LRU plus idle timeout) and `FileSessionStore`. `FileSessionStore` uses a per-session lock file, atomic replace and merge-on-write, so parallel processes never lose taint, including on Windows.
- **Claude Code hook**: `guardlayer hook claude-code` handles PreToolUse, PostToolUse and UserPromptSubmit. It returns `deny` or `ask` (never `allow`), flags injected tool output to Claude, tags Claude Code's built-in tools, checks only the target path of Write/Edit, and keeps file-backed sessions keyed by `session_id`. It fails open, or closed with `fail_closed`. `--print-config` prints the settings.json snippet.
- **LangGraph / LangChain**: `guard_tools(guard, tools)`. A REVIEW verdict becomes `interrupt()`, which you resume with `Command(resume=True)`. The graph's `thread_id` becomes the session.
- **OpenAI Agents SDK**: `guardrails(guard)` returns input, output, tool-input and tool-output guardrails. The session comes from the run context's `session_id`.
- **`guard_tool`**: wraps any sync or async tool function with a pre-call check and a post-call result scan, a refusal or `ToolBlocked`, an `approve` callback for REVIEW, and output withholding.
- **Config**: a `[session]` section (`store`, `dir`, `ttl_seconds`, `max_sessions`, `trusted_tools`, `untrusted_tools`, `actions`, `enabled`) and a `GUARDLAYER_STATE_DIR` env var. `strict` blocks `after_injection`; `airgap` also blocks `trifecta`.
- **REST**: `session_id` on the scan endpoints, `POST /v1/scan/tool-result`, `GET` / `DELETE /v1/sessions/{id}`.
- **Capabilities**: `ToolPolicy.resolve()` and `can_act()`. An explicit empty capability list marks a tool as harmless.
- New extras: `langgraph` and `openai-agents`. A new CI job runs the integration tests with both frameworks installed.

### Changed
- `scan_tool_call` skips the content scanners for tools tagged read-only, whose arguments cannot cause harm (for example, a search for "rm -rf"). Pass `scan_content=True` to force the scan.
- `asyncio` is imported lazily, cutting import time by about 35%.

## [0.3.0] - 2026-09-24

"Agent Guard": GuardLayer now governs what an agent is about to *do*, not just what text says.

### Added
- **Tool-call policy** (`guardlayer.tools.ToolPolicy`, used by `scan_tool_call`). Tools carry `read` / `write` / `network` / `exec` capabilities, set explicitly (glob patterns allowed) or inferred from the tool name. Adds allow- and deny-lists with globs, per-capability actions (`capability_actions={"exec": "review"}`), custom `ToolRule`s, `rule_actions` overrides and `disabled_rules`. About 0.1 ms per call.
- **Built-in tool rules**: `destructive_command` (block), `risky_command` (review), `persistence` (review), `credential_file` (block) and `dotenv_file` (review).
- **Egress control** for network- and exec-capable tools: `egress_metadata_endpoint` (block), `egress_exfil_service` for tunnels, request catchers, OAST and file drops (block), `egress_not_allowed` against `egress_allowlist` (block) and `egress_raw_ip` for public IPs (flag). Private and loopback addresses are not egress.
- **`REVIEW` verdict and action**: hold an action until a human approves it. Verdicts are ordered ALLOW < FLAG < REVIEW < BLOCK, and `ScanResult.needs_review` is new.
- **`Detection.action`**: a rule can carry its own action, which takes precedence over the category action.
- **Observe (shadow) mode**: `Policy(mode="observe")`, plus per-rule `observe` / `enforce` glob lists. Results gain `shadow_verdict`, `observed_rules` and `effective_verdict`. Observed detections are neither enforced nor redacted, but they still count toward `score`.
- **Presets** (`guardlayer.presets`): `observe`, `balanced`, `strict` and `airgap`, each with a stated residual risk. Available through `GuardLayer.from_preset()`, `preset = "..."` in config, `--preset` on the CLI or `GUARDLAYER_PRESET`.
- **Tamper-evident audit log**: `AuditLogger` hash-chains entries (`seq`, `prev_hash`, `entry_hash`), continues an existing chain on restart and can sign entries with Ed25519 (`signer=`, new `signing` extra). `verify_audit_log()` reports the first bad line and the head hash. It takes an `expected_head` to catch truncation.
- **Config**: `[tools]` section (`allowlist`, `denylist`, `capabilities`, `capability_actions`, `rules`, `rules_file`, `rule_actions`, `disabled_rules`, `egress_allowlist`), `[audit]` section, `[guard] mode/observe/enforce`, and a `GUARDLAYER_MODE` env var.
- **CLI**: `tool-call`, `presets`, `audit verify`, `audit keygen`, `--preset`, and `review` as a `--fail-on` level. `rules` now lists the tool rules too.
- **REST**: `/v1/scan/tool-call` accepts `metadata` and returns capabilities. `/v1/settings` reports the preset, mode and tool policy.

### Changed
- `ScanResult.allowed` is now false for REVIEW as well as BLOCK, and `@guard.protect` stops on either.
- `AuditLogger` filters on `effective_verdict`, so observe-mode results that would have been blocked are still logged. Chaining is on by default. An existing unchained log file must be replaced with a new file.
- `[guard] tool_allowlist` moved to `[tools] allowlist`. The old key still works.
- `examples/agent_tools.py` shows block, review and allow, and writes a verifiable audit log. It also no longer crashes on Windows consoles.

### Also in this release (previously unreleased)
- `benchmarks/public_eval.py`: a reproducible benchmark on deepset/prompt-injections and jackhhao/jailbreak-classification. Results are in the README.
- 10 more heuristic rules (47 total): `forget_everything`, `change_instructions`, `new_instructions_follow`, `prompt_beginning`, instruction override / new-instruction / prompt-extraction rules for German, Spanish, French, Portuguese, Italian, Dutch, Russian and Croatian/Serbian, `unethical_ai_persona`, `has_no_rules` and `jailbreak_marker`.

#### Changed
- The override rule now also covers orders, tasks, assignments and information. `disable_safety` also covers "OpenAI/Anthropic/company policy".
- The similarity search uses an inverted index for sparse vectors, which is about 2x faster on long prompts with identical results.
- Held-out recall with zero false positives: deepset 0.08 → 0.23, jailbreak-classification 0.66 → 0.72.
- `ClassifierScanner` classifies long texts in overlapping chunks (head and tail kept, up to `max_chunks`) instead of truncating at 512 tokens, so an injection at the end of a long document is still seen.
- `benchmarks/public_eval.py` gains `--classifier`, `--classifier-only`, `--threshold` and `--splits`, and scans each sample only once.
- The README benchmark table covers the classifier: deepset held-out recall 0.23 (rules) → 0.47 (rules + classifier), with precision still 1.00.

#### Fixed
- `load_samples` and `guardlayer batch` no longer split JSONL records on Unicode line separators (U+2028, U+0085) inside strings.

## [0.2.0] - 2026-09-23

A rebuild from a single-detector prototype into a complete input/output guard layer.

### Added
- **Three directions**: `scan_input`, `scan_output` and `scan_context` (indirect injection through RAG chunks, web pages and tool results).
- **Policy engine** (`Policy`, `Action`): per-category and per-direction actions (`score` / `block` / `flag` / `redact` / `log`), fail-open or fail-closed on scanner errors, a configurable redaction format.
- **Sanitized output**: `ScanResult.text` has redactions applied, and `ScanResult.modified` marks when that happened.
- **Scanners**: `ObfuscationScanner`, `SimilarityScanner` (with a dependency-free vector store and auto-learning), `SecretsScanner`, `PIIScanner` (Luhn / mod-97 / Verhoeff validation), `CanaryScanner`, `PromptLeakScanner`, `LinkScanner`, `LimitsScanner`, `DenyListScanner`, `ClassifierScanner` (optional), `LLMJudgeScanner`, `RelevanceScanner` (optional).
- **Heuristics**: expanded to 37 rules with categories and direction scoping. Every rule also runs against de-obfuscated views (homoglyphs, leetspeak, spaced letters, zero-width characters, Unicode-tag smuggling, base64/hex/percent/rot13 payloads). Custom rule packs load from JSON or TOML.
- **Canary tokens** for leak detection and goal-hijack (echo) detection.
- **Agent support**: `scan_tool_call` with a tool allow-list, and `scan_tool_result`.
- **`@guard.protect`** decorator for sync and async LLM calls, plus `GuardBlocked`.
- **Async API** (`ascan`, `ascan_input`, `ascan_output`, `ascan_context`), hooks, and `AuditLogger` (JSONL that stores text hashes by default).
- **Configuration** from TOML/JSON with environment-variable overrides (`GuardLayer.from_config`).
- **Evaluation harness** (`guardlayer eval`) and a bundled labelled sample.
- **CLI**: `scan`, `batch`, `eval`, `canary`, `rules`, `serve`, `--config` and `--fail-on`.
- **REST API** v1: input, output, context, batch, tool-call, canary, corpus and settings endpoints, with optional API-key auth.
- Dockerfile, a CI matrix covering Python 3.10–3.13 and Windows, a core-only install smoke test, a package build, and examples.

### Changed
- The `Scanner` protocol is now `scan(text, context: ScanContext)` and scanners declare `directions`.
- `Detection` gains `category` and `metadata`. `ScanResult` gains `id`, `timestamp`, `text`, `modified`, `latency_ms`, `timings_ms`, `errors` and `metadata`.
- Aggregation counts each rule once, so repeated hits no longer inflate the score.

## [0.1.0] - 2026-09-12
- Initial release: heuristic scanner, noisy-or pipeline, CLI and a minimal REST API.
