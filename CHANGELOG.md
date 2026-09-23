# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `benchmarks/public_eval.py`: a reproducible benchmark on deepset/prompt-injections and jackhhao/jailbreak-classification. Results are in the README.
- 10 more heuristic rules (47 total): `forget_everything`, `change_instructions`, `new_instructions_follow`, `prompt_beginning`, instruction override / new-instruction / prompt-extraction rules for German, Spanish, French, Portuguese, Italian, Dutch, Russian and Croatian/Serbian, `unethical_ai_persona`, `has_no_rules` and `jailbreak_marker`.

### Changed
- The override rule now also covers orders, tasks, assignments and information. `disable_safety` also covers "OpenAI/Anthropic/company policy".
- The similarity search uses an inverted index for sparse vectors, which is about 2x faster on long prompts with identical results.
- Held-out recall with zero false positives: deepset 0.08 → 0.23, jailbreak-classification 0.66 → 0.72.

- `ClassifierScanner` classifies long texts in overlapping chunks (head and tail kept, up to `max_chunks`) instead of truncating at 512 tokens, so an injection at the end of a long document is still seen.
- `benchmarks/public_eval.py` gains `--classifier`, `--classifier-only`, `--threshold` and `--splits`, and scans each sample only once.
- The README benchmark table covers the classifier: deepset held-out recall 0.23 (rules) → 0.47 (rules + classifier), with precision still 1.00.

### Fixed
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
