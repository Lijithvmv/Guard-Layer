# What's stable

GuardLayer is pre-1.0, so anything can still change between minor versions, but not everything is equally settled.
Changes to the **core** are called out in the changelog with upgrade notes; **add-ons** are optional installs or
optional features with their own trade-offs; **experimental** features work and are tested, but haven't been used
outside tests and benchmarks yet, and may change or be removed depending on how they do in real use.

## Core

The part that protects an agent. Expect it to stay, and expect upgrade notes when it changes.

| Feature | Where |
|---|---|
| Tool-call policy: capabilities, allow and deny lists, argument rules, egress rules, built-in command rules | `scan_tool_call`, `[tool.NAME]`, `[tools]` |
| Sessions: untrusted / hostile / sensitive / private, `trifecta`, `after_injection`, `sensitive_data_egress` | `guard.session(...)`, `[session]` |
| Labels: sources, sinks, destinations, confidentiality caps | `[labels]`, `[tool.NAME]` |
| Content scanners: injection rules, obfuscation, secrets, PII, links, limits, canaries, prompt leak, similarity | `scan_input`, `scan_output`, `scan_context`, `scan_tool_result` |
| Presets and observe mode | `preset = ...`, `[guard] mode` |
| Audit log (hash-chained) and `guardlayer audit report` | `[audit]` |
| Claude Code hook and hook server; LangGraph and OpenAI Agents SDK wrappers; `guard_tool` | `guardlayer hook claude-code`, `guardlayer.integrations` |
| `guardlayer policy check` and `guardlayer policy draft` | CLI |

## Add-ons

Optional; each has a cost or a dependency, described on its page.

| Add-on | Install / switch |
|---|---|
| Signed audit logs (Ed25519) | `signing` extra |
| Compliance evidence export and control mappings | built in, loaded only when used |
| REST API | `api` extra |
| Transformer classifier (PyTorch) or ONNX runtime | `ml` or `multilingual` extra; [measured, not recommended for blocking](../recipes/multilingual.md) |
| Semantic similarity and relevance | `embeddings` extra |
| LLM judge | `LLMJudgeScanner` with your own model |

## Experimental

| Feature | Why experimental |
|---|---|
| Task profiles (`[tasks.NAME]`, `out_of_task`) | not yet used outside tests and benchmarks; the format may change |
| File labels (`untrusted_file_executed`) | not yet used outside tests and benchmarks |
| Split-instruction detection (`split_injection`) | catches only splits across two consecutive contents |
| PDF and image extraction (`extract`, `ocr` extras) | the extractor interface may change |
| Action judge (`[judge]`) | measured on real sessions with one local 14B model: an estimated 1 hold in 400 calls, 8–40 s per question; see [consequence](../concepts/consequence.md) |
| Behavioural check (`check_intent`) | flagged nothing on AgentDojo with a local 7B model; may need a stronger model, or may be removed |

Each experimental module says so in its first lines, so it shows in your editor and in the API reference.
