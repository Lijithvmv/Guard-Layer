# Roll out without breaking anything

A security layer that blocks real users on day one gets switched off on day two. Measure first, enforce second.

## 1. Observe

```toml
# guardlayer.toml
preset = "observe"

[audit]
path = "guardlayer-audit.jsonl"
min_verdict = "flag"        # observe mode logs what enforcement *would* have done
```

Nothing is blocked, held or redacted. Every result carries a `shadow_verdict`, and the audit log records it.

## 2. Look at what would have happened

```bash
guardlayer audit report guardlayer-audit.jsonl --since-days 1   # by rule, by tool, latest; "(observed)" = would have fired
guardlayer evidence export guardlayer-audit.jsonl               # the same log as control-mapped evidence
```

Or read the log directly: each line has `verdict`, `shadow_verdict`, `observed_rules`, `categories` and `direction`. Look
for rules that would have fired on legitimate traffic. For each, decide: tune it, observe it longer, or accept it.

## 3. Enforce step by step

```toml
[guard]
mode = "enforce"
observe = ["egress_raw_ip", "from_now_on"]     # rules still too noisy for your traffic: keep observing them
```

or the other way round, enforcing only what you trust so far:

```toml
[guard]
mode = "observe"
enforce = ["secret", "tool_policy:*"]           # redact secrets and enforce the tool policy; observe the rest
```

## 4. Move to your target posture

Switch to `balanced` for most apps, `strict` for agents with real credentials or production access. Re-run step 2 after
every change of preset, rules or model.

!!! tip "Keep the evidence"
    The same audit log that drives rollout decisions is the evidence an auditor asks for later. Sign it
    (`signing_key`) from the start.
