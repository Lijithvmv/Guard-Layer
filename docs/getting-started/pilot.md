# Try it on your own work: a one-week pilot

The fastest way to learn whether GuardLayer fits is to run it on the agent you already use, on real work, **without
letting it block anything**. Observe mode records what GuardLayer *would* have done; after a week you read the report
and decide what to enforce.

This page uses Claude Code as the agent, since it's the easiest to try. The same steps work for your own LangGraph or
OpenAI Agents SDK agent (see the end of the page).

## Day 0: set up (15 minutes)

**1. Install into its own environment**, the way any user would:

=== "Windows"

    ```powershell
    py -m venv C:\guardlayer-pilot
    C:\guardlayer-pilot\Scripts\pip install guardlayer
    C:\guardlayer-pilot\Scripts\guardlayer --version
    ```

=== "macOS / Linux"

    ```bash
    python3 -m venv ~/guardlayer-pilot
    ~/guardlayer-pilot/bin/pip install guardlayer
    ~/guardlayer-pilot/bin/guardlayer --version
    ```

**2. Create a pilot config** next to it, `pilot.toml`:

```toml
preset = "observe"                 # record what would happen; enforce nothing

[audit]
path = "pilot-audit.jsonl"         # relative to this file
min_verdict = "allow"              # log every decision, so the report has the full picture
```

The audit log stores hashes of text, not the text itself (unless you add `include_text = true`), so it doesn't become a
copy of your secrets.

**3. Check it behaves** before connecting it to anything:

```bash
guardlayer --config pilot.toml tool-call Bash '{"command": "pytest -q"}'     # ALLOW
guardlayer --preset balanced tool-call Bash '{"command": "rm -rf ~"}'        # BLOCK (what enforcement would do)
```

**4. Connect it to one project only.** Generate the hook settings and paste them into that project's
`.claude/settings.json`, not your user-level settings, so only this project is observed:

```bash
guardlayer --config pilot.toml hook claude-code --print-config
```

The command in the output points at your pilot environment and config. In observe mode the hook never blocks or asks;
Claude Code behaves exactly as before, apart from about a second per tool call on Windows (less on macOS and Linux).

!!! tip "Repositories full of attack samples"
    If the project is a security tool with injection strings in its tests, add `[session] trusted_tools = ["Read", "Grep"]`
    to `pilot.toml`, or every read of those files will count as hostile content.

## Days 1–7: work normally, review for five minutes a day

```bash
guardlayer audit report pilot-audit.jsonl --since-days 1
```

The report shows how many decisions were notable, what enforcement *would* have done (`(observed)`), which rules fired
on which tools, and how many results had secrets or personal data redacted. For each notable entry, put it in one of
three buckets:

| Bucket | Example | What it means |
|---|---|---|
| **Correct** | a destructive command, a secret about to leave in a web request | the rule earns its place |
| **False alarm** | a normal `git push --force` on your own branch sent to review | tune it: observe that rule longer, allow the tool, or adjust the config |
| **Unsure** | a flagged page you can't judge | keep watching |

Also note **misses**: anything you saw the agent do that you'd have wanted stopped or reviewed, but the report doesn't
show. Misses matter as much as false alarms.

Keep the log honest: `guardlayer audit verify pilot-audit.jsonl` checks nobody (including you) edited it.

## Day 7: decide what to enforce

Enforce only what had no false alarms, and keep observing the rest:

```toml
preset = "observe"

[guard]
enforce = ["secret", "tool_policy:*"]     # redact secrets and enforce the tool policy; everything else still observed
```

Run another week, then move to `balanced` (or `strict` for agents holding production credentials). See
[Roll out without breaking anything](../recipes/rollout.md) for the full sequence.

## Your own agent instead of Claude Code

```py
from guardlayer.config import build_guard
from guardlayer.integrations.langgraph import guard_tools

guard = build_guard("pilot.toml")                 # the same observe config and audit log
tools = guard_tools(guard, [search, fetch_url, run_shell])
```

For the OpenAI Agents SDK use `guardrails(guard)`, and for anything else `guard_tool` (see Integrations). The daily
report works the same way.

## What to send back

A pilot is most useful when its findings come back. Open an issue with, for each false alarm or miss:

- the **rule name** and **tool** from the report, and the decision (`block`, `review`, `flag`);
- one sentence on why it was wrong, or what should have been caught;
- the GuardLayer version (`guardlayer --version`).

Never paste secrets, customer data or full tool output. The rule name and a description are enough.

## Removing it

Delete the hook entries from the project's `.claude/settings.json` and remove the pilot environment. Session state lives
in `~/.guardlayer/sessions`; delete that folder too if you want no trace.
