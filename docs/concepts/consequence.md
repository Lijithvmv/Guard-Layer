# Judging an action by its consequence

> **In one paragraph:** a hijacked agent only does harm when one of its actions crosses a line it can't come back
> from: data leaves to someone, something is published, money moves, access changes, files are destroyed. Before that
> line, nothing has harmed anyone yet. So GuardLayer doesn't ask "is this session tainted?" and hold everything; it
> asks **what this action would do to the world**, and only stops the actions that cross the line, judging them by
> where their data and destination came from. Local work (editing, building, testing) keeps running.

## Why not hold everything after something suspicious is read?

Because almost everything an agent does is local and recoverable, and holding it all teaches people to approve
without reading. Replaying 12 real Claude Code sessions (7,572 tool calls) through the earlier, session-wide rules,
about **70% of all calls** were held; about two thirds of those were edits, writes and tests, and the sessions held no
attack at all. On sessions that were never used to design the rules (9,744 calls), it was 67%.

At the same time, in recorded [AgentDojo](../evaluation.md#agentdojo) runs, every attack that got past detection did
its harm through an action that was either **irreversible** (a payment, a password change, a booking) or **carried a
value from the injected text** (the attacker's account number, URL or address).

## The three classes

| Class | Examples | What GuardLayer does after the agent read untrusted or injected content |
|---|---|---|
| **local** | edit or write a file, build, run tests | lets it run |
| **outbound** | send a message, fetch a URL, post to an API | holds it only if a destination or value in its arguments came from that content and not from you |
| **irreversible** | delete, rewrite history, publish (`git push`, `npm publish`), pay, book, change a password or access | holds it |

Shell commands are [parsed](agents.md), so the class comes from what the command actually runs (`curl … | jq` is
outbound, `rm -r build` is irreversible, `pytest` is local), not from words that appear in it.

**Declare your tools.** A tool's class is guessed from its name when you haven't declared it, and guesses miss: a
payment tool called `move_money` is guessed "outbound". Declare it:

```toml
[tool.move_money]
capabilities = ["network"]
consequence = "irreversible"
destination_args = ["payee"]     # arguments that say where things go, beyond to / recipient / url / channel / ...
```

`guardlayer policy draft` proposes these lines from your audit log, each marked for you to check.

## Where a value came from

GuardLayer remembers, as salted hashes, the identifiers and short phrases it saw in content from outside and in your
own messages. When an action is about to leave the machine, it asks one question of its destination arguments: **did
this value come from content an outsider could write, and never from you?** A plain name counts as much as a URL:
if a web page says "send the summary to Fred" and you never mentioned Fred, a message to Fred is held; a message to
the colleague you named runs.

## Credentials

A credential the agent fetches is judged by where it goes: kept in a shell variable and used only toward its own
service (a GitHub token sent to `api.github.com`) runs; printed into the conversation, written to a file, or sent to
any other host is blocked.

## What this does not protect against (measured)

- **An attack nobody detects.** The rule that reacts to injected content (`after_injection`) needs a detector to
  recognise the injection. With the detectors removed (a stand-in for an attacker who evades them), GuardLayer's
  defaults stopped **5 of 27** recorded attacks that had succeeded without a guard. The destination check
  (`[session] untrusted_destination = "outbound"`, off by default) doesn't need detection: with every tool result
  treated as untrusted it stopped **21 of 27**, at the cost of interrupting about one ordinary task in four (one in ten without it).
- **Values the agent works out itself.** "Book the most expensive hotel" produces a value that appears nowhere in the
  injected text. Only an irreversible action is held in that case; a judge that compares the action with your request
  would be needed for the rest.
- **Sending your data to a place you named,** re-encoded so it doesn't match what was read.
- **Small evidence.** The attack figures come from 27 recorded attacks with known templates on one 7B model.

Settings: `[session] after_injection_scope` and `trifecta_scope` (`"all"` restores the session-wide behaviour, as the
`strict` and `airgap` presets do), `untrusted_destination`, and per-tool `consequence` / `destination_args`.
