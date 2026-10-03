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

GuardLayer remembers, as hashes (keyed for phrases; see SECURITY.md), the identifiers and short phrases it saw in content from outside and in your
own messages. When an action is about to leave the machine, it asks one question of its destination arguments: **did
this value come from content an outsider could write, and never from you?** A plain name counts as much as a URL:
if a web page says "send the summary to Fred" and you never mentioned Fred, a message to Fred is held; a message to
the colleague you named runs.

What matters is what the action **carries** to that place. Opening a page at an address built only from words the
outsider wrote, or that you typed (following a link, opening a file a repository page listed), tells them nothing,
so it runs. Appending anything else to their URL (your contacts, a file's contents) or sending a body, message or
other argument to them is held. Replaying one research session (297 calls, mostly reading GitHub pages), this took
the check from 58 holds to 0, while the recorded attacks it stops stayed the same.

## Credentials

A credential the agent fetches is judged by where it goes: kept in a shell variable and used only toward its own
service (a GitHub token sent to `api.github.com`) runs; printed into the conversation, written to a file, or sent to
any other host is blocked.

## What this does not protect against (measured)

- **An attack nobody detects.** The rule that reacts to injected content (`after_injection`) needs a detector to
  recognise the injection. With the detectors removed (a stand-in for an attacker who evades them), the
  injection rules alone stopped **5 of 27** recorded attacks that had succeeded without a guard. The destination
  check (`[session] untrusted_destination = "outbound"`, on by default; `"off"` disables it) doesn't need detection:
  with it, the defaults stop **12 of 27**, and with every tool result treated as untrusted **19 of 27**. Its cost on
  17,316 real Claude Code calls: **2 extra holds** (one per project set), because following links and opening local
  pages carry nothing private. On AgentDojo's tasks, nearly all of which pay or send after reading untrusted content,
  it interrupts about one task in seven by default, one in four with every result untrusted.
  The two attacks it lets through only make the agent *visit* the attacker's site: a visit carries nothing private,
  so the check doesn't hold it (see below for what does).
  It compares a destination by what it names, so `https://www.site.example/x` and `site.example/x` are the same place,
  and it reads past encodings an agent undoes (base64, hex, HTML entities, invisible characters, look-alike letters).
- **An address the agent has to rebuild.** Spelled out ("site dot net"), reversed, split across sentences, or a
  different subdomain of the same site: the agent can reassemble it, but no matching can. The check covers copying,
  not transformation.
- **Actions with no destination, and values the agent works out itself.** A password change, or "book the most
  expensive hotel", carries no address copied from the injected text, so the destination check can't see it. In
  experiments, asking a local model whether each *irreversible* action matches what you asked for (the model sees
  only your messages and the action, never tool output), also asked about outbound actions that carry a link from
  untrusted content, raised the figure above to 27 of 27, interrupting about one ordinary task in three; a 7B model also refused some actions you had plainly asked for. It is not part of
  GuardLayer yet.
- **Sending your data to a place you named,** re-encoded so it doesn't match what was read.
- **Small evidence.** The attack figures come from 27 recorded attacks with known templates on one 7B model.

Settings: `[session] after_injection_scope` and `trifecta_scope` (`"all"` restores the session-wide behaviour, as the
`strict` and `airgap` presets do), `untrusted_destination`, and per-tool `consequence` / `destination_args`.
