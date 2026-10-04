# Judging an action by its consequence

> **In one paragraph:** a hijacked agent only does harm when one of its actions crosses a line it can't come back
> from: data leaves to someone, something is published, money moves, access changes, files are destroyed. Before that
> line, nothing has harmed anyone yet. So GuardLayer doesn't ask "is this session tainted?" and hold everything. It
> asks **what this action would do to the world**, and for the actions that cross the line, **what they carry and to
> whom**. Local work (editing, building, testing) keeps running.

## Why not hold everything after something suspicious is read?

Because almost everything an agent does is local and recoverable, and holding it all teaches people to approve
without reading. Replaying 12 real Claude Code sessions (7,572 tool calls) through the earlier, session-wide rules,
about **70% of all calls** were held; about two thirds of those were edits, writes and tests, and the sessions held no
attack at all. On sessions from other projects, never used to design the rules (6,962 calls), it was 76%.

At the same time, in recorded [AgentDojo](../evaluation.md#agentdojo) runs, every attack that got past detection did
its harm through an action that was either **irreversible** (a payment, a password change, a booking) or **sent
something to a place named in the injected text** (the attacker's account number, URL or address).

## The three classes

| Class | Examples | After the agent read untrusted content |
|---|---|---|
| **local** | edit or write a file, build, run tests | runs |
| **outbound** | send a message, fetch a URL, post to an API | held only if it sends something private to a place an outsider named (below) |
| **irreversible** | delete, rewrite history, publish (`git push`, `npm publish`), pay, book, change a password or access | held when an injection was detected, when the session also holds secrets, or when an outsider chose its destination or its object (the file to delete, the hotel to book) |

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

## The destination check: where it goes, and what it carries

On by default (`[session] untrusted_destination = "outbound"`). It needs no injection detection: an attacker who
writes text no detector recognises still has to tell the agent *where* to send things, and the agent read that
place in content an outsider could write.

An outbound action is held when both are true:

1. **Its destination was named by an outsider, not by you.** A plain name counts as much as a URL: if a web page
   says "send the summary to Fred" and you never mentioned Fred, a message to Fred is a candidate; a message to the
   colleague you named is not. Places are compared by what they name: `https://www.site.net/x` and `site.net/x` are
   one place, and an address hidden in base64, hex, HTML entities, invisible characters or look-alike letters is read
   the way the agent would read it.
2. **It carries something private.** A body, message or other argument, or a word in the URL that appears neither in
   the outsider's content nor in your own messages. Following a link, or opening a file a repository page listed,
   tells the outsider nothing they didn't write, so it runs. Appending your contacts or a file's contents to their URL
   does not.

Two more rules keep it honest:

- **This machine is not an outsider's place.** `localhost`, `127.0.0.1`, `*.localhost` and `file:` are never held by
  this check: data sent there doesn't leave.
- **A copy can't launder an address.** If the agent writes an outsider's address into a file and reads it back, the
  read counts as untrusted, because the file was written after untrusted content was read. A file you already had
  still vouches for what it names.

The hold message names the recipient and the source ("sends to 'fred', which came from tool:read_email"), so
approving or refusing takes seconds.

## Private data and public places

The destination check doesn't cover private data sent to a place **you** named that others can read: your public
channel, a gist, an issue. For that, declare which sources are private and which places are public
([labels](labels.md)). A call to a public place is then held when it carries the private source's identifiers (IDs,
numbers, addresses), names, or a six-word run copied from it, and not merely because something private was read
earlier ("Done." still posts).

## Credentials

A credential the agent fetches is judged by where it goes: kept in a shell variable and used only toward its own
service (a GitHub token sent to `api.github.com`) runs; printed into the conversation, written to a file, or sent to
any other host is blocked.

## What it costs (measured)

- **Interruptions:** on real Claude Code sessions, today's defaults (the destination check, and trust only for
  declared tools) added **1 hold in 7,572 calls** on the sessions used to design them, and **none in 6,962 calls**
  from other projects never used for design. On AgentDojo's tasks, nearly all of which pay or
  send right after reading untrusted content, the defaults hold about one task in four for approval.
- **Time:** GuardLayer's handling of a 4 KB tool result is ~48 ms (about 11 ms of it this check) and of a tool call
  ~5 ms, on an idle laptop.

## What it stops, and what it does not (measured)

On AgentDojo's published runs for five frontier models (Claude 3.7 Sonnet, Claude 3.5 Sonnet, GPT-4o, Gemini 2.0
Flash, Llama 3.3 70B; the `important_instructions` attack, no defense): 707 attacks that succeeded, and 644 ordinary
tasks. "Detectors removed" stands in for an attacker whose wording no detector recognises.

| | Attacks stopped | Ordinary tasks interrupted |
|---|---|---|
| detectors on (defaults) | 674 / 707 (95%) | 173 / 644 |
| detectors removed, destination check off, name-based trust (before 0.9) | 308 / 707 (44%) | 78 / 644 |
| detectors removed, **defaults** | **648 / 707 (92%)** | 173 / 644 |

Read the detectors-removed rows: the detectors-on row flatters, since these are published attack templates the
similarity detector can know. The plainest attack in the set (`direct`: the attacker's goal written as an ordinary
instruction) shows why. The detectors catch 9 of 23 on GPT-4o and 8 of 34 on Llama 3.3; the defaults stop 22 of 23
and 32 of 34, because they don't depend on how the instruction is worded.

**Which results count as outsider content.** A tool's result is trusted only when its capabilities were declared
(by you, or by an integration for its own tools, as Claude Code's Read, Grep and Glob are) or you named it in
`trusted_tools` or `[labels] sources`, and it is local. A name can't establish trust: `read_file` on a shared drive,
`get_channels`, a calendar, transactions or reviews carry text other people wrote; in these runs they delivered most
of the injections that name-based trust let through. `[labels] default_integrity = "trusted"` restores name-based
trust; `"untrusted"` distrusts every result.

AgentDojo's ordinary tasks nearly all pay, send or book right after reading such content, so one in four is held for
approval; on the real Claude Code sessions above these defaults added 1 hold in 14,534 calls.

Not covered:

- **Actions with no destination, and values the agent works out itself.** A password change, or "book the most
  expensive hotel", names no outsider's place. Only an irreversible action is held, and only when an injection was
  detected or secrets are present. In experiments a local model asked "did the user request this?" (shown only your
  messages and the action) closed this on AgentDojo, but on real sessions a 7B model refused 91% of actions it was
  asked about, so it is not part of GuardLayer.
- **Visiting an outsider's page.** It carries nothing private, so it runs. On the frontier-model runs this "visit the
  phishing link" goal is most of what remains when every tool result is treated as untrusted.
- **An address the agent has to rebuild:** spelled out ("site dot net"), reversed, split across sentences, or another
  subdomain of the same site. Matching covers copying, not transformation.
- **Paraphrase:** private data rewritten in new words isn't recognised when it goes to a public place.
- **Evidence limits:** recorded runs of one published attack family; no adaptive attacker has been run against these
  rules beyond the cases above.

## Where this comes from

Controlling information flow at the action boundary is established research; systems built on it usually rewrite
the agent's planner or run it in a separate interpreter. GuardLayer applies the idea to an agent it doesn't control
(through hooks), judges an action by what it carries rather than by whether the session was ever exposed, and
publishes the measured cost on real work above.

Settings: `[session] untrusted_destination` (`"outbound"` default, `"irreversible"`, `"off"`),
`after_injection_scope` and `trifecta_scope` (`"all"` restores the session-wide behaviour, as the `strict` and
`airgap` presets do), and per-tool `consequence` / `destination_args`.
