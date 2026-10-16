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

Shell output is judged by the command that produced it: `ls`, `grep`, `pytest` or a local script read this machine's
files; `curl`, `git fetch`, `pip install` or code that can't be analysed may bring in an outsider's text. A file a
command downloads (`curl -o`, `wget -O`, a redirect, a `git clone`) keeps that origin when it is read back later. A
file the agent runs is judged by what it would execute, even after an injection was detected: a local test runner
runs, a script that reaches out is held.

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

## Actions you didn't ask for

The destination check needs a destination. Many attacks have none: delete a file, cancel a shipment, move a robot,
leave a channel. These rules judge such actions by what **you** asked for, which an attacker can't change.

- **Your request sets a ceiling (`beyond_request`, on by default).** When every message you wrote only asks to read
  or find something ("summarise this page", "what's on my calendar?", "can you recommend a hotel?"), an action that
  changes something, after the agent read outside content, goes beyond your request and is held. Any message that asks
  for an action ("pay the bill", "check my inbox and reply to Bob", "please reschedule...") lifts the ceiling for the
  rest of the session, and so does a message it can't classify: it errs towards not holding. Words that are as often
  nouns ("my latest email", "my order", "my schedule") count as requests only where a request starts.
- **A detail from a source you named is yours, for the action you asked for.** "Invite Dora; her e-mail is on
  www.dora-website.com": the address comes from the page you pointed to. A source counts as named when the call that
  read it used a URL, host, file name or e-mail address from your own message, and the content held no detected
  injection. The detail is accepted only for an action you asked for: the tool's verb (or the same kind of verb: pay
  and send, book and reserve) **and** what it acts on must be in your words. Moving money, changing a scheduled
  transaction and changing a password are always held for approval, whoever named the document: that is exactly what
  invoice fraud and account takeover look like.
- **Text and tool names are read for what they do.** Arguments sent as text (a JSON string, or a Python-style dict
  from a text-based agent) are read by their fields. A multi-purpose tool is judged by the action its arguments ask
  for: `ManageShipment {"operation": "cancel"}` is irreversible, `{"action": "list"}` is a read. Tool names written
  `LikeThis` are read word by word. Moving files out of, or changing permissions on, your home folder
  (`mv ~/Documents/... /tmp`, `chmod 777 ~/.ssh/...`) is irreversible, like deleting them.
- **A short ID is named by outside prose only where the prose points at it.** "Find and delete the largest file"
  picks file 11 from the listing; a bare 11 somewhere in a file's text doesn't make it the outsider's choice, but "the
  file with ID 13" does.
- **The outsider's text chose the action (`action_chosen_by_content`, opt-in).** A call that changes something, whose
  tool or action only outside content asked for. It stops many attacks on business agents, but on coding agents its
  first form held 7.3% of calls instead of 1.6%, so it is off by default:
  `[session.actions] action_chosen_by_content = "review"`. A tool that already ran in the session (unheld, or
  approved) doesn't count as chosen by text that names it later.

Known gaps of these rules: an attacker who controls the very page or file you named, and asks for the same kind of
action you asked for, gets through when no injection is detected; a message like "do all the tasks on my list at
&lt;URL&gt;" hands the choice to that page, so its actions are held.

## What it costs (measured)

- **Interruptions:** all rules together hold **1.7% of 6,962 calls** (121) on one developer's real Claude Code
  sessions from projects not used to design the rules (but used to check every change; replayed with tool arguments
  passed with results, as the live hook does). On another agent's real work (OpenHands resolving GitHub issues, a
  different model and framework), they held under 1% out of the box and 0.2% with its tools declared (measured before
  0.9). On AgentDojo's ordinary tasks, nearly all of which pay, send or book right after reading outside content, the
  defaults hold **57 of 644 (9%)** for approval on the five models below, and **8.5% of 2,916** on 24 other models.
- **Time:** GuardLayer's handling of a 4 KB tool result is ~48 ms (about 11 ms of it this check) and of a tool call
  ~5 ms, on an idle laptop.

## What it stops, and what it does not (measured)

On AgentDojo's published runs for five frontier models (Claude 3.7 Sonnet, Claude 3.5 Sonnet, GPT-4o, Gemini 2.0
Flash, Llama 3.3 70B; the `important_instructions` attack, no defense): 707 attacks that succeeded, and 644 ordinary
tasks. "Detectors removed" stands in for an attacker whose wording no detector recognises.

| | Attack's harmful call held | Some call in the attack held | Ordinary tasks interrupted |
|---|---|---|---|
| detectors on (defaults) | 603 / 707 (85%) | 699 / 707 (99%) | 57 / 644 |
| detectors removed, **defaults** | **538 / 707 (76%)** | 637 / 707 (90%) | 55 / 644 |

"Harmful call" here means a call carrying a value from the injected text, which misses harmful calls with short or
computed arguments (delete file 13, book the most expensive hotel). A stricter count compares each attacked run with
the same task's run without the attack: of the 673 attacks whose agent made a state-changing call it didn't make
without the attack, GuardLayer held **660** with detectors on and **623** with them removed. On AgentDojo's runs of 24
other models (never used to develop the rules): **2,303 of 2,342** and **2,165 of 2,342**. These rules were developed
on the five models' runs, so their numbers are tuned; the 24-model numbers are not, but they share the same tasks and
attacks.

Read the detectors-removed rows: the detectors-on row flatters, since these are published attack templates the
similarity detector can know. The plainest attack in the set (`direct`: the attacker's goal written as an ordinary
instruction) shows why. The detectors catch 9 of 23 on GPT-4o and 8 of 34 on Llama 3.3; the defaults stop 22 of 23
and 32 of 34, because they don't depend on how the instruction is worded.

**Which results count as outsider content.** A tool's result is trusted only when someone vouched for who writes
it: you (`output = "trusted"` on the tool, `trusted_tools`, or a source's `integrity = "trusted"`), or an
integration for its own tools (Claude Code's Read, Grep and Glob read this machine's files), and the tool is local.
Declaring a tool's capabilities says what it can do, not who writes what it returns, so it doesn't make it trusted. A name can't establish trust: `read_file` on a shared drive,
`get_channels`, a calendar, transactions or reviews carry text other people wrote; in these runs they delivered most
of the injections that name-based trust let through. `[labels] default_integrity = "trusted"` restores name-based
trust; `"untrusted"` distrusts every result.

AgentDojo's ordinary tasks nearly all pay, send or book right after reading such content; about one in eleven is held
for approval, mostly paying a bill (always confirmed) and "do the tasks on my list at a URL".

Not covered:

- **Actions with no destination, after you asked for an action.** When your request lifts the ceiling ("book a
  hotel"), a different action an injection asks for, with no destination and no copied value, isn't held unless
  `action_chosen_by_content` is on.
- **Harm that is only text.** An answer that recommends what the attacker wanted ("you must visit Riverside View
  Hotel") calls no tool; GuardLayer guards actions.
- **Visiting an outsider's page.** It carries nothing private, so it runs. On the frontier-model runs this "visit the
  phishing link" goal is most of what remains when every tool result is treated as untrusted.
- **An address the agent has to rebuild:** spelled out ("site dot net"), reversed, split across sentences, or another
  subdomain of the same site. Matching covers copying, not transformation.
- **Paraphrase:** private data rewritten in new words isn't recognised when it goes to a public place.
- **Evidence limits:** recorded runs of one published attack family; no adaptive attacker has been run against these
  rules beyond the cases above.

## Research, not in GuardLayer: a judge for what the rules can't see

We tested asking a local model about the calls the rules let through but can't judge (an irreversible action, or
an outbound one carrying an untrusted link): does this action serve the user's own task? Two findings:

- **The question matters more than the model.** Asked "did the user request this action?", a 7B and a 14B model
  both refused 84 of 92 actions on real Claude Code sessions: agents take many steps nobody named. Asked whose goal
  the action serves, the 14B model refused 31 of 87.
- **Its benefit on attacks is not demonstrated.** It stopped 27 of 27 recorded attacks where the rules alone stop 25;
  on 27 samples that difference is noise (95% intervals 88-100% and 77-98%). It also held 20 of 14,534 real calls.

Because it adds holds without a demonstrated gain, it is not part of GuardLayer. The research code is in
`guardlayer/judge.py` and the replay scripts.

## Where this comes from

Controlling information flow at the action boundary is established research; systems built on it usually rewrite
the agent's planner or run it in a separate interpreter. GuardLayer applies the idea to an agent it doesn't control
(through hooks), judges an action by what it carries rather than by whether the session was ever exposed, and
publishes the measured cost on real work above.

Settings: `[session] untrusted_destination` (`"outbound"` default, `"irreversible"`, `"off"`),
`after_injection_scope` and `trifecta_scope` (`"all"` restores the session-wide behaviour, as the `strict` and
`airgap` presets do), and per-tool `consequence` / `destination_args`.
