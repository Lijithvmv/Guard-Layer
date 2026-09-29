# Labels: where data came from, and where it may go

Detection tries to recognise an attack in text, and a determined attacker can rephrase until it doesn't. Labels don't
depend on recognising anything. Every piece of content the agent reads gets a **label**, the session keeps the most
restrictive label of everything it has read, and each tool call is checked against it: *may content from there drive
this tool, and may data this sensitive reach it?* The answer is decided in code, whatever the model was told.

## The two axes

| Axis | Levels (low → high) | Meaning |
|---|---|---|
| **Integrity** | `trusted` → `untrusted` → `hostile` | who could have written it; `hostile` means an injection was *detected* in it |
| **Confidentiality** | `public` → `private` → `restricted` | how bad a leak would be; `restricted` means credentials, secrets or personal data |

Labels combine **most-restrictive-wins**: a session that has read one untrusted web page and one private customer record
is `untrusted` + `private`. Check it with `session.state.label`; every tool-call result and audit entry records it.

## Where labels come from

- **Capabilities** (the default): results of network, exec, remote or unknown tools are `untrusted`.
- **Detections**: a secret or personal data raises confidentiality to `restricted`; a detected injection makes integrity
  `hostile`.
- **Your declarations**, for what capabilities can't know:

```toml
[labels.sources]
get_customer = { confidentiality = "private" }     # business data, not a "secret" pattern
read_issue   = { integrity = "untrusted" }          # outsiders write issues
internal_kb  = { integrity = "trusted" }            # a vetted internal service
```

Declarations only raise a label; detections can raise it further.

!!! warning "Local data is trusted by default"
    Results of local, read-only tools (files, databases) count as `trusted` unless you say otherwise. If outsiders can
    write that data (repositories, shared drives, tickets, uploads), set `default_integrity = "untrusted"` in `[labels]`:
    every undeclared tool result then counts as untrusted. This default may change in a future release; run
    [`guardlayer policy check`](#check-your-configuration) to see what is assumed today.

## What tools accept

Tools that act can declare what they are willing to run with:

```toml
[labels.sinks]
post_comment = { max_confidentiality = "public" }     # a public channel: nothing private may reach it
write_file   = { accepts_untrusted = false }          # untrusted content must not drive it
send_money   = { accepts_untrusted = false }
```

| Rule | Fires when | Default action |
|---|---|---|
| `confidentiality_exceeds_sink` | the session holds data more sensitive than the tool's `max_confidentiality` | review |
| `untrusted_to_protected_sink` | the session has read untrusted (or hostile) content and the tool has `accepts_untrusted = false` | review |

These add to the session rules you already have (`sensitive_data_egress`, `trifecta`, `after_injection`); change any
action in `[session] actions`.

## Exact destinations and argument values

Allowing a domain allows everything on it. Argument rules say *which* values a tool may take:

```toml
[[tools.arguments]]
tool = "http_post"
argument = "url"
allow = ["https://api.github.com/repos/myorg/*"]     # our repositories, not someone's gist

[[tools.arguments]]
tool = "send_email"
argument = "to"
allow = ["*@mycompany.com", "*@partner.example"]
action = "review"                                    # or "block"
```

Values are matched case-insensitively as globs; recipient lists are checked one address at a time
(`"Asha <asha@mycompany.com>, b@outside.example"`), and nested arguments are found. `deny = [...]` works the same way.

**Destinations** let some values receive more sensitive data than the tool's cap:

```toml
[labels]
sinks = { send_email = { max_confidentiality = "public" } }
destinations = [{ tool = "send_email", argument = "to", match = "*@mycompany.com", max_confidentiality = "private" }]
```

Internal recipients may get private data; one outside address in the same email caps the whole call at `public`.

## Files keep their label

An agent could write a script while reading an untrusted page, then run it with a command that looks harmless. So a file
written while the session's label is above `trusted`/`public` **keeps that label**:

- a later call that mentions the file (reading, uploading or running it) raises the caller's label to it, **in any
  session**, including a new one the next day;
- running a file written in an untrusted context needs review (`untrusted_file_executed`).

A write that needed approval is recorded only after it actually ran (the Claude Code hook and `guard_tool` report it;
elsewhere call `guard.record_written(tool, arguments, session=...)`). File labels live next to the session state: a
`file-labels.json` beside on-disk sessions, in memory otherwise.

## Disguised copies of secrets

Secrets the session has seen are remembered as fingerprints, never in the clear. An outgoing call is checked for the
secret as-is, with separators removed (`s k - p r o j ...`), and in base64, base64url, hex and URL-encoded form. Any of
those blocks the call (`sensitive_data_egress`), even when nothing untrusted was read. Paraphrased or summarised
*information* can't be fingerprinted; confidentiality labels cover that case instead.

## Images, PDFs and other non-text content

Tool results that are bytes, or MCP content blocks with images, audio or embedded files, aren't scanned as if they were
text. Readable formats are extracted and scanned like any other content: PDFs with `pip install "guardlayer[extract]"`,
images by OCR with `pip install "guardlayer[ocr]"` plus the Tesseract program. Add your own extractor with
`guard.extractors.append(fn)`, where `fn(data: bytes, mime: str) -> str | None`.

Whatever can't be read (audio, video, binaries, images without OCR) is recorded as `unreadable_content` and makes the
session **untrusted**, unless the tool is declared trusted. An instruction hidden in an image nobody could read still
can't drive a protected action or carry private data out.

## Check your configuration

```bash
guardlayer --config guardlayer.toml policy check                 # every tool named in the config
guardlayer --config guardlayer.toml policy check --tools send_email read_file
guardlayer policy check --claude-code                            # Claude Code's built-in tools
```

For each tool it shows its capabilities (declared, inferred or unknown), what its output counts as, what it accepts as
a sink, and whether its egress is limited, then warns about gaps: unknown capabilities, unlimited egress, output assumed
trusted, private data declared but sinks uncapped, network tools marked trusted, failing open. `--strict` exits 1 on any
warning, for CI; `--json` is for tooling.

## Claude Code

The hook labels shell output (`BashOutput`) and sub-agent reports (`Task`, `Agent`) as untrusted, scans them, and
reports writes so file labels work across sessions. Your `[labels] sources` win over these defaults.
