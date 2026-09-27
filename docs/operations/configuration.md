# Configuration

One TOML or JSON file configures everything. Load it with `GuardLayer.from_config("guardlayer.toml")`, `--config` on
the CLI, or `GUARDLAYER_CONFIG` for the REST API. A preset sets the baseline; everything in the file overrides it.

```toml
preset = "balanced"            # observe | balanced | strict | airgap

[guard]
flag_threshold = 0.4
block_threshold = 0.8
fail_closed = false            # block when a scanner errors (strict and airgap set this)
auto_learn = true              # add blocked prompts to the similarity corpus
mode = "enforce"               # or "observe": record what would happen, enforce nothing
observe = ["egress_raw_ip"]    # observe only these rules or categories (globs), even in enforce mode
enforce = []                   # keep enforcing these in observe mode

[actions]                      # category, or "direction:category" -> score | block | flag | review | redact | log
secret = "redact"
"output:pii" = "redact"
policy = "block"

[tools]                        # agent tool-call policy
allowlist = ["search", "bash", "mcp__github__*"]
denylist = ["delete_repo"]
egress_allowlist = ["api.github.com"]   # a domain covers its subdomains
remote_tools = ["kb_*"]                 # added to the defaults (mcp__*, *search*, *web*, ...)
capabilities = { run_sql = ["write"], lookup = ["read"], TodoWrite = [] }
capability_actions = { exec = "review" }
rule_actions = { egress_raw_ip = "block" }
disabled_rules = []
rules = [{ name = "no_prod", pattern = "prod-db", action = "block" }]

[session]                      # taint tracking
actions = { trifecta = "review", after_injection = "review", sensitive_data_egress = "block" }
trusted_tools = ["read_docs"]           # results never count as untrusted or hostile
untrusted_tools = ["read_email"]        # results always count as untrusted ("*" for every tool)
allow_egress = { send_money = ["iban"] } # data types a tool may send out (exempt from egress and trifecta)
store = "memory"                        # or "file", with dir = "...", for checks in separate processes
ttl_seconds = 86400

[audit]                        # tamper-evident audit log
path = "guardlayer-audit.jsonl"         # "{hostname}" and "{pid}" are filled in
min_verdict = "flag"
signing_key = "audit.key"               # optional Ed25519 key (`signing` extra)
include_text = false                    # store scanned text, not only its hash (avoid)

[scanners.heuristics]
disabled_rules = ["fake_role_header"]
rules_file = "my_rules.toml"

[scanners.similarity]
threshold = 0.55
corpus_file = "attacks.txt"
max_windows = 256                       # windows compared per text; lower is faster on very long texts

[scanners.pii]
entities = ["email", "credit_card", "aadhaar"]

[scanners.links]
allowed_domains = ["example.com"]

[scanners.denylist]            # opt-in: on when the section is present
terms = ["project nightingale"]

[scanners.classifier]          # opt-in, `ml` extra
threshold = 0.7
# device = 0                   # GPU index
# model = "org/model"          # a different Hugging Face classifier
# revision = "<commit sha>"    # pin it (the default model is pinned for you)
```

Every scanner section accepts `enabled` and `directions`. The default scanners are on unless disabled; the opt-in ones
(`denylist`, `classifier`, `relevance`) switch on when their section is present.

## Environment variables

| Variable | Overrides |
|---|---|
| `GUARDLAYER_PRESET` | `preset` |
| `GUARDLAYER_MODE` | `[guard] mode` |
| `GUARDLAYER_FLAG_THRESHOLD`, `GUARDLAYER_BLOCK_THRESHOLD` | the thresholds |
| `GUARDLAYER_FAIL_CLOSED` | `[guard] fail_closed` |
| `GUARDLAYER_AUTO_LEARN` | `[guard] auto_learn` |
| `GUARDLAYER_CONFIG` | config path for the REST API |
| `GUARDLAYER_API_KEY` | required `X-API-Key` for the REST API |
| `GUARDLAYER_STATE_DIR` | session directory for the Claude Code hook |

## In code

Everything in the file has a Python equivalent:

```python
from guardlayer import GuardLayer, Policy, SessionPolicy, ToolPolicy

guard = GuardLayer(
    policy=Policy(block_threshold=0.8, fail_closed=True),
    tool_policy=ToolPolicy(egress_allowlist=["api.github.com"], capability_actions={"exec": "review"}),
    session_policy=SessionPolicy(untrusted_tools=["read_email"]),
)
```

Or build from a dict: `GuardLayer.from_config({"preset": "strict", "tools": {"egress_allowlist": ["api.github.com"]}})`.
