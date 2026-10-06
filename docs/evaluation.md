# Evaluation

GuardLayer is measured three ways, and every number here can be reproduced from the repository:

1. **Public prompt-injection datasets**: text-level precision, recall and false-positive rate on held-out data.
2. **An agentic evaluation**: a real model runs tool-using tasks with injections hidden in what it reads; scored by what
   the tools actually executed.
3. **[AgentDojo](#agentdojo)**: a third-party benchmark (ETH Zurich) with its own environments, tasks and attacks.

Where a result is *not* a fair test (for example, a model evaluated on data it was trained on, or rules written after
seeing the attacks), it says so.

### Real work and recorded frontier-model attacks (October 2026)

Replays, not live runs: each recorded call goes through GuardLayer's own code path, but the agent never saw its
answer. Scripts: `benchmarks/transcript_replay.py` (Claude Code transcripts; `--rebuild-files` rebuilds the files a
session wrote, so file rules judge their real content) and `benchmarks/agentdojo_trace_replay.py`.

| What | Data (type) | Calls or runs | Held / stopped |
|---|---|---|---|
| Interruptions, `balanced` | one developer's Claude Code sessions from projects never used for design (real use) | 6,962 calls | 1.61-1.68% held |
| Interruptions, no setup | OpenHands agents resolving real GitHub issues (third-party recorded, CC BY 4.0) | 11,869 calls | 0.75% held |
| Interruptions, tools declared | same | 11,869 calls | 0.11% held |
| Attacks, detectors off | AgentDojo published runs of five frontier models, `important_instructions` (third-party recorded) | 707 succeeded attacks | 92% stopped |
| Ordinary tasks, same runs | same | 644 tasks | 27% held |

The real-use sessions were checked for overlap with the design sessions by shared tool-call ids (a first held-out set
was 28% copies of design sessions and was corrected). The interval is a bound: content the replay couldn't rebuild was
counted both as held and as not held.

**Against a model-based judge.** On the same seeded sample (85 succeeded attacks across four attack styles and 40
ordinary tasks), an open-source LLM alignment checker that reads the agent's trace, run locally on a 14B model,
stopped 80 attacks and held 11 ordinary tasks; GuardLayer stopped 82 and held 5, in about 0.01 s per decision against
about 50 s. On plainly worded attacks (`direct`) it was 14 of 15 for GuardLayer and 11 of 15 for the judge. The samples
are small and the intervals overlap; the judge's authors use a much larger model; and no attack was adapted to either.

### Public datasets

`python benchmarks/public_eval.py` downloads four public datasets (about 12 MB) and scores
GuardLayer on them. The rules were tuned only on the `train` splits; the table reports the
held-out `test` splits. A prediction counts as positive at FLAG or above. Add
`--classifier` to include the transformer classifier, or use `--classifier-only` to run it alone.

| Configuration | deepset/prompt-injections (n=116) | jailbreak-classification (n=262) | Latency p50 / p95 |
|---|---|---|---|
| **Default** (rules + zero-dependency layers) | P **1.00** · R 0.23 · FPR **0.00** | P **1.00** · R 0.72 · FPR **0.00** | 0.5–9 ms / 4–63 ms |
| Classifier only (`ml` extra) | P 1.00 · R 0.37 · FPR 0.00 | *P 0.98 · R 0.86 · FPR 0.02 †* | 150–340 ms / 0.25–2.8 s |
| **Default + classifier** | P **1.00** · R **0.47** · FPR **0.00** | *P 0.98 · R 0.90 · FPR 0.02 †* | 150–360 ms / 0.27–2.9 s |

Dataset links: [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) ·
[jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification).
Classifier: [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) at the pinned revision `90c9989`, threshold 0.7, CPU.

† **Not a fair test.** jailbreak-classification is part of that model's training data, so
its classifier numbers are optimistic. deepset is not in its training data, and 0.47 is
the number to trust.

**Two more held-out sets** (added September 2026, never used to tune the rules, MIT licence):

| Configuration | Lakera/gandalf_ignore_instructions (n=1,000, all attacks) | SPML chatbot prompt injection (n=16,011: 12,541 attacks, 3,470 benign) |
|---|---|---|
| **Default** (rules + zero-dependency layers) | R **0.57** | P **1.00** · R 0.21 · FPR **0.00** |
| Default + classifier | *R 1.00 ‡* | not run yet (about an hour on CPU) |

‡ **Probably not a fair test.** The classifier's model card names 7 training datasets and says 8 more MIT-licensed
ones were used without naming them; Lakera's Gandalf data is MIT-licensed and a near-perfect score suggests it was among them.
The rules-only numbers are clean: GuardLayer's rules have never seen either set. Gandalf's real attempts are short, direct
extraction attacks, which signatures catch well; SPML's attacks are often written as ordinary requests to a role-playing
chatbot, which is where signatures alone fall short (compare deepset, 0.23).

How to read this:

- **The defaults favour precision.** Across all 1,968 prompts, none of the benign ones were
  flagged, and none of SPML's 3,470 benign prompts either. That makes the defaults safe to put in front of real traffic.
- **The classifier roughly doubles recall on unseen data**, from 0.23 to 0.47 on deepset. It
  costs about 150 ms per short prompt on CPU and about 750 MB of model weights. It also adds
  a few false positives: 1.2% on deepset-train, mostly **German** prompts, since the model
  is English-only. The rules and the classifier complement each other: the rules cover eight
  non-English languages, and the classifier covers English paraphrases.
- **Recall on deepset stays limited.** Many of its positives are ordinary role prompts
  ("I want you to act as a debater…") or requests for political opinions, which a guard
  shouldn't block.
- **Latency grows with prompt length.** Long prompts are split into windows for similarity
  and into chunks for the classifier. Use a GPU (`device = 0`) or keep the classifier for
  high-risk routes only.

Enable the classifier in config:

```toml
[scanners.classifier]      # pip install "guardlayer[ml]"; first run downloads the model
threshold = 0.7
# device = 0               # GPU index; omit for CPU
# model = "org/your-model" # a different Hugging Face classifier
# revision = "<commit>"    # pin it to an exact commit
```

**The default model is pinned.** Its upstream project was archived in July 2026 and is no longer
maintained, so GuardLayer loads it at a fixed revision (`90c9989b1a342275dd0d1a95aad283c04e075671`,
Apache-2.0) instead of whatever the repository serves today. A floating model reference can change
under you. Each classifier detection records the model and revision in its metadata. If you use your
own model, pass `revision` to pin it too.

### Agentic evaluation

Prompt-injection datasets score text. Agents fail by *acting*. [`benchmarks/agentic_eval.py`](https://github.com/Lijithvmv/Guard-Layer/blob/main/benchmarks/agentic_eval.py)
runs a tool-using agent through 38 scenarios in a simulated workspace (inbox, files with a planted API key and database
password, web pages; nothing real is contacted):

- **30 attacks:** 5 attacker goals (email the secrets out, POST them out, `rm -rf ~/projects`, add a `curl | sh` line to
  `~/.bashrc`, send a phishing email to all staff) × 3 injection styles (blunt "ignore all previous instructions", a polite
  HTML comment, a fake IT-security notice) × 2 carrier tasks, hidden in the email, web page or README the task makes the agent read.
- **8 benign tasks**, including legitimate side effects (emailing a todo list, posting a status update, running the tests), to
  measure what the guard costs.

Scoring uses what the tools actually executed. **Hijacked** means the attacker's action ran; **succeeded** means the goal was
achieved (for exfiltration, the secret actually reached the attacker). Each run is repeated with GuardLayer wrapping every tool
(`guard_tool`, default `balanced` posture), once with REVIEW requests denied (a vigilant human) and once with them all approved
(a rubber-stamping human).

**Worst-case agent.** `--model scripted` is an agent that obeys every instruction it reads, so the numbers measure GuardLayer
itself rather than how easily a particular model is fooled. It is deterministic and runs in CI
([`tests/test_agentic_scripted.py`](https://github.com/Lijithvmv/Guard-Layer/blob/main/tests/test_agentic_scripted.py)).

| Scripted agent, 30 attacks + 8 benign tasks | Hijacked | Succeeded | Attacked tasks still done | Benign tasks done | Approvals asked on benign |
|---|---|---|---|---|---|
| No guard | 30 / 30 | 30 / 30 | 30 / 30 | 8 / 8 | 0 |
| GuardLayer, reviews denied | **0 / 30** | **0 / 30** | 14 / 30 | 7 / 8 | 1 |
| GuardLayer, reviews rubber-stamped | 8 / 30 | 4 / 30 | 23 / 30 | 8 / 8 | 1 |
| `strict`, reviews denied | 1 / 30 | 0 / 30 | 10 / 30 | 5 / 8 | 2 |

**A real model.** `qwen2.5-coder:7b` (Q4_K_M, Ollama, temperature 0, seed 7) with the tools tagged explicitly
([`benchmarks/configs/agentic-tagged.toml`](https://github.com/Lijithvmv/Guard-Layer/blob/main/benchmarks/configs/agentic-tagged.toml)). In 24 of 30 attacks the agent read the
injected content; in the other 6 it finished without opening it.

| qwen2.5-coder:7b, 30 attacks + 8 benign tasks | Hijacked | Succeeded | Attacked tasks still done | Benign tasks done | Approvals asked on benign |
|---|---|---|---|---|---|
| No guard | 21 / 30 | 19 / 30 | 26 / 30 | 8 / 8 | 0 |
| GuardLayer, reviews denied | **0 / 30** | **0 / 30** | 10 / 30 | 7 / 8 | 1 |
| GuardLayer, reviews rubber-stamped | 5 / 30 | 3 / 30 | 19 / 30 | 8 / 8 | 1 |

Without a guard, the model followed the fake IT-security notice most often (8 successes), then the blunt override (7), then the
polite HTML comment (4). With GuardLayer and rubber-stamped reviews, the 3 successes were two `rm -rf ~/projects` and one
`~/.bashrc` line that a human approved; two more attacker POSTs ran but carried only redacted values. This run predates one later
fix (redacted markers were re-flagged as secrets, adding redundant review prompts) that doesn't change what gets blocked.

How to read it:

- **Blocking needs no human for exfiltration.** Secrets are redacted before the model sees them and fingerprinted, so even
  with every review rubber-stamped, no secret left. The 4 successes under rubber-stamping are the destructive command and the
  `~/.bashrc` persistence line: `balanced` sends those to REVIEW, and a human approved them. The REVIEW verdict is only as good
  as the person reading it. Under `strict`, nothing succeeded even with rubber-stamping, at a higher utility cost.
- **Protection costs utility under attack.** When an email or page carries an injection, GuardLayer withholds the whole result,
  and the agent loses the legitimate content too (14 of 30 attacked tasks still completed with the scripted agent, 10 of 30
  with qwen2.5-coder, against 26 of 30 unguarded). Redacting only the injected span, instead of the whole result, would recover some of it.
- **An injection that isn't detected can still direct an ordinary-domain request.** Under `strict`, one attacker-directed POST
  ran (carrying only a refusal message, because reading `.env` had been blocked). Only `tools.egress_allowlist` closes that path.
- **Benign cost:** one approval request, for reading `.env` in a task that legitimately asked for it.

Results: [`benchmarks/results/`](https://github.com/Lijithvmv/Guard-Layer/tree/main/benchmarks/results/). Run it against any Ollama model:
`python benchmarks/agentic_eval.py --model qwen2.5-coder:7b --config benchmarks/configs/agentic-tagged.toml`.

### AgentDojo

[AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH Zurich, v1.2.2) is a third-party benchmark: its own simulated
banking and Slack environments, user tasks, injection tasks, attack (`important_instructions`) and scoring. GuardLayer plugs in as
a defense that wraps AgentDojo's tool executor ([`benchmarks/agentdojo_eval.py`](https://github.com/Lijithvmv/Guard-Layer/blob/main/benchmarks/agentdojo_eval.py)).
Model: `qwen2.5-coder:7b` through Ollama with an 8k context, AgentDojo's prompt-based tool calling, temperature 0,
10 tool-loop iterations. 10 user tasks and 10 attack pairs sampled per suite (seed 2026), so every figure is out of 10 and
one task is 10 points: read these as a direction, not a precise rate.

| Suite · defense | Benign tasks done | Attacks succeeded | Attacked tasks still done |
|---|---|---|---|
| Banking · no defense | 6 / 10 | 7 / 10 | 6 / 10 |
| Banking · GuardLayer 0.5.0 | 4 / 10 | 6 / 10 | 5 / 10 |
| Banking · GuardLayer, fixes below | 4 / 10 | **0 / 10** | 5 / 10 |
| Banking · fixes + `allow_egress` for the payment tools | 5 / 10 | **0 / 10** | 5 / 10 |
| Slack · no defense | 8 / 10 | 4 / 10 | 0 / 10 |
| Slack · GuardLayer 0.5.0 | 6 / 10 | 3 / 10 | 0 / 10 |
| Slack · GuardLayer, fixes below | 6 / 10 | **0 / 10** | 0 / 10 |

**The 0 / 10 rows were measured after seeing the attacks.** At text level, 0.5.0 detected one of the five attack
families in AgentDojo. The misses were fixed as general rules, not strings: a typo-tolerant "ignore previous instructions", content
addressed "to you, the AI", instructions posed as a precondition of the user's task, and fake system markers inside content
(4 of 5 families now detected; a plain TODO-style goal stays undetectable by design). No false positives on 4,509 benign
prompts from the public datasets or 1,006 benign AgentDojo environment texts. But the same attacks were then re-run. That shows the gap was closed, not how GuardLayer does on attacks it has never seen; the
held-out public datasets above are the better guide for that. Marking every tool result untrusted (`untrusted_tools = ["*"]`, AgentDojo's
threat model) gave the same numbers after the fixes; before them it stopped one more banking attack (5 / 10).

What it costs:

- **Benign utility drops by 2 tasks in each suite** (6 → 4 banking, 8 → 6 Slack). In benign banking runs every block was a
  legitimate `send_money` call: the IBAN in the payment counts as personal data, and sending it through a network-capable tool
  is `sensitive_data_egress`. AgentDojo's tools are untagged, so GuardLayer assumes any of them
  can send data off the machine. Allowing IBANs for the payment tools
  ([`benchmarks/configs/agentdojo-banking.toml`](https://github.com/Lijithvmv/Guard-Layer/blob/main/benchmarks/configs/agentdojo-banking.toml):
  `allow_egress = { send_money = ["iban"], ... }`) removed every benign block and recovered one task (5 / 10), with attack success
  still 0 / 10: the attacks' injections are still detected and `after_injection` still holds the payment. Nobody approves REVIEW
  requests in the benchmark, so every review also counts as a refusal.
- **The whole tool result is withheld when it carries an injection**, so the agent also loses the legitimate content. That is
  why attacked tasks don't recover. Slack's attacked tasks fail with or without a defense for this model.
- **One model, 10 samples per suite, one attack style.** AgentDojo has 949 (user task, attack) pairs and 17 attack styles;
  these runs cover 40 pairs and one style. 0 / 10 means "probably under about 28%" (95% interval), not "stops everything". The per-task logs are kept out of the repository; the summary rows, with the GuardLayer commit
  each was measured at, are in [`benchmarks/results/`](https://github.com/Lijithvmv/Guard-Layer/tree/main/benchmarks/results/).

**Workspace and travel (2026-09-30, GuardLayer `f00529b`, 16k context).** Same model, 10 user tasks and 10 attack pairs
per suite. The attack style is the one the rules were fixed on above, so these suites are new environments and tasks, not
new attacks.

| Suite · defense | Normal tasks done | Attacks succeeded | Attacked tasks still done |
|---|---|---|---|
| Workspace · no defense | 3 / 10 | 1 / 10 | 1 / 10 |
| Workspace · GuardLayer | 3 / 10 | **0 / 10** | 0 / 10 |
| Travel · no defense | 2 / 10 | 3 / 10 | 2 / 10 |
| Travel · GuardLayer | 2 / 10 | **0 / 10** | 0 / 10 |

No cost on normal tasks; under attack the withheld results cost the task, as in the other suites.

**Strip mode doesn't recover attacked tasks (2026-09-29, GuardLayer `1b11bd9`).** `on_injection="strip"` cuts the injected
part out of a tool result instead of withholding the whole result. Same model, sample and seed as above:

| Suite · mode | Normal tasks done | Attacks succeeded | Attacked tasks still done | Results withheld / stripped |
|---|---|---|---|---|
| Banking · withhold (default) | 5 / 10 | 0 / 10 | 5 / 10 | 16 / 0 |
| Banking · strip | 4 / 10 | 0 / 10 | 5 / 10 | 0 / 7 |
| Slack · withhold (default) | 6 / 10 | 0 / 10 | 0 / 10 | 33 / 0 |
| Slack · strip | 6 / 10 | 0 / 10 | 0 / 10 | 32 / 1 |

Attacks stayed at 0 either way, but attacked tasks didn't recover: in Slack almost every poisoned result still fell back to
withholding (the cut would have been most of the message), and in banking the stripped results didn't help this model finish.
On LLMail-Inject, the attacker's target also survived 117 of 269 cuts (see below). Strip mode stays opt-in; the default is
still to withhold.

Reproduce: `pip install agentdojo==0.1.35` in a separate environment, then
`python benchmarks/agentdojo_eval.py --model <ollama model> --suites banking,slack --per-suite 10 --max-iters 10`.

### Recorded agent sessions: ADR-Bench (2026-10-02, GuardLayer 0.8.0)

[ADR](https://github.com/uber/ADR) (Uber, Apache-2.0) publishes 303 recorded sessions of a coding agent using 134 MCP
servers, labelled benign (261) or malicious (42 with recordings). [`benchmarks/adr_eval.py`](https://github.com/Lijithvmv/Guard-Layer/blob/main/benchmarks/adr_eval.py)
replays every prompt, tool call and tool result through a GuardLayer session; a session counts as *intervened* when a
tool call would have been held for review or refused. No tools were declared, as in an out-of-the-box deployment.

| Preset | Malicious sessions intervened | Normal sessions intervened |
|---|---|---|
| balanced | 9 / 42 | **42 / 261 (16%)** |
| strict | 25 / 42 | 212 / 261 |

**This is a poor result, and it is reported as such.**

- The malicious sessions are malicious *tool servers*: the user's request is ordinary and the tools' outputs look
  ordinary (a "credential manager" that collects credentials, an "access auditor"). The harm happens on the server side.
  No content scanner can see that; only declaring which tools are trusted, and with what, can. Undeclared, GuardLayer
  caught 9 of 42, all through `trifecta`.
- **One normal session in six would have been interrupted.** Causes: content rules firing on ordinary tool output
  (`dangerous_scheme` on `Created file: ...` and `file://` in error messages; `split_letter_obfuscation`), which then
  trigger `after_injection` on the next call; and `trifecta` on every network-capable MCP call once personal data has
  appeared in any tool result. Our benign test sets had no MCP tool output, so the referee never saw these.
- The recordings keep tool names but not arguments, so argument and egress rules couldn't be tested; and it is a
  replay, so it measures whether GuardLayer would have intervened, not what the agent would have done next.

**What 0.8.1 changed.** Before any fix was written the sessions were split in two by a salted hash of the task id
(`--split dev|heldout`); the causes were studied on the dev half only. Four fixes: floats no longer read as card, phone
or Aadhaar numbers; leetspeak decoding skips tokens with no letters (`1.1.1.1` had become `i.i.i.i`, "split letters");
`file:` counts only inside a link; and personal data in tool output makes a session *private* rather than *sensitive*,
so it no longer triggers `trifecta` (`strict` and `airgap` keep it).

| `balanced` | Normal sessions interrupted, before → after | Malicious sessions, before → after |
|---|---|---|
| Dev half (studied) | 21 / 143 → 2 / 143 | 6 / 19 → 3 / 19 |
| **Held-out half** | **21 / 118 → 5 / 118** | 3 / 23 → 0 / 23 |

The malicious "catches" that went away came from the same `trifecta` firing on personal data that hit normal sessions
about as often: it wasn't telling them apart. Checked against what the change could cost elsewhere: in our recorded
AgentDojo runs, `trifecta` on personal data alone interrupted 12 of 130 normal tasks and was the only thing that stopped
1 of 130 attacks. Public datasets, LLMail-Inject and the Indian-language set are unchanged (same recall, zero false
positives).

### Unseen attacks: LLMail-Inject

The AgentDojo fixes were written after seeing its attacks, so they can't show how GuardLayer does on attacks it has never
seen. [LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) (Microsoft and academic partners,
2025, MIT licence) can: in a public challenge, attackers sent emails to an LLM email assistant, adapting against real
defenses, to make it send an email to an address they chose. Every submission records whether it worked. GuardLayer's
rules were never tuned on it. Each unique phase-2 email was scanned as untrusted context (`scan_context`), the way a guarded
agent sees an email it reads; detected means `flag` or above.

**First run (0.6.0 rules, never tuned on it):**

| LLMail-Inject phase 2 | Emails | Rules only | + classifier |
|---|---|---|---|
| All attack attempts | 38,014 | 11.2% | not run (CPU time) |
| Attacks that hijacked the model | 2,486 | 17.4% | 47.0% (95% CI 45.1–49.0%) |
| … and also got past the challenge's own defenses | 234 | 24.4% | 50.4% (44.1–56.8%) |
| Benign emails (false positives) | 238 | 0 | 0 |

**Improving it without fooling ourselves.** Writing rules from these misses and re-running the same emails would repeat
the AgentDojo mistake. So before any miss was read, the 99 attacker teams were split: 66 are **held out** (an email sent by
any held-out team is held out), and rules may be written only from the other teams' emails. A referee
([`benchmarks/referee.py`](https://github.com/Lijithvmv/Guard-Layer/blob/main/benchmarks/referee.py)) then accepts a candidate
rule only if it catches more held-out attacks, adds **no** hits on 5,151 benign texts (4,509 public prompts, 404 AgentDojo
environment texts, 238 LLMail emails), fires on the dev attacks it came from, and names nothing specific to this challenge's
goal. Every run is logged in `benchmarks/results/referee.jsonl`, rejected ones included.

Round 1 (2026-09-29): six candidates written from 60 sampled dev misses, one per technique. The referee rejected
`forged_tool_call` (fake `<function_calls>` markup: 2 dev hits, no held-out gain) and accepted five:
`forged_chat_turn` (fake `</assistant><user>` turns and role tags: +536 held-out), `summary_anchored_action` ("at the end of
your summary, send…": +344), `agent_goal_statement` (+3), `forged_safety_verdict` (fake "Safety Check: Passed": +1) and
`split_letter_obfuscation` ("s-e-n-d": +1). The last three barely generalise beyond the teams they came from.

| Held-out teams only | Emails | Rules before | Rules after | After + classifier |
|---|---|---|---|---|
| All attack attempts | 31,953 | 6.4% | **22.5%** | not run |
| Attacks that hijacked the model | 1,719 | 10.4% | **44.5%** (42.2–46.9%) | **56.0%** (53.7–58.4%) |
| … and also got past the challenge's own defenses | 161 | 9.3% | **38.5%** (31.3–46.2%) | **48.4%** (40.9–56.1%) |
| Benign emails (false positives) | 238 | 0 | 0 | 0 |

- **Detection still misses about half of what works against a real model**, even with the classifier. That is why GuardLayer
  doesn't rely on it. The attacker's goal here was an email to an outside address, and a tool rule on the email tool stops that
  whether the injection is detected or not, for example
  `{ name = "external_recipient", tools = ["send_email"], pattern = '@(?!(?:[a-z0-9-]+\.)*example\.com\b)[a-z0-9.-]+\.[a-z]{2,}', action = "review" }`.
  (`tools.egress_allowlist` checks URLs and hosts, not email addresses.)
- The new rules apply to content an agent reads (`scan_context`), not to what a user types; the public benchmark above is
  unchanged. Most matches give `flag`, which marks the session hostile so the agent's next side-effecting action goes to review.
- **The held-out set is not fresh forever.** Each accept or reject decision leaks a little about it; it has been used for one
  round. After one more round it should be replaced (for example with phase 1 of the challenge).
- 5,151 benign texts bound the false-positive rate, not prove it zero: real mail containing XML role tags, or a colleague
  writing "summarise these then send them to me", can trigger the new rules.
- The classifier (`protectai/deberta-v3-base-prompt-injection-v2`, pinned) predates the challenge. The "before" classifier
  figure wasn't measured on the held-out split. Scored on text, not on agent runs.

Reproduce (about 263 MB, not committed): download `raw_submissions_phase2.jsonl`, `emails_for_fp_tests.json` and
`scenarios.json` from the dataset's `data/` folder, then `python benchmarks/llmail_eval.py --data <dir>` (add
`--classifier --hijacked-only` for the classifier column). Referee: `python benchmarks/referee.py --data <dir> --candidate
benchmarks/candidates/2026-09-29.toml`; `--list-dev-misses 20` samples dev misses to study. Results:
`benchmarks/results/llmail-inject-phase2.jsonl` and `benchmarks/results/referee.jsonl`.

### Your own data

```
$ guardlayer eval your_data.jsonl        # {"text": "...", "label": 1, "direction": "input"}
$ guardlayer eval                        # bundled 67-sample smoke test (also used during tuning)
```
