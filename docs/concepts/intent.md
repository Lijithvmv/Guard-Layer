# Behavioural check: who asked for this action?

!!! warning "Experimental"
    On AgentDojo banking with a local 7B model the check flagged nothing (0 of 30 replays) while 4 of 10 attacks succeeded; it may need a stronger model. Measure it on your own agent before relying on it. It may change or be removed in a later release, depending on how it works in real use.

Scanners look for injections by what they *say*. An attacker who writes in another language, or phrases the request
politely, can get past them. The behavioural check doesn't read the content at all. It asks a different question:
**would the agent still take this action if the user had never asked for anything?**

## How it works

Before a risky tool call runs, GuardLayer rebuilds the conversation with the user's request hidden:

- user messages become one neutral task: *"Please summarise the results of the tool calls above."*
- the assistant's own text is dropped (it can restate the request);
- the system prompt, earlier tool calls and **everything the agent read** stay as they were.

Your model runs once more on that masked conversation. A model following its user has no reason to send an email or
run a command when all it's been asked is to summarise. If it proposes **the same action anyway** (same tool, same
recipient, URL, path or command, or mostly the same arguments), the action is coming from the content, not the user:
`injection_driven_action`, **review** by default.

The idea is from MELON (masked re-execution, ICML 2025). It works whatever language or wording the injection used.

## Using it

You supply `replay`: a function that sends the masked messages to your model and returns the tool calls it proposes.
GuardLayer accepts `(name, arguments)` pairs, `{"name", "arguments"}` dicts or OpenAI-style `tool_calls` entries.

```py
from guardlayer import GuardLayer, Verdict

guard = GuardLayer()
session = guard.session(user_id)

def replay(masked_messages):
    reply = client.chat.completions.create(model=MODEL, messages=masked_messages, tools=TOOLS)
    return reply.choices[0].message.tool_calls or []

# before running a tool call the model proposed:
if session.needs_intent_check(call.name):
    check = session.check_intent(call.name, call.arguments, messages=messages, replay=replay)
    if check.verdict >= Verdict.REVIEW:
        ask_a_human(call, check)
```

`acheck_intent` takes an async `replay`. `needs_intent_check` is true only for tools that can act (network, exec, write,
or untagged) and, in a session, only after the session has read untrusted content: before that nothing but the user can
be steering the agent, so no model call is spent.

| Rule | When | Default |
|---|---|---|
| `injection_driven_action` | the model proposes the same action with the request hidden | review |
| `intent_check_failed` | your `replay` raised (timeout, API error); recorded, not guessed | log |

Change either with `SessionPolicy.actions`, like the other session rules.

## Limits

- **Cost:** one extra model call per checked action. Check risky calls only.
- **Restated tasks:** content that also restates the user's task ("the user asked you to send this to...") can make the
  masked run act too; the check then flags a genuine action. Treat a review as a question, not a verdict.
- **Weak models:** a model that ignores the neutral task and calls tools anyway gives noisy results. Measure on your own
  traffic in observe mode first.
- **Needs the conversation:** the check needs the message list your agent sends to its model. The Claude Code hook
  doesn't see it, so it can't use this check.

It adds a signal that doesn't depend on wording. It doesn't replace containment: keep [labels](labels.md), task profiles
and the tool policy on.
