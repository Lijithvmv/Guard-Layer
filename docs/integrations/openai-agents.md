# OpenAI Agents SDK

`pip install "guardlayer[openai-agents]"`

```py
from agents import Agent, Runner, function_tool
from guardlayer import GuardLayer
from guardlayer.integrations.openai_agents import guardrails

gl = guardrails(GuardLayer())
agent = Agent(
    name="assistant",
    input_guardrails=[gl.input],
    output_guardrails=[gl.output],
    tools=[function_tool(fetch, tool_input_guardrails=[gl.tool_input], tool_output_guardrails=[gl.tool_output])],
)
await Runner.run(agent, prompt, context={"session_id": "user-42"})
```

| Guardrail | Behaviour |
|---|---|
| `input` / `output` | Trip the SDK's tripwire (`InputGuardrailTripwireTriggered` / `OutputGuardrailTripwireTriggered`) when GuardLayer doesn't allow the text. |
| `tool_input` | A blocked or review-level call is rejected; the model gets a refusal instead of a result. |
| `tool_output` | Output containing an injection is replaced by a notice. |

The session is read from the run context (`context={"session_id": ...}`, or an object with a `session_id` attribute).
Pass `guardrails(guard, session=...)` to override it. Without a session id, each check is stateless.

!!! note "Human approval"
    GuardLayer can't pause an Agents SDK run by itself. For real human approval, also set the SDK's `needs_approval` on
    the tool; GuardLayer's `review` verdict then refuses rather than waits.
