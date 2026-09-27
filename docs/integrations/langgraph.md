# LangGraph / LangChain

`pip install "guardlayer[langgraph]"`

```py
from guardlayer import GuardLayer
from guardlayer.integrations.langgraph import guard_tools
from langgraph.prebuilt import create_react_agent

guard = GuardLayer()
tools = guard_tools(guard, [search, fetch_url, run_shell])     # drop-in for ToolNode / create_react_agent
agent = create_react_agent(model, tools, checkpointer=checkpointer)
```

What the guarded tools do:

| Situation | Behaviour |
|---|---|
| Call blocked | The model receives a refusal it can read and reason about; the tool doesn't run. |
| Call needs review | The graph pauses with LangGraph's `interrupt()`. Resume with `Command(resume=True)` to approve; anything else refuses. |
| Result contains an injection | The result is withheld; the model gets a notice to treat that source as untrusted. |
| Result contains a secret | It's redacted before the model sees it. |

The graph's `thread_id` becomes the GuardLayer [session](../concepts/sessions.md), so taint follows the conversation.
Override it with `session=` (a string, a `GuardSession` or a callable).

```py
from langgraph.types import Command

config = {"configurable": {"thread_id": "user-42"}}
state = agent.invoke({"messages": [("user", "clean up the repo")]}, config)
if state.get("__interrupt__"):                  # GuardLayer asked for approval
    print(state["__interrupt__"][0].value)     # what the tool wants to do, and why it needs review
    agent.invoke(Command(resume=True), config)  # approve (or resume with False to refuse)
```

Options: `on_review="deny"` refuses review-level calls instead of pausing (for unattended graphs), and
`withhold_at="flag"` withholds results at a lower threshold.

Interrupts need a checkpointer. Graph state must be JSON-serializable; GuardLayer's interrupt payload is.
