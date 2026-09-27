# Any framework

`guard_tool` wraps any sync or async Python function that an agent can call. The call is checked before it runs and the
result is scanned after.

```python
from guardlayer import GuardLayer
from guardlayer.integrations.tools import guard_tool

guard = GuardLayer()

@guard_tool(guard, session="user-42")
def run_shell(cmd: str) -> str:
    return "ran: " + cmd                      # your real implementation

print(run_shell(cmd="ls -la"))               # runs
print(run_shell(cmd="rm -rf ~"))             # returns a refusal; the function never runs
```

| Option | Default | Meaning |
|---|---|---|
| `session` | none | a session id, a `GuardSession`, or a zero-argument callable returning one (e.g. the current user) |
| `approve` | none | `approve(result) -> bool` for `review` verdicts. With no approver, `review` is treated like `block`. |
| `on_block` | `"message"` | return a refusal string the model can read, or `"raise"` to raise `ToolBlocked` |
| `withhold_at` | `block` | results at or above this verdict are replaced by a notice |
| `name` | the function name | the tool name used for capabilities and rules |

```py
@guard_tool(guard, session=lambda: request.user_id, approve=ask_on_slack)
def send_email(to: str, body: str) -> str: ...
```

The wrapper keeps the function's signature and docstring (`functools.wraps`), so framework decorators such as
LangChain's `@tool` or the Agents SDK's `@function_tool` still work on top of it.

## Your own agent loop

If you run the loop yourself, call the scans directly:

```py
for call in model_response.tool_calls:
    verdict = guard.scan_tool_call(call.name, call.args, session=session_id)
    if verdict.is_blocked or (verdict.needs_review and not approve(verdict)):
        messages.append(tool_message(call, refusal_message(call.name, verdict)))
        continue
    output = run(call)
    scanned = guard.scan_tool_result(call.name, output, session=session_id)
    messages.append(tool_message(call, scanned.text if scanned.allowed else withheld_message(call.name, scanned)))
```

`refusal_message` and `withheld_message` live in `guardlayer.integrations.tools`.
