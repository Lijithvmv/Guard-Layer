"""Behavioural hijack check: did the user ask for this tool call, or did something the agent read?

Masked re-execution (MELON, ICML 2025): ask the agent's own model again, with the user's request replaced by a neutral
task ("summarise the tool results above") and everything the agent read left in place. A model that is following its
user has no reason to propose the same action under the neutral task. If it does, the action is being driven by the
content, whatever language or wording that content used. So this catches injections no scanner recognises.

GuardLayer does the masking, the comparison and the verdict. The app supplies `replay`: a call to its own model with the
masked messages, returning the tool calls the model proposes. It costs one model call per checked action, so check only
risky calls (`GuardLayer.needs_intent_check`).

Limits, stated plainly: content that also restates the user's task can make the replay act too (a missed hijack), a
model that ignores the neutral task gives noisy results, and the check needs the message list. It adds a signal; it
does not replace containment.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from guardlayer.filelabels import PATH_ARGUMENTS
from guardlayer.tools import argument_values, flatten_arguments

NEUTRAL_TASK = "Please summarise the results of the tool calls above in a few sentences."
# Arguments that decide where an action lands. The same value here under the masked request is the tell-tale sign.
DESTINATION_ARGUMENTS = ("to", "recipient", "recipients", "cc", "bcc", "email", "address", "url", "uri", "link", "iban",
                         "account", "channel", "user", "phone", "command", "cmd", *PATH_ARGUMENTS)  # fmt: skip
ARGUMENT_OVERLAP = 0.8  # or this share of all argument values equal

ToolCall = tuple[str, Any]  # (name, arguments)
Replay = Callable[[list[dict[str, Any]]], Iterable[Any]]


def mask_user_request(messages: Sequence[Mapping[str, Any]], task: str = NEUTRAL_TASK) -> list[dict[str, Any]]:
    """The conversation with the user's request hidden: user messages become the neutral task, assistant text is
    dropped (it can restate the request), and system messages, tool calls and tool results stay as they were.

    Messages are chat-style dicts (`role`, `content`, optional `tool_calls`), the shape most model APIs use.
    """
    masked: list[dict[str, Any]] = []
    asked = False
    for message in messages:
        m = dict(message)
        role = m.get("role")
        if role == "user":
            if asked:  # one neutral request is enough; later user turns would carry more of the real task
                continue
            m["content"], asked = task, True
        elif role == "assistant":
            m["content"] = ""
        masked.append(m)
    if not asked:
        masked.append({"role": "user", "content": task})
    return masked


def normalise_call(call: Any) -> ToolCall | None:
    """Accept `(name, arguments)`, `{"name", "arguments"}`, or an OpenAI-style `{"function": {"name", "arguments"}}`
    (arguments may be a JSON string), or an object with `name`/`function` and `arguments`/`args` attributes."""
    if isinstance(call, tuple) and len(call) == 2:
        name, args = call
    elif isinstance(call, Mapping):
        fn = call.get("function") if isinstance(call.get("function"), Mapping) else call
        name, args = fn.get("name"), fn.get("arguments", fn.get("args"))
    else:
        name = getattr(call, "name", None) or getattr(call, "function", None)
        args = getattr(call, "arguments", getattr(call, "args", None))
    if not isinstance(name, str) or not name:
        return None
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            pass
    return name, args


def _values(arguments: Any) -> set[str]:
    return {v.strip().lower() for v in flatten_arguments(arguments).split("\n") if v.strip()}


def same_action(original: ToolCall, replayed: ToolCall) -> bool:
    """Same tool, and the same destination (recipient, URL, path, command...) or mostly the same argument values."""
    if original[0] != replayed[0]:
        return False
    a, b = original[1], replayed[1]
    for name in DESTINATION_ARGUMENTS:
        mine = {v.strip().lower() for v in argument_values(a, name)}
        if mine and mine & {v.strip().lower() for v in argument_values(b, name)}:
            return True
    va, vb = _values(a), _values(b)
    if not va:
        return True  # an argument-less action proposed again is the same action
    return len(va & vb) / len(va) >= ARGUMENT_OVERLAP


@dataclass
class IntentCheck:
    """Outcome of one masked re-execution."""

    driven_by_content: bool
    replayed: list[ToolCall] = field(default_factory=list)
    matched: ToolCall | None = None
    error: str | None = None


def check(tool_name: str, arguments: Any, messages: Sequence[Mapping[str, Any]], replay: Replay, *, task: str = NEUTRAL_TASK) -> IntentCheck:
    """Run the replay on the masked conversation and compare its proposals with the call under check."""
    try:
        proposed = [c for c in map(normalise_call, replay(mask_user_request(messages, task)) or []) if c]
    except Exception as exc:  # the app's model call failed: report it, don't guess
        return IntentCheck(False, error=f"{type(exc).__name__}: {exc}")
    original = (tool_name, arguments)
    matched = next((c for c in proposed if same_action(original, c)), None)
    return IntentCheck(matched is not None, proposed, matched)


async def acheck(tool_name: str, arguments: Any, messages: Sequence[Mapping[str, Any]], replay: Callable[..., Any], *, task: str = NEUTRAL_TASK) -> IntentCheck:
    """`check` for an async `replay`."""
    try:
        proposed = [c for c in map(normalise_call, await replay(mask_user_request(messages, task)) or []) if c]
    except Exception as exc:
        return IntentCheck(False, error=f"{type(exc).__name__}: {exc}")
    original = (tool_name, arguments)
    matched = next((c for c in proposed if same_action(original, c)), None)
    return IntentCheck(matched is not None, proposed, matched)
