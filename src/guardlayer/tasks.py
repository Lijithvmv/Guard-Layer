"""Task profiles: the tools (and argument values) a kind of task may use, chosen by trusted code per request.

Detection asks "does this text look like an attack?". A task profile asks "is this action part of what the user asked
for?", which doesn't depend on how an attacker words things or which language they use:

```toml
[tasks.summarise_inbox]
tools = ["list_emails", "read_email"]

[tasks.reply_to_customer]
tools = ["read_email", "get_customer", "send_email"]
arguments = [{ tool = "send_email", argument = "to", allow = ["{task.customer_email}"] }]
```

```python
session = guard.session(user_id, task="reply_to_customer", task_args={"customer_email": "asha@example.com"})
```

* A tool outside the profile gets `out_of_task`; an argument outside the profile's allowed values gets
  `task_argument_not_allowed` (review by default, see `[session] actions`).
* `{task.NAME}` in an allowed value is filled from `task_args`, which come from the **trusted** request, so an injected
  recipient or URL can't match.
* **Monotonic:** during a session a profile can only narrow (`session.narrow(...)`) without a human; switching to a wider
  profile or clearing it needs `approved=True`.

The research this follows: privileges derived from the user's task, which can only shrink without approval (Progent,
2025), and planners that never see untrusted data (CaMeL, 2025).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from guardlayer.tools import ArgumentRule

_TEMPLATE = re.compile(r"\{task\.([A-Za-z_][A-Za-z0-9_]*)\}")
_PROFILE_KEYS = {"tools", "arguments", "description"}


@dataclass(frozen=True)
class TaskProfile:
    name: str
    tools: tuple[str, ...]
    arguments: tuple[Mapping[str, Any], ...] = ()
    description: str = ""

    @classmethod
    def from_dict(cls, name: str, data: Mapping[str, Any]) -> TaskProfile:
        unknown = set(data) - _PROFILE_KEYS
        if unknown:
            raise ValueError(f"task {name!r}: unknown key(s) {sorted(unknown)}; use {sorted(_PROFILE_KEYS)}")
        tools = data.get("tools")
        if not tools or isinstance(tools, str) or not all(isinstance(t, str) for t in tools):
            raise ValueError(f"task {name!r}: `tools` must be a non-empty list of tool names or globs")
        arguments = tuple(data.get("arguments", ()))
        for rule in arguments:
            ArgumentRule.from_dict(rule)  # validates the shape; {task.NAME} templates are ordinary strings here
        return cls(name, tuple(tools), arguments, str(data.get("description", "")))

    def templates(self) -> set[str]:
        """Names used as {task.NAME} in allowed or denied values."""
        names: set[str] = set()
        for rule in self.arguments:
            for value in (*rule.get("allow", ()), *rule.get("deny", ())):
                names |= set(_TEMPLATE.findall(str(value)))
        return names

    def argument_rules(self, task_args: Mapping[str, Any]) -> list[ArgumentRule]:
        """The profile's argument rules with {task.NAME} filled from `task_args` (from the trusted request)."""
        missing = self.templates() - set(task_args)
        if missing:
            raise ValueError(f"task {self.name!r} needs task_args {sorted(missing)}")

        def fill(values: Any) -> tuple[str, ...]:
            return tuple(_TEMPLATE.sub(lambda m: str(task_args[m.group(1)]), str(v)) for v in values)

        rules = []
        for rule in self.arguments:
            data = dict(rule)
            if "allow" in data:
                data["allow"] = list(fill(data["allow"]))
            if "deny" in data:
                data["deny"] = list(fill(data["deny"]))
            rules.append(ArgumentRule.from_dict(data))
        return rules

