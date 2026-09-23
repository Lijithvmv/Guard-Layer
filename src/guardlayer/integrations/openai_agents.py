"""OpenAI Agents SDK integration: GuardLayer as input, output and tool guardrails.

    from guardlayer.integrations.openai_agents import guardrails

    gl = guardrails(guard)
    agent = Agent(
        name="assistant",
        tools=[function_tool(fetch, tool_input_guardrails=[gl.tool_input], tool_output_guardrails=[gl.tool_output])],
        input_guardrails=[gl.input],
        output_guardrails=[gl.output],
    )
    await Runner.run(agent, "...", context={"session_id": "user-42"})

* `input` / `output`: trip the SDK's tripwire (`InputGuardrailTripwireTriggered` /
  `OutputGuardrailTripwireTriggered`) when GuardLayer does not allow the text.
* `tool_input`: a blocked or review-level call is rejected, and the model gets a refusal
  message instead of a result. For real human approval, also set the SDK's own
  `needs_approval` on the tool. GuardLayer cannot pause an Agents run by itself.
* `tool_output`: output containing an injection is replaced by a notice.

The session is read from the run context: `context={"session_id": ...}`, or an object with a
`session_id` attribute. Pass `session=` (an id, or a callable taking the context) to override
it. Without a session id, each check is stateless.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from guardlayer.integrations.tools import refusal_message, withheld_message
from guardlayer.models import Verdict

if TYPE_CHECKING:  # pragma: no cover
    from guardlayer.pipeline import GuardLayer


def _context_session(context: Any) -> str | None:
    if isinstance(context, dict):
        value = context.get("session_id")
    else:
        value = getattr(context, "session_id", None)
    return str(value) if value else None


def _text(value: Any) -> str:
    """Flatten SDK input (a string, or a list of message items with text parts) into text."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            content = item.get("content") if isinstance(item, dict) else getattr(item, "content", None)
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                parts.extend(str(p.get("text", "")) if isinstance(p, dict) else str(getattr(p, "text", "")) for p in content)
        return "\n".join(p for p in parts if p)
    if hasattr(value, "model_dump_json"):
        return value.model_dump_json()
    return json.dumps(value, ensure_ascii=False, default=str)


@dataclass
class GuardrailSet:
    input: Any
    output: Any
    tool_input: Any
    tool_output: Any


class _Checks:
    """The guardrail logic, independent of the SDK so it can be tested without it."""

    def __init__(self, guard: GuardLayer, session: str | Callable[[Any], str | None] | None, withhold_at: Verdict) -> None:
        self.guard, self.session, self.withhold_at = guard, session, withhold_at

    def _sid(self, context: Any) -> str | None:
        if callable(self.session):
            return self.session(context)
        return self.session or _context_session(context)

    def input(self, context: Any, value: Any) -> tuple[bool, dict[str, Any]]:
        result = self.guard.scan_input(_text(value), session=self._sid(context))
        return not result.allowed, result.to_dict(include_text=False)

    def output(self, context: Any, value: Any) -> tuple[bool, dict[str, Any]]:
        result = self.guard.scan_output(_text(value), session=self._sid(context))
        return not result.allowed, result.to_dict(include_text=False)

    def tool_input(self, context: Any, tool_name: str, raw_arguments: str | None) -> str | None:
        """Returns a refusal message, or None to allow."""
        try:
            arguments: Any = json.loads(raw_arguments) if raw_arguments else {}
        except ValueError:
            arguments = raw_arguments
        result = self.guard.scan_tool_call(tool_name, arguments, session=self._sid(context))
        return None if result.allowed else refusal_message(tool_name, result)

    def tool_output(self, context: Any, tool_name: str, output: Any) -> str | None:
        """Returns a replacement notice, or None to pass the output through."""
        result = self.guard.scan_tool_result(tool_name, output, session=self._sid(context))
        return withheld_message(tool_name, result) if result.verdict >= self.withhold_at else None


def guardrails(
    guard: GuardLayer,
    *,
    session: str | Callable[[Any], str | None] | None = None,
    withhold_at: Verdict | str = Verdict.BLOCK,
) -> GuardrailSet:
    """Build the four guardrails. Needs `pip install openai-agents`."""
    try:
        from agents import (
            GuardrailFunctionOutput,
            ToolGuardrailFunctionOutput,
            input_guardrail,
            output_guardrail,
            tool_input_guardrail,
            tool_output_guardrail,
        )
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise ModuleNotFoundError("OpenAI Agents guardrails need: pip install openai-agents") from exc

    checks = _Checks(guard, session, Verdict(withhold_at))

    @input_guardrail(name="guardlayer_input")
    def gl_input(ctx: Any, agent: Any, value: Any) -> Any:
        tripped, info = checks.input(ctx.context, value)
        return GuardrailFunctionOutput(output_info=info, tripwire_triggered=tripped)

    @output_guardrail(name="guardlayer_output")
    def gl_output(ctx: Any, agent: Any, value: Any) -> Any:
        tripped, info = checks.output(ctx.context, value)
        return GuardrailFunctionOutput(output_info=info, tripwire_triggered=tripped)

    @tool_input_guardrail(name="guardlayer_tool_input")
    def gl_tool_input(data: Any) -> Any:
        tc = data.context
        refusal = checks.tool_input(tc.context, tc.tool_name, tc.tool_arguments)
        return ToolGuardrailFunctionOutput.allow() if refusal is None else ToolGuardrailFunctionOutput.reject_content(refusal)

    @tool_output_guardrail(name="guardlayer_tool_output")
    def gl_tool_output(data: Any) -> Any:
        tc = data.context
        notice = checks.tool_output(tc.context, tc.tool_name, data.output)
        return ToolGuardrailFunctionOutput.allow() if notice is None else ToolGuardrailFunctionOutput.reject_content(notice)

    return GuardrailSet(gl_input, gl_output, gl_tool_input, gl_tool_output)
