"""LangChain / LangGraph integration: guard the tools you hand to `ToolNode` or `create_react_agent`.

    from guardlayer.integrations.langgraph import guard_tools

    tools = guard_tools(guard, [search, fetch_url, run_shell])
    graph = create_react_agent(model, tools, checkpointer=MemorySaver())

Every call goes through `scan_tool_call` before it runs, and every result goes through
`scan_tool_result` before the model reads it. The graph's `thread_id` is the GuardLayer
session, so taint builds up across the whole conversation.

* BLOCK: the tool returns a refusal message and the model is told not to retry.
* REVIEW: `on_review="interrupt"` (the default) pauses the graph with LangGraph's
  `interrupt()`. Resume with `Command(resume=True)` to approve, anything else to refuse.
  This needs a checkpointer. `on_review="deny"` refuses without asking.
* Output with an injection is withheld from the model.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

from guardlayer.integrations.tools import guard_tool
from guardlayer.models import ScanResult, Verdict

if TYPE_CHECKING:  # pragma: no cover
    from guardlayer.pipeline import GuardLayer


def _thread_session() -> str | None:
    try:
        from langgraph.config import get_config

        return (get_config().get("configurable") or {}).get("thread_id")
    except Exception:  # outside a graph run
        return None


def is_approval(value: Any) -> bool:
    """How a resume value is read: True, {"approved": True}, or "yes"/"approve" mean approved."""
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return bool(value.get("approved"))
    return isinstance(value, str) and value.strip().lower() in {"y", "yes", "approve", "approved", "allow"}


def interrupt_approver(tool_name: str) -> Callable[[ScanResult], bool]:
    def approve(result: ScanResult) -> bool:
        from langgraph.types import interrupt

        answer = interrupt(
            {
                "type": "guardlayer_review",
                "tool": tool_name,
                "rules": sorted({d.rule for d in result.detections}),
                "reasons": [d.message for d in result.detections if d.action],
                "result_id": result.id,
            }
        )
        return is_approval(answer)

    return approve


def guard_tools(
    guard: GuardLayer,
    tools: Iterable[Any],
    *,
    session: Any = None,
    on_review: str = "interrupt",
    withhold_at: Verdict | str = Verdict.BLOCK,
) -> list[Any]:
    """Return guarded copies of LangChain tools (anything with `.name`, `.invoke` and `.ainvoke`).

    `session` defaults to the graph's `thread_id`. Pass a string, a `GuardSession` or a callable to override it.
    """
    if on_review not in {"interrupt", "deny"}:
        raise ValueError("on_review must be 'interrupt' or 'deny'")
    try:
        from langchain_core.tools import StructuredTool
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise ModuleNotFoundError("guard_tools needs langchain-core: pip install langgraph") from exc

    resolver = session if session is not None else _thread_session
    guarded = []
    for tool in tools:
        call, acall = _invokers(tool)
        options = {
            "name": tool.name,
            "session": resolver,
            "approve": interrupt_approver(tool.name) if on_review == "interrupt" else None,
            "on_block": "message",
            "withhold_at": withhold_at,
        }
        guarded.append(
            StructuredTool.from_function(
                func=guard_tool(guard, call, **options),
                coroutine=guard_tool(guard, acall, **options),
                name=tool.name,
                description=tool.description,
                args_schema=tool.args_schema,
                return_direct=getattr(tool, "return_direct", False),
            )
        )
    return guarded


def _invokers(tool: Any) -> tuple[Callable[..., Any], Callable[..., Any]]:
    def call(**kwargs: Any) -> Any:
        return tool.invoke(kwargs)

    async def acall(**kwargs: Any) -> Any:
        return await tool.ainvoke(kwargs)

    return call, acall
