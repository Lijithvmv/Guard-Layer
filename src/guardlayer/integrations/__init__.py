"""Drop-in integrations for agent frameworks.

* `guardlayer.integrations.tools`: `guard_tool`, which wraps any Python tool function
  (sync or async) with a pre-call policy check and a post-call result scan. It works with any
  framework that calls plain functions.
* `guardlayer.integrations.claude_code`: a Claude Code hook (`guardlayer hook claude-code`)
  for PreToolUse, PostToolUse and UserPromptSubmit, with file-backed session taint.
* `guardlayer.integrations.langgraph`: `guard_tools` for LangChain/LangGraph tools; a REVIEW
  verdict becomes a LangGraph `interrupt()` for human approval.
* `guardlayer.integrations.openai_agents`: input, output and tool guardrails for the OpenAI Agents SDK.

Framework imports are lazy: the core stays dependency-free, and each module imports its
framework only when used.
"""
