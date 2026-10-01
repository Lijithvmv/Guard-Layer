# Python API

Generated from the source docstrings. Everything here is importable from `guardlayer` unless noted.

## The guard

::: guardlayer.GuardLayer
    options:
      members: [scan_input, scan_output, scan_context, scan_tool_call, scan_tool_result, needs_intent_check, check_intent, acheck_intent, scan, scan_batch, session, protect, add_canary, add_hook, from_preset, from_config]

::: guardlayer.GuardBlocked

## Results

::: guardlayer.ScanResult

::: guardlayer.Detection

::: guardlayer.Verdict

::: guardlayer.Action

::: guardlayer.Category

## Policies

::: guardlayer.Policy

::: guardlayer.ToolPolicy

::: guardlayer.ToolRule

::: guardlayer.SessionPolicy

::: guardlayer.GuardSession

## Audit and evidence

::: guardlayer.AuditLogger

::: guardlayer.AuditSigner

::: guardlayer.verify_audit_log

::: guardlayer.compliance.build_evidence

::: guardlayer.compliance.EvidencePack

## Integrations

::: guardlayer.integrations.tools.guard_tool

::: guardlayer.integrations.langgraph.guard_tools

::: guardlayer.integrations.openai_agents.guardrails

## Extending

::: guardlayer.BaseScanner

::: guardlayer.Rule

::: guardlayer.LLMJudgeScanner

::: guardlayer.default_scanners
