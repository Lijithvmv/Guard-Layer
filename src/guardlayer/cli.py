"""Command-line interface.

    guardlayer scan "text"                    # scan a prompt (reads stdin if no text)
    guardlayer scan --direction output < reply.txt
    guardlayer tool-call bash '{"cmd": "rm -rf /"}'   # check an agent tool call against the tool policy
    guardlayer batch prompts.jsonl            # one {"text": ..., "direction": ...} per line
    guardlayer eval [dataset.jsonl]           # precision / recall / latency
    guardlayer canary "system prompt"         # embed a canary token
    guardlayer rules                          # list built-in signature and tool rules
    guardlayer presets                        # security postures and their residual risk
    guardlayer audit verify audit.jsonl       # check the audit hash chain (and signatures)
    guardlayer audit keygen audit             # write audit.key / audit.pub (Ed25519)
    guardlayer evidence export audit.jsonl --format csv -o evidence.csv   # control-mapped evidence pack
    guardlayer evidence controls              # frameworks and controls GuardLayer maps to
    guardlayer hook claude-code --print-config   # settings.json snippet for the Claude Code hook
    guardlayer hook claude-code --server --print-config   # the same, answered by a long-running server (faster)
    guardlayer serve --port 8000              # REST API (needs the `api` extra)

`scan` exits 1 when the verdict is BLOCK (or at/above `--fail-on`), so it composes in CI.
`--preset NAME` (any command) applies a preset underneath the `--config` file.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from guardlayer import __version__
from guardlayer.config import build_guard
from guardlayer.models import Action, Verdict

FAIL_ON = ["flag", "review", "block"]


def _print_result(result, as_json: bool) -> None:  # type: ignore[no-untyped-def]
    if as_json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return
    print(f"verdict: {result.verdict.value.upper()}  score {result.score}  ({result.latency_ms} ms)")
    for d in result.detections:
        action = f" -> {d.action}" if d.action else ""
        print(f"  - [{d.scanner}:{d.rule}] {d.category} sev {d.severity:.2f}{action}: {d.message}")
    if result.shadow_verdict is not None:
        print(f"observe mode: would be {result.shadow_verdict.value.upper()} (observed: {', '.join(result.observed_rules)})")
    if result.modified:
        print(f"sanitized: {result.text}")
    for err in result.errors:
        print(f"  ! scanner error: {err}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardlayer", description="Input/output security filtering for LLM and agent applications.")
    parser.add_argument("--version", action="version", version=f"guardlayer {__version__}")
    parser.add_argument("--config", help="TOML/JSON config file.")
    parser.add_argument("--preset", help="Security preset: observe, balanced, strict or airgap.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a piece of text.")
    scan.add_argument("text", nargs="?", help="Text to scan (reads stdin if omitted).")
    scan.add_argument("--direction", choices=["input", "output", "context"], default="input")
    scan.add_argument("--system-prompt", help="System prompt (enables leak detection on outputs).")
    scan.add_argument("--json", action="store_true", help="Emit the full result as JSON.")
    scan.add_argument("--fail-on", choices=FAIL_ON, default="block", help="Verdict that yields exit code 1.")

    tool = sub.add_parser("tool-call", help="Check an agent tool call against the tool policy and scanners.")
    tool.add_argument("tool", help="Tool name, e.g. bash or http_get.")
    tool.add_argument("arguments", nargs="?", help="Arguments as JSON (or a plain string); reads stdin if omitted.")
    tool.add_argument("--json", action="store_true", help="Emit the full result as JSON.")
    tool.add_argument("--fail-on", choices=FAIL_ON, default="review", help="Verdict that yields exit code 1.")

    batch = sub.add_parser("batch", help="Scan a JSONL file of {text, direction} records.")
    batch.add_argument("path")
    batch.add_argument("--fail-on", choices=FAIL_ON, default="block")

    ev = sub.add_parser("eval", help="Evaluate on a labelled JSONL dataset (default: bundled sample).")
    ev.add_argument("path", nargs="?")
    ev.add_argument("--positive", choices=["flag", "block"], default="flag", help="Minimum verdict counted as a detection.")
    ev.add_argument("--json", action="store_true")

    canary = sub.add_parser("canary", help="Embed a canary token in a prompt.")
    canary.add_argument("prompt")
    canary.add_argument("--echo", action="store_true", help="Goal-hijack mode: ask the model to echo the token.")

    sub.add_parser("rules", help="List built-in heuristic and tool rules.")
    sub.add_parser("presets", help="List security presets and their residual risk.")

    audit = sub.add_parser("audit", help="Tamper-evident audit log tools.")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    verify = audit_sub.add_parser("verify", help="Verify an audit log's hash chain (and signatures).")
    verify.add_argument("path")
    verify.add_argument("--public-key", help="Ed25519 public key (PEM) to verify signatures with.")
    verify.add_argument("--expected-head", help="A head hash recorded earlier, to detect a truncated log.")
    keygen = audit_sub.add_parser("keygen", help="Generate an Ed25519 signing key pair: PREFIX.key and PREFIX.pub.")
    keygen.add_argument("prefix")
    report = audit_sub.add_parser("report", help="What GuardLayer decided (or would have, in observe mode): by rule, by tool, latest.")
    report.add_argument("path")
    report.add_argument("--since-days", type=float, help="Only entries from the last N days.")
    report.add_argument("--min", default="flag", choices=["flag", "review", "block"], help="Lowest decision to include.")
    report.add_argument("--latest", type=int, default=15, help="How many recent notable entries to list.")
    report.add_argument("--json", action="store_true", help="Machine-readable output.")

    evidence = sub.add_parser("evidence", help="Control-mapped compliance evidence from an audit log.")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    export = evidence_sub.add_parser("export", help="Verify an audit log and export it as a control-mapped evidence pack.")
    export.add_argument("path")
    export.add_argument("--format", choices=["summary", "jsonl", "csv"], default="summary")
    export.add_argument("-o", "--output", help="Write to this file instead of stdout.")
    export.add_argument("--framework", action="append", help="Limit to a framework (repeatable); see `evidence controls`.")
    export.add_argument("--public-key", help="Ed25519 public key (PEM) to verify signatures with.")
    export.add_argument("--expected-head", help="A head hash recorded earlier, to detect a truncated log.")
    export.add_argument("--allow-unverified", action="store_true", help="Export even if the log fails verification (marked in the pack).")
    evidence_sub.add_parser("controls", help="List the frameworks and controls GuardLayer maps evidence to.")

    policy = sub.add_parser("policy", help="Check a configuration: what GuardLayer assumes about each tool, and gaps.")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    pcheck = policy_sub.add_parser("check", help="Per-tool capabilities, labels, sink limits and egress, with warnings.")
    pcheck.add_argument("--tools", nargs="*", help="Tool names to check (default: every tool named in the config).")
    pcheck.add_argument("--claude-code", action="store_true", help="Include Claude Code's built-in tools, as the hook sees them.")
    pcheck.add_argument("--strict", action="store_true", help="Exit 1 if there are warnings (for CI).")
    pcheck.add_argument("--json", action="store_true", help="Machine-readable output.")
    pdraft = policy_sub.add_parser("draft", help="Draft [tool.NAME] declarations from audit logs (what the agent actually used).")
    pdraft.add_argument("audit", nargs="+", help="Audit log(s) (JSONL) recorded with min_verdict = \"allow\".")
    pdraft.add_argument("--claude-code", action="store_true", help="Skip Claude Code's built-in tools (already known).")
    pdraft.add_argument("-o", "--output", help="Write the draft here instead of printing it.")
    pdraft.add_argument("--force", action="store_true", help="Overwrite --output if it exists.")

    hook = sub.add_parser("hook", help="Run as an agent hook (reads the event JSON on stdin).")
    hook_sub = hook.add_subparsers(dest="hook_target", required=True)
    cc = hook_sub.add_parser("claude-code", help="Claude Code PreToolUse / PostToolUse / UserPromptSubmit hook.")
    cc.add_argument("--state-dir", help="Session state directory (default ~/.guardlayer/sessions or GUARDLAYER_STATE_DIR).")
    cc.add_argument("--block-prompts", action="store_true", help="Also block user prompts that GuardLayer blocks.")
    cc.add_argument("--withhold-injections", action="store_true",
                    help="Replace a tool result that holds a likely prompt injection, so Claude never reads it "
                         "(default: Claude is warned and the auto-mode classifier is told; the output stays visible).")
    cc.add_argument("--print-config", action="store_true", help="Print the settings.json hooks snippet and exit.")
    cc.add_argument("--server", action="store_true",
                    help="Run as a long-running local server for Claude Code's HTTP hooks (with --print-config: print that setup).")
    cc.add_argument("--ensure-server", action="store_true", help="Start the server if it isn't running (a SessionStart hook).")
    cc.add_argument("--port", type=int, help="Server port (default: derived from --config and --preset).")
    cc.add_argument("--token-env", help="Require a bearer token, read from this environment variable (shared machines).")

    serve = sub.add_parser("serve", help="Run the REST API.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    args = parser.parse_args(argv)
    if args.preset:
        os.environ["GUARDLAYER_PRESET"] = args.preset  # an env var, so it also reaches `serve`

    if args.command == "rules":
        from guardlayer.rules import DEFAULT_RULES
        from guardlayer.tools import DEFAULT_TOOL_RULES

        for rule in DEFAULT_RULES:
            print(f"{rule.name:<30} {rule.category:<20} {rule.severity:.2f}  {','.join(sorted(rule.directions)):<22} {rule.message}")
        print("\ntool-call rules:")
        for t in DEFAULT_TOOL_RULES:
            caps = ",".join(sorted(t.capabilities)) if t.capabilities else "any tool"
            print(f"{t.name:<30} {t.category:<20} {Action(t.action).value:<6} {caps:<22} {t.message}")
        return 0

    if args.command == "presets":
        from guardlayer.presets import PRESETS

        for preset in PRESETS.values():
            print(f"{preset.name}\n  {preset.description}\n  residual risk:")
            for risk in preset.residual_risk:
                print(f"    - {risk}")
            print()
        return 0

    if args.command == "audit":
        return _audit(args)

    if args.command == "evidence":
        return _evidence(args)

    if args.command == "policy" and args.policy_command == "draft":
        from guardlayer.declare import draft, tool_usage

        guard = build_guard(args.config)
        if args.claude_code:
            from guardlayer.integrations import claude_code

            claude_code.configure_guard(guard)
        usage = tool_usage(args.audit)
        if not usage:
            print("No tool calls or results in these audit logs (record with [audit] min_verdict = \"allow\").", file=sys.stderr)
            return 1
        known = [name for name in usage if guard.tool_policy._explicit(name)]
        text = draft(usage, guard, known=known, source=", ".join(Path(a).name for a in args.audit))
        if args.output:
            out = Path(args.output)
            if out.exists() and not args.force:
                print(f"{out} exists; pass --force to overwrite it.", file=sys.stderr)
                return 1
            out.write_text(text, encoding="utf-8")
            print(f"Wrote {out}: {len(usage) - len(known)} tool(s) to check.", file=sys.stderr)
        else:
            print(text, end="")
        return 0

    if args.command == "policy":
        from guardlayer.policycheck import check_policy, configured_tools, format_report, to_json

        guard = build_guard(args.config)
        tools = list(args.tools or [])
        if args.claude_code:
            from guardlayer.integrations import claude_code

            claude_code.configure_guard(guard)
            tools += [t for t in claude_code.CLAUDE_CODE_CAPABILITIES if t not in tools]
        if not tools:
            tools = configured_tools(guard)
        if not tools:
            print("No tools to check: pass --tools NAME ..., or --claude-code, or name tools in the config.", file=sys.stderr)
            return 2
        reports, global_warnings = check_policy(guard, tools)
        print(json.dumps(to_json(reports, global_warnings), indent=2) if args.json else format_report(reports, global_warnings))
        warned = any(rep.warnings for rep in reports) or bool(global_warnings)
        return 1 if args.strict and warned else 0

    if args.command == "hook":
        from guardlayer.integrations import claude_code, hookserver

        config = Path(args.config).resolve().as_posix() if args.config else None
        state_dir = Path(args.state_dir).expanduser().resolve().as_posix() if args.state_dir else None
        port = args.port or hookserver.default_port(config, args.preset)
        extra = [*(["--state-dir", state_dir] if state_dir else []), *(["--block-prompts"] if args.block_prompts else []),
                 *(["--withhold-injections"] if args.withhold_injections else []),
                 *(["--token-env", args.token_env] if args.token_env else [])]  # fmt: skip
        if args.print_config:
            command = claude_code.default_command(args.config, args.preset)
            if state_dir:
                command += f' --state-dir "{state_dir}"'
            if args.block_prompts:
                command += " --block-prompts"
            if args.withhold_injections:
                command += " --withhold-injections"
            if args.server:
                ensure = command + f" --ensure-server --port {port}" + (f" --token-env {args.token_env}" if args.token_env else "")
                print(json.dumps(hookserver.settings_snippet(port, ensure, token_env=args.token_env), indent=2))
            else:
                print(json.dumps(claude_code.settings_snippet(command), indent=2))
            return 0
        token = os.environ.get(args.token_env) if args.token_env else None
        if args.token_env and not token:
            print(f"--token-env {args.token_env}: that environment variable is empty", file=sys.stderr)
            return 2
        if args.ensure_server:
            start = [sys.executable, "-m", "guardlayer.cli", *(["--config", config] if config else []),
                     *(["--preset", args.preset] if args.preset else []), "hook", "claude-code", "--server", "--port", str(port), *extra]  # fmt: skip
            ok, message = hookserver.ensure_server(port, start, config=config, preset=args.preset, token=token)
            if not ok:  # shown to the user; tool calls go unchecked until the server runs
                print(json.dumps({"systemMessage": f"GuardLayer: {message}. Tool calls are NOT being checked until it runs."}))
            return 0
        if args.server:
            service = hookserver.HookService(lambda: claude_code.configure_guard(build_guard(config), state_dir), config=config,
                                             preset=args.preset, block_prompts=args.block_prompts, token=token,
                                             withhold=args.withhold_injections)  # fmt: skip
            server = hookserver.make_server(service, port)
            print(f"GuardLayer hook server on http://{hookserver.HOST}:{port}{hookserver.PATH} (pid {os.getpid()})", file=sys.stderr, flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            return 0
        guard = claude_code.configure_guard(build_guard(args.config), args.state_dir)
        return claude_code.run(guard, block_prompts=args.block_prompts, withhold=args.withhold_injections)

    if args.command == "serve":
        try:
            import uvicorn
        except ModuleNotFoundError:
            print("serve needs the 'api' extra: pip install 'guardlayer[api]'", file=sys.stderr)
            return 2
        if args.config:
            os.environ["GUARDLAYER_CONFIG"] = args.config
        uvicorn.run("guardlayer.api:app", host=args.host, port=args.port)
        return 0

    guard = build_guard(args.config)

    if args.command == "scan":
        text = args.text if args.text is not None else sys.stdin.read()
        result = guard.scan(text, args.direction, system_prompt=args.system_prompt)
        _print_result(result, args.json)
        return 1 if result.verdict >= Verdict(args.fail_on) else 0

    if args.command == "tool-call":
        raw = args.arguments if args.arguments is not None else sys.stdin.read()
        try:
            arguments = json.loads(raw) if raw.strip() else None
        except json.JSONDecodeError:
            arguments = raw
        result = guard.scan_tool_call(args.tool, arguments)
        if not args.json:
            print(f"tool: {args.tool}  capabilities: {', '.join(result.metadata['capabilities']) or 'none (untagged: every rule applies)'}")
        _print_result(result, args.json)
        return 1 if result.verdict >= Verdict(args.fail_on) else 0

    if args.command == "batch":
        worst = Verdict.ALLOW
        for line in Path(args.path).read_text(encoding="utf-8").split("\n"):  # not splitlines(): JSON strings may hold U+2028 etc.
            if not line.strip():
                continue
            item = json.loads(line)
            result = guard.scan(item["text"], item.get("direction", "input"))
            worst = max(worst, result.verdict)
            print(json.dumps({"verdict": result.verdict.value, "score": result.score, "rules": sorted({d.rule for d in result.detections}), "text": item["text"][:120]}, ensure_ascii=False))
        return 1 if worst >= Verdict(args.fail_on) else 0

    if args.command == "eval":
        from guardlayer.evaluation import evaluate, load_samples

        report = evaluate(guard, load_samples(args.path), positive=Verdict(args.positive))
        print(json.dumps(report.to_dict(), indent=2) if args.json else report.summary())
        return 0

    if args.command == "canary":
        c = guard.add_canary(args.prompt, echo=args.echo)
        print(json.dumps({"token": c.token, "prompt": c.prompt, "echo": c.echo}, indent=2))
        return 0

    return 0


def _audit(args: argparse.Namespace) -> int:
    from guardlayer.audit import AuditSigner, audit_report, format_audit_report, verify_audit_log

    if args.audit_command == "report":
        data = audit_report(args.path, since_days=args.since_days, min_verdict=args.min, latest=args.latest)
        print(json.dumps(data, indent=2) if args.json else format_audit_report(data))
        return 0
    if args.audit_command == "keygen":
        key, pub = Path(f"{args.prefix}.key"), Path(f"{args.prefix}.pub")
        if key.exists() or pub.exists():
            print(f"refusing to overwrite {key} / {pub}", file=sys.stderr)
            return 2
        signer = AuditSigner.generate()
        key.write_bytes(signer.private_pem())
        try:
            key.chmod(0o600)
        except OSError:  # pragma: no cover - some filesystems ignore it
            pass
        pub.write_bytes(signer.public_pem())
        print(f"wrote {key} (private: keep it out of the repo) and {pub} (key id {signer.key_id})")
        return 0

    report = verify_audit_log(args.path, public_key=args.public_key, expected_head=args.expected_head)
    print(report.summary())
    return 0 if report.ok else 1


def _evidence(args: argparse.Namespace) -> int:
    from guardlayer import compliance

    if args.evidence_command == "controls":
        for fw, title in compliance.FRAMEWORKS.items():
            print(f"{fw}  ({title})")
            for c in compliance.CONTROLS.values():
                if c.framework == fw:
                    print(f"  {c.id:<12} {c.title}")
        print(f"\n{compliance.DISCLAIMER}")
        return 0

    try:
        pack = compliance.build_evidence(
            args.path, public_key=args.public_key, expected_head=args.expected_head, frameworks=args.framework
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if not pack.verification.ok:
        print(f"audit log failed verification: {pack.verification.summary()}", file=sys.stderr)
        if not args.allow_unverified:
            print("refusing to export unverified evidence (use --allow-unverified to export it marked as such)", file=sys.stderr)
            return 1
    text = pack.render(args.format)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8", newline="")
        print(f"wrote {args.output}: {len(pack.records)} entries, {len(pack.control_summary())} controls", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
