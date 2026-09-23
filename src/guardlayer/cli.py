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
    from guardlayer.audit import AuditSigner, verify_audit_log

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


if __name__ == "__main__":
    raise SystemExit(main())
