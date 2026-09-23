"""Command-line interface.

    guardlayer scan "text"                    # scan a prompt (reads stdin if no text)
    guardlayer scan --direction output < reply.txt
    guardlayer batch prompts.jsonl            # one {"text": ..., "direction": ...} per line
    guardlayer eval [dataset.jsonl]           # precision / recall / latency
    guardlayer canary "system prompt"         # embed a canary token
    guardlayer rules                          # list built-in signature rules
    guardlayer serve --port 8000              # REST API (needs the `api` extra)

`scan` exits 1 when the verdict is BLOCK (or at/above `--fail-on`), so it composes in CI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from guardlayer import __version__
from guardlayer.config import build_guard
from guardlayer.models import Verdict


def _print_result(result, as_json: bool) -> None:  # type: ignore[no-untyped-def]
    if as_json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return
    print(f"verdict: {result.verdict.value.upper()}  score {result.score}  ({result.latency_ms} ms)")
    for d in result.detections:
        print(f"  - [{d.scanner}:{d.rule}] {d.category} sev {d.severity:.2f}: {d.message}")
    if result.modified:
        print(f"sanitized: {result.text}")
    for err in result.errors:
        print(f"  ! scanner error: {err}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardlayer", description="Input/output security filtering for LLM and agent applications.")
    parser.add_argument("--version", action="version", version=f"guardlayer {__version__}")
    parser.add_argument("--config", help="TOML/JSON config file.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a piece of text.")
    scan.add_argument("text", nargs="?", help="Text to scan (reads stdin if omitted).")
    scan.add_argument("--direction", choices=["input", "output", "context"], default="input")
    scan.add_argument("--system-prompt", help="System prompt (enables leak detection on outputs).")
    scan.add_argument("--json", action="store_true", help="Emit the full result as JSON.")
    scan.add_argument("--fail-on", choices=["flag", "block"], default="block", help="Verdict that yields exit code 1.")

    batch = sub.add_parser("batch", help="Scan a JSONL file of {text, direction} records.")
    batch.add_argument("path")
    batch.add_argument("--fail-on", choices=["flag", "block"], default="block")

    ev = sub.add_parser("eval", help="Evaluate on a labelled JSONL dataset (default: bundled sample).")
    ev.add_argument("path", nargs="?")
    ev.add_argument("--positive", choices=["flag", "block"], default="flag", help="Minimum verdict counted as a detection.")
    ev.add_argument("--json", action="store_true")

    canary = sub.add_parser("canary", help="Embed a canary token in a prompt.")
    canary.add_argument("prompt")
    canary.add_argument("--echo", action="store_true", help="Goal-hijack mode: ask the model to echo the token.")

    sub.add_parser("rules", help="List built-in heuristic rules.")

    serve = sub.add_parser("serve", help="Run the REST API.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    args = parser.parse_args(argv)

    if args.command == "rules":
        from guardlayer.rules import DEFAULT_RULES

        for rule in DEFAULT_RULES:
            print(f"{rule.name:<30} {rule.category:<20} {rule.severity:.2f}  {','.join(sorted(rule.directions)):<22} {rule.message}")
        return 0

    if args.command == "serve":
        import os

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

    if args.command == "batch":
        worst = Verdict.ALLOW
        for line in Path(args.path).read_text(encoding="utf-8").splitlines():
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


if __name__ == "__main__":
    raise SystemExit(main())
