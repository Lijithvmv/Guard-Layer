"""Command-line interface: `guardlayer scan "<text>"`.

Reads text from the argument or, if omitted, from stdin. Exits non-zero when the
verdict is BLOCK, so it composes in shell pipelines and CI checks.
"""

from __future__ import annotations

import argparse
import json
import sys

from guardlayer import GuardLayer, Verdict, __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardlayer", description="Scan LLM text for prompt-injection / jailbreak signals.")
    parser.add_argument("--version", action="version", version=f"guardlayer {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a piece of text.")
    scan.add_argument("text", nargs="?", help="Text to scan (reads stdin if omitted).")
    scan.add_argument("--direction", choices=["input", "output"], default="input")
    scan.add_argument("--json", action="store_true", help="Emit the full result as JSON.")

    args = parser.parse_args(argv)

    if args.command == "scan":
        text = args.text if args.text is not None else sys.stdin.read()
        result = GuardLayer().scan(text, direction=args.direction)

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"verdict: {result.verdict.value.upper()}  (score {result.score})")
            for d in result.detections:
                print(f"  - [{d.scanner}:{d.rule}] {d.message} (severity {d.severity})")

        return 1 if result.verdict is Verdict.BLOCK else 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
