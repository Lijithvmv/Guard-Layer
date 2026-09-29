"""Export AgentDojo's benign environment texts (emails, files, messages, web pages, transactions) for false-positive tests.

Every injection placeholder is filled with its benign default, so nothing here is an attack. Run with AgentDojo installed
(`pip install agentdojo==0.1.35`, in a separate environment):

    python benchmarks/agentdojo_benign_texts.py        # -> benchmarks/data/agentdojo_benign.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suite


def strings(value, out: set[str], min_len: int) -> None:  # type: ignore[no-untyped-def]
    if isinstance(value, str):
        if len(value) >= min_len:
            out.add(value.strip())
    elif isinstance(value, dict):
        for v in value.values():
            strings(v, out, min_len)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            strings(v, out, min_len)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--benchmark-version", default="v1.2.2")
    p.add_argument("--suites", default="workspace,travel,banking,slack")
    p.add_argument("--min-length", type=int, default=20, help="skip short fields (names, IDs, amounts)")
    p.add_argument("--out", default="benchmarks/data/agentdojo_benign.jsonl")
    args = p.parse_args()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with out.open("w", encoding="utf-8") as fh:
        for name in args.suites.split(","):
            suite = get_suite(args.benchmark_version, name)
            env = suite.load_and_inject_default_environment({})  # no injections: placeholders get benign defaults
            texts: set[str] = set()
            strings(env.model_dump(mode="json"), texts, args.min_length)
            for text in sorted(texts):
                fh.write(json.dumps({"text": text, "label": 0, "suite": name}) + "\n")
            print(f"{name:10} {len(texts)} texts")
            total += len(texts)
    print(f"total {total} -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
