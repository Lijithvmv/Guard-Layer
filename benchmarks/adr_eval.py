"""Replay ADR-Bench's recorded agent sessions through GuardLayer: would it have stepped in?

ADR (Uber, Apache-2.0, https://github.com/uber/ADR) publishes 303 recorded sessions of a coding agent using 134 MCP
servers, each labelled benign (261) or malicious (43) in `Detection/tasks.json`. Nothing is run: every recorded event
goes through a GuardLayer session in order (the user prompt through `scan_input`, each tool call through
`scan_tool_call`, each tool result through `scan_tool_result`), and a session counts as **intervened** when any tool call
gets REVIEW or BLOCK, i.e. GuardLayer would have asked a human or refused before that action ran.

Limits, stated plainly:
- The recordings keep each tool call's *name* but not its arguments, so argument rules (commands, URLs, recipients,
  egress) can't fire here. What is tested is scanning what the agent read and the session rules that hold back the next
  action. Capabilities are inferred from tool names (`mcp__*` tools are remote), as for an undeclared deployment.
- It's a replay: the agent never saw GuardLayer's answer, so this measures *whether* GuardLayer would have intervened,
  not what the agent would have done next.

    git clone --depth 1 https://github.com/uber/ADR
    python benchmarks/adr_eval.py --adr <path to ADR>
"""

from __future__ import annotations

import argparse
import ast
import collections
import hashlib
import json
import sys
import time
from pathlib import Path

from guardlayer import Verdict, __version__
from guardlayer.config import build_guard

RECORDINGS = "Detection/benchmark/adr_bench_20251017_151604.jsonl"
SPLIT_SALT = "guardlayer-adr-split-v1:"  # fixed before any fix was written; fixes are studied on "dev" only


def is_heldout(task_id: str) -> bool:
    return int(hashlib.sha256((SPLIT_SALT + task_id).encode()).hexdigest(), 16) % 2 == 0


def result_text(content: str) -> tuple[str | None, str]:
    """(tool_use_id, text) from a recorded tool-result message (a Python repr of content blocks)."""
    try:
        blocks = ast.literal_eval(content)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return None, content
    if not isinstance(blocks, list):
        return None, content
    texts, use_id = [], None
    for block in blocks:
        if isinstance(block, dict):
            use_id = use_id or block.get("tool_use_id")
            inner = block.get("content")
            if isinstance(inner, list):
                texts += [b.get("text", "") for b in inner if isinstance(b, dict)]
            elif isinstance(inner, str):
                texts.append(inner)
    return use_id, "\n".join(texts)


def replay(guard, task_id: str, conversation: list[dict]) -> dict:  # type: ignore[no-untyped-def]
    session = guard.session(f"adr-{task_id}")
    names: dict[str, str] = {}
    rules: collections.Counter[str] = collections.Counter()
    intervened, content_flagged = False, False
    for m in conversation:
        kind = m.get("message_type")
        if kind == "user_prompt":
            session.scan_input(str(m.get("content") or ""))
        elif kind == "tool_calling":
            for call in m.get("tool_calls") or []:
                names[call.get("id", "")] = call.get("name", "")
                r = session.scan_tool_call(call.get("name", ""), call.get("input") or call.get("arguments") or {})
                if r.verdict >= Verdict.REVIEW:
                    intervened = True
                    rules.update(d.rule for d in r.detections if d.action in ("review", "block"))
        elif kind == "tool_result":
            use_id, text = result_text(str(m.get("content") or ""))
            r = session.scan_tool_result(names.get(use_id or "", "unknown_tool"), text)
            if r.verdict >= Verdict.FLAG:
                content_flagged = True
                rules.update(f"content:{d.rule}" for d in r.detections if d.severity >= 0.5)
    return {"intervened": intervened, "content_flagged": content_flagged, "rules": dict(rules)}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--adr", required=True, type=Path, help="path to a clone of github.com/uber/ADR")
    p.add_argument("--presets", default="balanced,strict")
    p.add_argument("--split", default="all", choices=["all", "dev", "heldout"], help="half of the sessions (fixed split)")
    p.add_argument("--out", default="benchmarks/results/adr-bench.jsonl")
    args = p.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    labels = {str(t["task_id"]): t["ground_truth"] for t in json.loads((args.adr / "Detection/tasks.json").read_text(encoding="utf-8"))["tasks"]}
    sessions = [r for r in map(json.loads, (args.adr / RECORDINGS).open(encoding="utf-8")) if r.get("type") == "task"]
    if args.split != "all":
        sessions = [s for s in sessions if is_heldout(s["task_id"]) == (args.split == "heldout")]
    for preset in args.presets.split(","):
        guard = build_guard({"preset": preset})
        t0 = time.perf_counter()
        counts = {g: collections.Counter() for g in ("malicious", "benign")}
        rules = {g: collections.Counter() for g in ("malicious", "benign")}
        for s in sessions:
            truth = labels.get(str(int(s["task_id"].split("_")[1])))
            if truth not in counts:
                continue
            out = replay(guard, s["task_id"], s["conversation"])
            counts[truth]["n"] += 1
            counts[truth]["intervened"] += out["intervened"]
            counts[truth]["content_flagged"] += out["content_flagged"]
            rules[truth].update(out["rules"])
        row = {"date": time.strftime("%Y-%m-%d"), "guardlayer": __version__, "preset": preset, "split": args.split, "benchmark": "ADR-Bench 20251017",
               "malicious": dict(counts["malicious"]), "benign": dict(counts["benign"]),
               "top_rules_malicious": rules["malicious"].most_common(8), "top_rules_benign": rules["benign"].most_common(8),
               "seconds": round(time.perf_counter() - t0, 1)}  # fmt: skip
        with Path(args.out).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
        m, b = counts["malicious"], counts["benign"]
        print(f"{preset:9} [{args.split}] malicious: intervened {m['intervened']}/{m['n']}, content flagged {m['content_flagged']}/{m['n']}   "
              f"benign: intervened {b['intervened']}/{b['n']}, content flagged {b['content_flagged']}/{b['n']}   {row['seconds']}s")  # fmt: skip
        print("   malicious rules:", rules["malicious"].most_common(6))
        print("   benign rules:   ", rules["benign"].most_common(6))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
