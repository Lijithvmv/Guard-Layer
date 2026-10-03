"""Replay Claude Code session transcripts through GuardLayer: how often would it have stopped real work?

Claude Code keeps every session as a JSONL transcript (`~/.claude/projects/<project>/<session>.jsonl`): the user's
prompts, each tool call with its input, and each tool result. This script feeds them, in order, through the same
handling the Claude Code hook uses (`PreToolUse` -> `scan_tool_call`, `PostToolUse` -> `scan_tool_result` and file
labels, `UserPromptSubmit` -> `scan_input`) and counts the tool calls that would have been held for approval or
refused, by rule. Nothing is run and nothing leaves the machine.

It exists because an audit log stores hashes, not text, so it can't be replayed; the transcripts can.

Privacy: the output holds counts, rule names, tool names and times. With `--show-sources` it also lists *where* each
taint came from (a file path or URL for Read/Grep/Glob/WebFetch, a short hash of the command for shell tools), never
the content.

`--clear-after-hostile` simulates a person clearing the hostile taint right after each read that caused it (the best
case for the "clear" design: someone who checks at once). Secret fingerprints and file labels are kept, as the design
requires. The result reports approvals *and* the number of clear decisions, since both cost a person's attention.

Limits, stated plainly:
- It's a replay: the agent never saw GuardLayer's answer, so this measures whether GuardLayer would have stepped in,
  not what the agent would have done next.
- The transcript's tool result is the text the model saw, which can differ slightly from the hook's `tool_response`.
- Sub-agent transcripts are not included.
- File labels resolve relative paths against *this process's* working directory, as the hook server does (pilot
  finding 7): run it from the directory the hook server started in, or `untrusted_file_executed` will differ.

Checked against the pilot's audit log for day 1 (2026-10-02, 86 tool calls): the same rules on every call.

    cd <project>; python <GuardLayer>/benchmarks/transcript_replay.py ~/.claude/projects/<project> --since 2026-10-02T08:45:00Z
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
import tempfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardlayer import __version__
from guardlayer.config import build_guard
from guardlayer.consequence import consequence, distinctive_values
from guardlayer.integrations.claude_code import _scan_output_of, configure_guard, handle_event, policy_view
from guardlayer.models import Category, Verdict
from guardlayer.session import HOSTILE_CATEGORIES, _carried
from guardlayer.tools import flatten_arguments

_PATH_TOOLS = {"Read": "file_path", "Grep": "path", "Glob": "path", "WebFetch": "url", "WebSearch": "query"}


def parse_time(value: str) -> datetime:
    t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def result_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
    return ""


def events(path: Path) -> Iterator[tuple[datetime, dict[str, Any]]]:
    """Hook-shaped events from one transcript, in order."""
    inputs: dict[str, tuple[str, dict[str, Any]]] = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("type") not in ("user", "assistant") or row.get("isMeta") or row.get("isCompactSummary"):
                continue
            when = parse_time(row["timestamp"]) if row.get("timestamp") else None
            if when is None:
                continue
            base = {"session_id": row.get("sessionId") or path.stem, "cwd": row.get("cwd")}
            content = (row.get("message") or {}).get("content")
            if row["type"] == "assistant" and isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        tool_input = block.get("input") or {}
                        inputs[block["id"]] = (block["name"], tool_input)
                        yield when, {**base, "hook_event_name": "PreToolUse", "tool_name": block["name"],
                                     "tool_input": tool_input, "tool_use_id": block["id"]}  # fmt: skip
            elif row["type"] == "user":
                if isinstance(content, str):
                    yield when, {**base, "hook_event_name": "UserPromptSubmit", "prompt": content}
                    continue
                if not isinstance(content, list):
                    continue
                texts = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
                for block in content:
                    if (
                        isinstance(block, dict)
                        and block.get("type") == "tool_result"
                        and block.get("tool_use_id") in inputs
                    ):
                        tool, tool_input = inputs[block["tool_use_id"]]
                        yield when, {**base, "hook_event_name": "PostToolUse", "tool_name": tool, "tool_input": tool_input,
                                     "tool_response": result_text(block.get("content")), "tool_use_id": block["tool_use_id"]}  # fmt: skip
                if texts and not any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
                    yield when, {**base, "hook_event_name": "UserPromptSubmit", "prompt": "\n".join(texts)}


def where(tool: str, tool_input: dict[str, Any]) -> str:
    key = _PATH_TOOLS.get(tool)
    if key and tool_input.get(key):
        return str(tool_input[key])[:200]
    return "sha256:" + hashlib.sha256(json.dumps(tool_input, sort_keys=True).encode()).hexdigest()[:12]


class _ScanCache:
    """Detector results cached on disk across replays.

    What a detector finds in a text doesn't depend on the session rules being evaluated, so re-running the detectors
    on 17k tool results for every rule change only costs time (~45 min a replay). Session rules still run in full.
    Delete the cache file whenever a detector or its configuration changes.
    """

    def __init__(self, path: str) -> None:
        import pickle

        self.path, self.pickle = Path(path), pickle
        self.data: dict[tuple[str, str, str, str], list[Any]] = {}
        if self.path.exists():
            self.data = pickle.loads(self.path.read_bytes())
        self.hits = self.misses = 0

    def wrap(self, guard: Any) -> None:
        import copy

        for scanner in guard.scanners:
            original = scanner.scan

            def scan(text: str, ctx: Any, _orig: Any = original, _name: str = scanner.name) -> list[Any]:
                key = (_name, ctx.direction, str((ctx.metadata or {}).get("tool", "")),
                       hashlib.sha256(text.encode("utf-8", "replace")).hexdigest())  # fmt: skip
                if key in self.data:
                    self.hits += 1
                    return copy.deepcopy(self.data[key])
                self.misses += 1
                found = _orig(text, ctx)
                self.data[key] = copy.deepcopy(found)
                return found

            scanner.scan = scan

    def save(self) -> None:
        self.path.write_bytes(self.pickle.dumps(self.data))


def replay(paths: list[Path], args: argparse.Namespace) -> dict[str, Any]:
    state_dir = tempfile.mkdtemp(prefix="gl-replay-")
    guard = configure_guard(
        build_guard(args.config) if args.config else build_guard({"preset": args.preset}), state_dir
    )
    cache = _ScanCache(args.scan_cache) if args.scan_cache else None
    if cache is not None:
        cache.wrap(guard)
    since = parse_time(args.since) if args.since else None
    until = parse_time(args.until) if args.until else None
    totals: collections.Counter[str] = collections.Counter()
    by_rule: collections.Counter[str] = collections.Counter()
    triggers: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    sessions: dict[str, dict[str, int]] = {}
    judge = None
    if args.judge:
        from guardlayer.judge import OllamaJudge

        judge = OllamaJudge(args.judge, host=args.judge_host)
    asked: collections.Counter[str] = collections.Counter()
    prompts: dict[str, list[str]] = collections.defaultdict(list)
    # Identifiers seen anywhere in a session (the user's prompts and every tool result, trusted or not): an outbound
    # destination in none of them is novel, which no rewriting of an outsider's address can avoid.
    seen: dict[str, set[str]] = collections.defaultdict(set)
    for path in paths:
        for when, event in events(path):
            if (since and when < since) or (until and when >= until):
                continue
            sid = event["session_id"]
            per = sessions.setdefault(sid, collections.Counter())
            session = guard.session(sid)
            kind = event["hook_event_name"]
            if kind == "UserPromptSubmit":
                prompts[sid].append(str(event.get("prompt") or ""))
                seen[sid] |= distinctive_values(str(event.get("prompt") or ""))
            if kind == "PreToolUse":
                tool = event["tool_name"]
                meta = {
                    k: event[k] for k in ("cwd", "tool_use_id") if event.get(k)
                }  # as handle_event: cwd resolves relative paths
                result = session.scan_tool_call(
                    tool, policy_view(tool, event["tool_input"]), metadata={**meta, "source": "replay"}
                )
                totals["tool_calls"] += 1
                per["tool_calls"] += 1
                rules = sorted({d.rule for d in result.detections if d.action in ("review", "block")})
                calls.append({"tool_use_id": event["tool_use_id"], "tool": tool, "rules": rules,
                              "outcome": "refused" if result.is_blocked else "held" if result.needs_review else "ok"})  # fmt: skip
                if not (result.is_blocked or result.needs_review) and session.state.untrusted:
                    # Would the second-stage judge be asked? Irreversible actions, and outbound ones carrying a link
                    # that came from untrusted content and not from the user (see judge.py).
                    view = policy_view(tool, event["tool_input"])
                    caps, tagged = guard.tool_policy.resolve(tool)
                    cls = consequence(tool, caps, tagged, view)
                    text = json.dumps(view, default=str)
                    links = [v for v in _carried(text, session.state.untrusted_values, session.state.user_values)
                             if "." in v and "@" not in v]  # fmt: skip
                    hosts = {v for v in distinctive_values(text) if "." in v and "@" not in v and "/" not in v}
                    if cls == "outbound" and hosts - seen[sid]:
                        totals["novel_destination"] += 1
                        asked[f"novel:{tool}"] += 1
                    if cls == "irreversible" or (cls == "outbound" and links):
                        asked[f"{cls}:{tool}"] += 1
                        totals["judge_asked"] += 1
                        if judge is not None:
                            verdict = judge(prompts[sid], tool, view)
                            totals[f"judge_answer_{verdict.requested}"] += 1
                            if verdict.requested is False:
                                asked[f"NO {cls}:{tool}"] += 1
                if result.is_blocked or result.needs_review:
                    outcome = "refused" if result.is_blocked else "held"
                    totals[outcome] += 1
                    per[outcome] += 1
                    for d in result.detections:
                        if d.action in ("review", "block"):
                            by_rule[d.rule] += 1
                continue
            if kind != "PostToolUse":
                handle_event(event, guard)
                continue
            # The PostToolUse branch of handle_event, inline, so the scan result is visible here.
            tool = event["tool_name"]
            guard.record_written(tool, event.get("tool_input"), session=session)
            if not _scan_output_of(guard, tool):
                continue
            meta = {k: event[k] for k in ("cwd", "tool_use_id") if event.get(k)}
            seen[sid] |= distinctive_values(flatten_arguments(event.get("tool_response"))[:200_000])
            result = session.scan_tool_result(
                tool, flatten_arguments(event.get("tool_response")), metadata={**meta, "source": "replay"}
            )
            new_hostile = result.verdict >= Verdict.FLAG and bool(HOSTILE_CATEGORIES & set(result.categories))
            new_sensitive = Category.SECRET.value in set(result.categories) and bool(session.state.sensitive_sources)
            if new_hostile or new_sensitive:
                last = guard.sessions.get(sid)
                entry = {"time": when.isoformat(timespec="seconds"), "session": sid[:8], "tool": event["tool_name"],
                         "rules": sorted({d.rule for d in result.detections if d.category in HOSTILE_CATEGORIES | {Category.SECRET.value}}),
                         "made": sorted(({"hostile"} if new_hostile else set()) | ({"sensitive"} if new_sensitive else set()))}  # fmt: skip
                if args.show_sources:
                    entry["where"] = where(event["tool_name"], event["tool_input"])
                triggers.append(entry)
                if new_hostile and args.clear_after_hostile and last is not None:
                    # The file store merges on put (taint only grows, so concurrent hooks can't lose it); a clear
                    # has to replace the stored state, so: delete, then put the cleared copy.
                    last.hostile_sources = []
                    guard.sessions.delete(sid)
                    guard.sessions.put(last)
                    totals["clears"] += 1
                    per["clears"] += 1
    if cache is not None:
        cache.save()
        totals["scan_cache_hits"], totals["scan_cache_misses"] = cache.hits, cache.misses
    return {
        "guardlayer": __version__,
        "preset": None if args.config else args.preset,
        "config": args.config,
        "since": args.since,
        "until": args.until,
        "clear_after_hostile": args.clear_after_hostile,
        "transcripts": len(paths),
        "sessions": len([s for s in sessions.values() if s["tool_calls"]]),
        "totals": dict(totals),
        "held_or_refused_by_rule": dict(by_rule.most_common()),
        "judge": args.judge,
        "judge_asked_by_tool": dict(asked.most_common()),
        "per_session": {sid[:8]: dict(c) for sid, c in sessions.items() if c["tool_calls"]},
        "taint_events": triggers,
        **({"calls": calls} if args.calls else {}),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("paths", nargs="+", help="transcript .jsonl files or project directories")
    p.add_argument(
        "--preset", default="balanced", help="preset to replay with (default: balanced, what observe shadows)"
    )
    p.add_argument("--config", help="a GuardLayer config file instead of --preset")
    p.add_argument("--since", help="ISO time; only events at or after it (e.g. the pilot start)")
    p.add_argument("--until", help="ISO time; only events before it (e.g. the end of the dev days)")
    p.add_argument(
        "--clear-after-hostile", action="store_true", help="simulate a person clearing each hostile taint at once"
    )
    p.add_argument("--show-sources", action="store_true", help="list the path/URL (or command hash) behind each taint")
    p.add_argument(
        "--calls", action="store_true", help="include every tool call's outcome (ids, tool, rules; no content)"
    )
    p.add_argument("--judge", help="Ollama model: also ask the second-stage judge where it would be asked (slow)")
    p.add_argument("--judge-host", default="http://127.0.0.1:11434", help="Ollama server for --judge")
    p.add_argument("--scan-cache", help="file caching detector results across replays (delete it when detectors change)")
    p.add_argument("-o", "--output", help="write the JSON result here")
    args = p.parse_args(argv)
    paths: list[Path] = []
    for raw in args.paths:
        path = Path(raw).expanduser()
        paths += sorted(path.glob("*.jsonl")) if path.is_dir() else [path]
    out = replay(paths, args)
    text = json.dumps(out, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    t = out["totals"]
    print(f"{out['sessions']} sessions, {t.get('tool_calls', 0)} tool calls: held {t.get('held', 0)}, "
          f"refused {t.get('refused', 0)}, clears {t.get('clears', 0)}", file=sys.stderr)  # fmt: skip
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
