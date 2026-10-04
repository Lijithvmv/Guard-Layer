"""The GuardLayer pipeline — run an ensemble of scanners and turn their signals into a decision.

Design: layered detection. No single detector is reliable against prompt injection,
so each scanner votes with Detections and a `Policy` decides what to do:

* per category/direction **actions** — score, block, flag, review, redact, or just log;
* a **noisy-or** aggregate of the scored severities, mapped to allow / flag / block
  via two thresholds (independent weak signals compound, never exceeding 1.0);
* **observe mode**, globally or per rule — detections are recorded and a `shadow_verdict`
  says what enforcement would have done, but nothing is blocked or rewritten;
* **fail-open or fail-closed** when a scanner raises.

The same guard filters prompts (`scan_input`), responses (`scan_output`) and
third-party content such as RAG chunks or tool results (`scan_context`), and wraps
LLM calls and agent tool calls (see `guardlayer.tools` for the tool-call policy).
"""

from __future__ import annotations

import dataclasses
import fnmatch
import functools
import inspect
import json
import logging
import re
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, TypeVar

from guardlayer.canary import Canary, CanaryManager
from guardlayer.consequence import consequence
from guardlayer.credentials import credential_flow
from guardlayer.extract import DEFAULT_EXTRACTORS, Extractor, extract, media_parts
from guardlayer.filelabels import FileLabelStore, written_paths
from guardlayer.intent import NEUTRAL_TASK, IntentCheck, Replay
from guardlayer.intent import acheck as _intent_acheck
from guardlayer.intent import check as _intent_check
from guardlayer.labels import BOTTOM as _BOTTOM_LABEL
from guardlayer.labels import Integrity, Label
from guardlayer.models import DIRECTIONS, Action, Category, Detection, Direction, ScanContext, ScanResult, Verdict
from guardlayer.scanners.base import Scanner
from guardlayer.scanners.heuristics import HeuristicScanner
from guardlayer.scanners.leakage import CanaryScanner, PromptLeakScanner
from guardlayer.scanners.links import LinkScanner
from guardlayer.scanners.obfuscation import ObfuscationScanner
from guardlayer.scanners.pii import PIIScanner
from guardlayer.scanners.policy import LimitsScanner
from guardlayer.scanners.secrets import SecretsScanner
from guardlayer.scanners.similarity import SimilarityScanner
from guardlayer.session import (
    HOSTILE_CATEGORIES,
    SEAM_CHARS,
    GuardSession,
    MemorySessionStore,
    SessionPolicy,
    SessionState,
    SessionStore,
    file_label_detections,
    judge_trigger,
    observe_content,
    observe_input,
    observe_label,
    observe_tool_call,
    remember_prompt,
    taint_detections,
    task_detections,
)
from guardlayer.shell import command_view
from guardlayer.tools import ToolPolicy, flatten_arguments

logger = logging.getLogger("guardlayer")

F = TypeVar("F", bound=Callable[..., Any])

DEFAULT_ACTIONS: dict[str, Action] = {
    Category.SECRET.value: Action.REDACT,
    f"output:{Category.PII.value}": Action.REDACT,
    f"input:{Category.PII.value}": Action.LOG,
    f"context:{Category.PII.value}": Action.LOG,
}


@dataclass
class Policy:
    """How detections become a verdict.

    `actions` maps a category — or a `"direction:category"` pair, which takes
    precedence — to an `Action`. Unlisted categories are scored. A detection that carries
    its own `action` (tool-policy rules do) uses that instead.

    `mode = "observe"` records everything but enforces nothing (shadow mode). `observe`
    lists detections to only observe even in enforce mode; `enforce` lists detections to
    keep enforcing in observe mode. Entries are globs matched against the rule name,
    `scanner:rule` and the category, e.g. `"heuristics:*"`, `"egress_raw_ip"`, `"pii"`.
    """

    flag_threshold: float = 0.4
    block_threshold: float = 0.8
    actions: dict[str, Action] = field(default_factory=lambda: dict(DEFAULT_ACTIONS))
    fail_closed: bool = False
    redaction_format: str = "[REDACTED:{rule}]"
    mode: Literal["enforce", "observe"] = "enforce"
    observe: list[str] = field(default_factory=list)
    enforce: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 0.0 <= self.flag_threshold <= self.block_threshold <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= flag <= block <= 1")
        if self.mode not in ("enforce", "observe"):
            raise ValueError("mode must be 'enforce' or 'observe'")
        self.actions = {key: Action(value) for key, value in self.actions.items()}
        self.observe, self.enforce = list(self.observe), list(self.enforce)

    def action_for(self, direction: str, category: str) -> Action:
        return self.actions.get(f"{direction}:{category}", self.actions.get(category, Action.SCORE))

    def is_observed(self, detection: Detection) -> bool:
        """True when this detection is recorded but not enforced."""
        keys = (f"{detection.scanner}:{detection.rule}", detection.rule, detection.category)

        def matches(patterns: list[str]) -> bool:
            return any(fnmatch.fnmatchcase(k, p) for p in patterns for k in keys)

        return matches(self.observe) or (self.mode == "observe" and not matches(self.enforce))


class GuardBlocked(Exception):
    """Raised by `protect`-wrapped calls when a prompt or response is blocked (or held for review)."""

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        rules = ", ".join(sorted({d.rule for d in result.detections})) or "policy"
        super().__init__(f"GuardLayer blocked {result.direction} (score {result.score}; {rules})")


def default_scanners(canaries: CanaryManager | None = None) -> list[Scanner]:
    """The zero-dependency default ensemble."""
    return [
        HeuristicScanner(),
        ObfuscationScanner(),
        SimilarityScanner(),
        SecretsScanner(),
        PIIScanner(),
        LimitsScanner(),
        CanaryScanner(canaries),
        PromptLeakScanner(),
        LinkScanner(),
    ]


class GuardLayer:
    """Filter LLM inputs, outputs and third-party context through a configurable scanner ensemble."""

    def __init__(
        self,
        scanners: Sequence[Scanner] | None = None,
        *,
        policy: Policy | None = None,
        flag_threshold: float | None = None,
        block_threshold: float | None = None,
        canaries: CanaryManager | None = None,
        auto_learn: bool = False,
        tool_allowlist: Iterable[str] | None = None,
        tool_policy: ToolPolicy | None = None,
        session_policy: SessionPolicy | None = None,
        sessions: SessionStore | None = None,
        hooks: Iterable[Callable[[ScanResult], None]] = (),
    ) -> None:
        self.policy = policy or Policy()
        if flag_threshold is not None or block_threshold is not None:
            self.policy = dataclasses.replace(
                self.policy,
                flag_threshold=self.policy.flag_threshold if flag_threshold is None else flag_threshold,
                block_threshold=self.policy.block_threshold if block_threshold is None else block_threshold,
            )
        self.canaries = canaries if canaries is not None else CanaryManager()
        self.scanners: list[Scanner] = list(scanners) if scanners else default_scanners(self.canaries)
        for scanner in self.scanners:  # share one canary registry
            if isinstance(scanner, CanaryScanner) and canaries is None:
                self.canaries = scanner.manager
        self.auto_learn = auto_learn
        self.tool_policy = tool_policy or ToolPolicy()
        if tool_allowlist is not None:
            self.tool_policy.allowlist = set(tool_allowlist)
        self.session_policy = session_policy or SessionPolicy()
        self.sessions: SessionStore = sessions if sessions is not None else MemorySessionStore()
        self._file_labels: FileLabelStore | None = None
        self.extractors: list[Extractor] = list(DEFAULT_EXTRACTORS)  # bytes -> text for PDFs, images... (guardlayer.extract)
        self._file_labels_for: object | None = None
        self.preset: str | None = None  # set by `from_preset` / a config with `preset = ...`
        self.hooks: list[Callable[[ScanResult], None]] = list(hooks)
        # Optional second-stage judge (guardlayer.judge): asked about calls the rules let through, only where they
        # can't see the harm. `judge_unavailable` is what a call gets when the judge doesn't answer.
        self.judge: Callable[..., Any] | None = None
        self.judge_unavailable: str = "review"

    # ------------------------------------------------------------------ construction helpers
    @classmethod
    def from_config(cls, source: str | Path | Mapping[str, Any]) -> GuardLayer:
        """Build a guard from a TOML/JSON file path or a config dict (see `guardlayer.config`)."""
        from guardlayer.config import build_guard

        return build_guard(source)

    @classmethod
    def from_preset(cls, name: str, overrides: Mapping[str, Any] | None = None) -> GuardLayer:
        """Build a guard from a named preset (see `guardlayer.presets`), with optional config overrides."""
        from guardlayer.config import build_guard

        return build_guard({**dict(overrides or {}), "preset": name})

    @property
    def tool_allowlist(self) -> set[str] | None:
        return self.tool_policy.allowlist

    @tool_allowlist.setter
    def tool_allowlist(self, value: Iterable[str] | None) -> None:
        self.tool_policy.allowlist = set(value) if value is not None else None

    @property
    def flag_threshold(self) -> float:
        return self.policy.flag_threshold

    @property
    def block_threshold(self) -> float:
        return self.policy.block_threshold

    def get_scanner(self, name: str) -> Scanner | None:
        return next((s for s in self.scanners if s.name == name), None)

    def add_hook(self, hook: Callable[[ScanResult], None]) -> None:
        self.hooks.append(hook)

    def session(self, session_id: str | None = None, *, task: str | None = None, task_args: Mapping[str, Any] | None = None) -> GuardSession:
        """A view of this guard bound to one session, so tool calls are judged by what came before.

        `task` puts the session under a task profile (see `guardlayer.tasks`), with `task_args` from the trusted request.
        """
        session = GuardSession(self, session_id)
        if task is not None:
            session.set_task(task, task_args)
        return session

    def _load_session(self, session: str | GuardSession | None) -> SessionState | None:
        if session is None:
            return None
        sid = session.id if isinstance(session, GuardSession) else str(session)
        return self.sessions.get(sid) or SessionState(sid)

    # ------------------------------------------------------------------ core scan
    def scan(
        self,
        text: str,
        direction: Direction = "input",
        *,
        context: ScanContext | None = None,
        **context_fields: Any,
    ) -> ScanResult:
        """Scan one text. Extra keyword args populate the `ScanContext`."""
        if direction not in DIRECTIONS:
            raise ValueError(f"direction must be one of {DIRECTIONS}")
        if not isinstance(text, str):
            raise TypeError(f"text must be str, not {type(text).__name__}")
        ctx = context or ScanContext(direction=direction, **context_fields)
        ctx.direction = direction
        return self._run(text, ctx)

    def scan_input(self, prompt: str, *, session: str | GuardSession | None = None, **context_fields: Any) -> ScanResult:
        """Scan a user prompt before it reaches the model."""
        state = self._load_session(session)
        if state is None:
            return self.scan(prompt, "input", **context_fields)
        context_fields["metadata"] = {**dict(context_fields.get("metadata") or {}), "session_id": state.id}
        result = self.scan(prompt, "input", **context_fields)
        observe_input(state, prompt, result)
        if self.judge is not None:
            remember_prompt(state, prompt)  # the judge needs the user's task in words; kept only with a judge
        self.sessions.put(state)
        return result

    def scan_output(
        self,
        response: str,
        *,
        prompt: str | None = None,
        system_prompt: str | None = None,
        canary: Canary | str | None = None,
        session: str | GuardSession | None = None,
        **context_fields: Any,
    ) -> ScanResult:
        """Scan a model response before it reaches the user (or a tool)."""
        if session is not None:
            sid = session.id if isinstance(session, GuardSession) else str(session)
            context_fields["metadata"] = {**dict(context_fields.get("metadata") or {}), "session_id": sid}
        tokens = list(context_fields.pop("canary_tokens", []))
        expected = context_fields.pop("expected_canary", None)
        if isinstance(canary, Canary):
            if canary.echo:
                expected = canary.token
            else:
                tokens.append(canary.token)
        elif isinstance(canary, str):
            if self.canaries.is_echo(canary):
                expected = canary
            else:
                tokens.append(canary)
        return self.scan(
            response, "output",
            prompt=prompt, system_prompt=system_prompt, canary_tokens=tokens, expected_canary=expected,
            **context_fields,
        )  # fmt: skip

    def scan_context(
        self, content: str, *, source: str | None = None, session: str | GuardSession | None = None, **context_fields: Any
    ) -> ScanResult:
        """Scan third-party content (RAG chunk, web page, email, tool result) for indirect injection.

        With a `session`, the content marks the session as having read untrusted content
        (and hostile / sensitive content, if found).
        """
        return self._scan_content(content, source=source, session=session, tool=None, **context_fields)

    def _scan_content(
        self, content: str, *, source: str | None, session: str | GuardSession | None, tool: str | None,
        extra: Sequence[Detection] = (), force_untrusted: bool = False, **context_fields: Any,
    ) -> ScanResult:
        metadata = dict(context_fields.pop("metadata", {}) or {})
        if source:
            metadata["source"] = source
        state = self._load_session(session)
        if state is not None:
            metadata["session_id"] = state.id
        # Results of remote tools (network/exec, untagged, or matching `remote_tools` such as
        # MCP or search tools) are untrusted: someone outside this machine could have written them.
        reaches_network = True if tool is None else self.tool_policy.is_remote(tool)
        if tool is not None and self.session_policy.default_integrity == "declared" and not (
            self.tool_policy.is_declared(tool) or self.session_policy.declares(tool)
        ):
            # A name can't establish trust: "read_file" on a shared drive, "get_channels", a calendar or a review
            # list carry text other people wrote. Only tools whose capabilities were declared (by you, or by an
            # integration for its own tools) are trusted when local.
            reaches_network = True
        policy = self.session_policy
        untrusted = state is not None and policy.enabled and (
            policy.is_untrusted(tool, reaches_network) or (force_untrusted and not policy.declared_trusted(tool))
        )
        ctx = ScanContext(direction="context", metadata=metadata, **context_fields)
        extra = [*extra, *(self._seam_detections(state.seam, content, ctx) if untrusted and state is not None and state.seam else [])]
        result = self._run(content, ctx, extra=extra)
        if state is not None:
            observe_content(
                self.session_policy, state, content, result,
                source=source or "context", tool=tool, can_reach_network=reaches_network, untrusted=untrusted,
            )  # fmt: skip
            if force_untrusted and untrusted:
                observe_label(state, Label(Integrity.UNTRUSTED), f"unreadable:{source or tool}")
            if untrusted:
                state.seam = result.text[-SEAM_CHARS:]  # redacted text, so no secret is kept in the session
            self.sessions.put(state)
        return result

    def _seam_detections(self, seam: str, content: str, ctx: ScanContext) -> list[Detection]:
        """An injection split across the previous untrusted content and this one.

        Scans the end of the previous content joined to the start of this one. Only findings that neither piece has on
        its own count (each piece is scanned separately anyway), reported as one `split_injection` detection.
        """
        head = content[: 2 * SEAM_CHARS]
        joined, alone = seam + "\n" + head, head
        found: dict[str, Detection] = {}
        for scanner in self.scanners:
            if "context" not in getattr(scanner, "directions", DIRECTIONS):
                continue
            try:
                joined_dets = [d for d in scanner.scan(joined, ctx) if d.category in HOSTILE_CATEGORIES]
                if not joined_dets:
                    continue
                known = {d.rule for d in scanner.scan(alone, ctx)} | {d.rule for d in scanner.scan(seam, ctx)}
            except Exception:  # the main scan reports scanner errors
                continue
            for d in joined_dets:
                if d.rule not in known:
                    found.setdefault(d.rule, d)
        if not found:
            return []
        worst = max(found.values(), key=lambda d: d.severity)
        return [Detection("session", "split_injection", worst.category, worst.severity,
                          "An injection is split across this content and the previous untrusted content "
                          f"({', '.join(sorted(found))} only matches when the two are read together).",
                          metadata={"rules": sorted(found)})]  # fmt: skip

    def scan_batch(self, texts: Iterable[str], direction: Direction = "input", **context_fields: Any) -> list[ScanResult]:
        return [self.scan(t, direction, **context_fields) for t in texts]

    # ------------------------------------------------------------------ agents
    @property
    def file_labels(self) -> FileLabelStore:
        """Labels of files written in an untrusted or sensitive context (see `guardlayer.filelabels`).

        Stored next to the session state: a JSON file when sessions are on disk (shared across processes, as with the
        Claude Code hook), in memory otherwise.
        """
        if self._file_labels is None or self._file_labels_for is not self.sessions:
            directory = getattr(self.sessions, "dir", None)
            self._file_labels = FileLabelStore(Path(directory) / "file-labels.json" if directory else None)
            self._file_labels_for = self.sessions
        return self._file_labels

    def record_written(self, tool_name: str, arguments: Mapping[str, Any] | str | None, *, session: str | GuardSession | None) -> None:
        """After a write tool actually ran: label the files it wrote with the session's label.

        Integrations call this post-execution (the Claude Code hook's PostToolUse, `guard_tool`), which also covers
        writes a human approved after a REVIEW.
        """
        state = self._load_session(session)
        caps, tagged = self.tool_policy.resolve(tool_name)
        if state is not None and (not tagged or "write" in caps) and state.label != _BOTTOM_LABEL:
            self.file_labels.record(written_paths(arguments), state.label)

    def scan_tool_call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | str | None = None,
        *,
        session: str | GuardSession | None = None,
        scan_content: bool | None = None,
        **context_fields: Any,
    ) -> ScanResult:
        """Scan a model-proposed tool call (name + arguments) before executing it.

        Runs the tool policy (allow/deny lists, capability actions, argument and egress rules)
        and, with a `session`, the taint rules (what the session has already read decides what
        it may do next). The content scanners also run over the arguments, except for tools
        tagged read-only (`scan_content=None`, the default), whose arguments cannot cause harm.
        A REVIEW verdict means: ask a human first.
        """
        caps, tagged = self.tool_policy.resolve(tool_name)
        remote = self.tool_policy.is_remote(tool_name)
        arguments_text = flatten_arguments(arguments)  # original text: file labels and secret fingerprints use it
        # Rules judge what a shell command executes, not every string in it (see `guardlayer.shell`).
        view = command_view(tool_name, arguments) if (not tagged or "exec" in caps) else None
        rule_arguments = {**arguments, view[0]: view[1]} if view is not None and isinstance(arguments, Mapping) else arguments
        rule_text = flatten_arguments(rule_arguments)
        payload = rule_arguments if isinstance(rule_arguments, str) else json.dumps(rule_arguments or {}, ensure_ascii=False, default=str)
        extra = self.tool_policy.evaluate(tool_name, rule_arguments)
        if view is not None and any(d.rule == "credential_access" for d in extra):
            extra = self._bind_credentials(tool_name, str(arguments[view[0]]), extra)  # type: ignore[index]
        metadata = {
            **dict(context_fields.pop("metadata", {}) or {}),
            "tool": tool_name,
            "capabilities": sorted(caps),
            "remote": remote,
            "command_view": "parsed" if view is not None else "text",
        }
        if remote:
            extra += self._secrets_in_egress(tool_name, rule_text)
        state = self._load_session(session)
        refs: list[tuple[str, Label]] = []
        if state is not None:
            metadata["session_id"] = state.id
            refs = self.file_labels.referenced(arguments, arguments_text)
            for path, label in refs:  # a labelled file the call mentions: the session has now, in effect, read it
                observe_label(state, label, f"file:{path}")
            extra += file_label_detections(self.session_policy, tool_name, caps, tagged, refs)
            extra += task_detections(self.session_policy, state, tool_name, arguments)
            metadata["session"] = {"untrusted": state.untrusted, "hostile": state.hostile, "sensitive": state.sensitive,
                                   "label": state.label.to_dict(), "task": state.task}  # fmt: skip
            extra += taint_detections(self.session_policy, state, tool_name, caps, tagged, arguments_text, remote=remote,
                                      arguments=arguments)  # fmt: skip
        if scan_content is None:
            scan_content = self.tool_policy.can_act(tool_name)
        ctx = ScanContext(direction="output", metadata=metadata, **context_fields)
        result = self._run(payload, ctx, extra=extra, content=scan_content)
        if state is not None and self.judge is not None and result.verdict < Verdict.REVIEW:
            result = self._judged(result, state, tool_name, caps, tagged, arguments, remote, refs, payload, ctx)
        if state is not None:
            observe_tool_call(state, tool_name, result)
            # Record only what runs without a human in between; a reviewed write is recorded after it ran
            # (`record_written`), because a refused one never happened.
            if result.verdict < Verdict.REVIEW and (not tagged or "write" in caps) and state.label != _BOTTOM_LABEL:
                self.file_labels.record(written_paths(arguments), state.label)
            self.sessions.put(state)
        return result

    def _judged(
        self, result: ScanResult, state: SessionState, tool_name: str, caps: frozenset[str], tagged: bool,
        arguments: Any, remote: bool, refs: list[tuple[str, Label]], payload: str, ctx: ScanContext,
    ) -> ScanResult:
        """Ask the second-stage judge about a call the rules let through, where they can't see the harm."""
        kind = consequence(tool_name, caps, tagged, arguments if arguments is not None else payload, remote=remote,
                           declared=self.session_policy.declared_consequence(tool_name))  # fmt: skip
        why = judge_trigger(self.session_policy, state, tool_name, kind, arguments, refs)
        if why is None:
            return result
        verdict = self.judge(state.user_prompts, tool_name, arguments)  # type: ignore[misc]
        if verdict.requested is True:
            return result
        action = "review" if verdict.requested is False else self.judge_unavailable
        if action == "allow":
            return result
        message = (f"A check of your messages found this action doesn't serve your task: {verdict.reason}"
                   if verdict.requested is False else f"The action check couldn't answer ({verdict.reason}).")  # fmt: skip
        det = Detection("judge", "not_the_users_goal" if verdict.requested is False else "judge_unavailable",
                        Category.PROMPT_INJECTION.value, 0.7, message,
                        metadata={"trigger": why, "consequence": kind}, action=action)  # fmt: skip
        return self._decide(payload, ctx, [*result.detections, det], list(result.errors))

    # ------------------------------------------------------------------ behavioural check
    def needs_intent_check(self, tool_name: str, *, session: str | GuardSession | None = None) -> bool:
        """Is `check_intent` worth a model call for this tool call?

        Only for tools that can act (network, exec, write, or untagged), and, with a session, only once the session has
        read untrusted content: before that, nothing but the user can be driving the agent.
        """
        if not self.tool_policy.can_act(tool_name):
            return False
        state = self._load_session(session)
        return state is None or state.untrusted or state.hostile

    def check_intent(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | str | None,
        *,
        messages: Sequence[Mapping[str, Any]],
        replay: Replay,
        session: str | GuardSession | None = None,
        task: str = NEUTRAL_TASK,
        **context_fields: Any,
    ) -> ScanResult:
        """Behavioural hijack check (see `guardlayer.intent`): replay the conversation with the user's request hidden.

        `replay(masked_messages)` calls your model and returns the tool calls it proposes. If it proposes this same
        action anyway, the action is driven by content the agent read: `injection_driven_action` (review by default).
        Language- and wording-independent; one extra model call, so use `needs_intent_check` to pick risky calls.
        """
        outcome = _intent_check(tool_name, arguments, messages, replay, task=task)
        return self._intent_result(tool_name, arguments, outcome, session, context_fields)

    async def acheck_intent(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | str | None,
        *,
        messages: Sequence[Mapping[str, Any]],
        replay: Callable[..., Any],
        session: str | GuardSession | None = None,
        task: str = NEUTRAL_TASK,
        **context_fields: Any,
    ) -> ScanResult:
        """`check_intent` with an async `replay`."""
        outcome = await _intent_acheck(tool_name, arguments, messages, replay, task=task)
        return self._intent_result(tool_name, arguments, outcome, session, context_fields)

    def _intent_result(self, tool_name: str, arguments: Any, outcome: IntentCheck, session: Any, context_fields: dict) -> ScanResult:
        actions = self.session_policy.actions
        info = {"driven_by_content": outcome.driven_by_content, "replayed": [name for name, _ in outcome.replayed][:20]}
        detections = []
        if outcome.error:
            info["error"] = outcome.error
            detections.append(Detection("session", "intent_check_failed", Category.POLICY.value, 0.0,
                                        f"Couldn't run the behavioural check for {tool_name!r}: {outcome.error}",
                                        metadata={"tool": tool_name}, action=actions["intent_check_failed"].value))  # fmt: skip
        elif outcome.driven_by_content:
            detections.append(Detection("session", "injection_driven_action", Category.PROMPT_INJECTION.value, 0.9,
                                        f"With the user's request hidden, the model still proposes {tool_name!r} with the same "
                                        "destination: the action is driven by content the agent read.",
                                        metadata={"tool": tool_name}, action=actions["injection_driven_action"].value))  # fmt: skip
        metadata = {**dict(context_fields.pop("metadata", {}) or {}), "tool": tool_name, "intent": info}
        state = self._load_session(session)
        if state is not None:
            metadata["session_id"] = state.id
        payload = arguments if isinstance(arguments, str) else json.dumps(arguments or {}, ensure_ascii=False, default=str)
        return self._run(payload, ScanContext(direction="output", metadata=metadata, **context_fields), extra=detections, content=False)

    def _bind_credentials(self, tool_name: str, command: str, extra: list[Detection]) -> list[Detection]:
        """Judge a fetched credential by where it goes (`guardlayer.credentials`): kept in a variable and used only
        toward its own service is fine; printed into the transcript or sent elsewhere is not."""
        flow = credential_flow(command)
        if flow in ("", "unknown"):
            return extra
        rest = [d for d in extra if d.rule != "credential_access"]
        if flow == "bound":
            rest.append(Detection("tool_policy", "credential_bound", Category.POLICY.value, 0.1,
                                  "A credential was fetched into a variable and used only toward its own service.",
                                  metadata={"tool": tool_name}))  # fmt: skip
        elif flow == "printed":
            rest.append(Detection("tool_policy", "credential_exposed", Category.DATA_EXFILTRATION.value, 0.9,
                                  "This prints a live credential into the agent's context. Capture it in a variable "
                                  "(TOKEN=$(...)) and use it only toward its own service.",
                                  metadata={"tool": tool_name},
                                  action=self.tool_policy.rule_actions.get("credential_exposed", Action.BLOCK).value))  # fmt: skip
        else:
            rest.append(Detection("tool_policy", "credential_exfiltration", Category.DATA_EXFILTRATION.value, 1.0,
                                  "A fetched credential is being sent to a host other than the service it belongs to.",
                                  metadata={"tool": tool_name},
                                  action=self.tool_policy.rule_actions.get("credential_exfiltration", Action.BLOCK).value))  # fmt: skip
        return rest

    def _secrets_in_egress(self, tool_name: str, arguments_text: str) -> list[Detection]:
        """A secret in the arguments of a call that leaves the machine needs a human.

        Redacting it would not help: integrations run the tool with the original arguments,
        so the secret would leave unredacted. Uses the guard's own secrets scanner(s), so
        disabling the `secrets` scanner also disables this check.
        """
        if not arguments_text or "secret_in_egress" in self.tool_policy.disabled_rules:
            return []
        found: list[Detection] = []
        ctx = ScanContext(direction="output", metadata={"tool": tool_name})
        for scanner in self.scanners:
            if isinstance(scanner, SecretsScanner):
                found += scanner.scan(arguments_text, ctx)
        if not found:
            return []
        kinds = sorted({d.rule for d in found})
        return [
            Detection(
                "tool_policy", "secret_in_egress", Category.DATA_EXFILTRATION.value, 0.9,
                f"Tool {tool_name!r} would send a secret out of the machine ({', '.join(kinds)}).",
                metadata={"tool": tool_name, "secrets": kinds},
                action=self.tool_policy.rule_actions.get("secret_in_egress", Action.REVIEW).value,
            )
        ]  # fmt: skip

    def scan_tool_result(
        self, tool_name: str, result: Any, *, session: str | GuardSession | None = None,
        arguments: Mapping[str, Any] | str | None = None, **context_fields: Any,
    ) -> ScanResult:  # fmt: skip
        """Scan what a tool returned before the model reads it (indirect injection channel).

        With a `session`, results from network-capable (or untagged) tools mark the session
        untrusted, injections mark it hostile, and secrets/PII mark it sensitive. Pass the call's `arguments` so a
        file the agent wrote after reading untrusted content is read back as untrusted, whatever tool reads it.
        """
        read_back = False
        if arguments is not None and session is not None:
            refs = self.file_labels.referenced(arguments, flatten_arguments(arguments))
            read_back = any(label.integrity >= Integrity.UNTRUSTED for _, label in refs)
        parts = None if isinstance(result, str) else media_parts(result)
        if parts is None:
            text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
            return self._scan_content(text, source=f"tool:{tool_name}", session=session, tool=tool_name,
                                      force_untrusted=read_back, **context_fields)  # fmt: skip
        # Bytes or media blocks: scan what can be extracted; what can't be read makes the session untrusted.
        texts, blobs = parts
        extracted, unreadable = extract(blobs, self.extractors)
        extra = []
        if unreadable:
            extra.append(Detection("session", "unreadable_content", Category.POLICY.value, 0.0,
                                   f"Couldn't read {', '.join(sorted(set(unreadable)))} content; treated as untrusted.",
                                   metadata={"media": unreadable[:10]}, action=Action.LOG.value))  # fmt: skip
        return self._scan_content("\n\n".join([*texts, *extracted]), source=f"tool:{tool_name}", session=session,
                                  tool=tool_name, extra=extra, force_untrusted=bool(unreadable) or read_back, **context_fields)  # fmt: skip

    # ------------------------------------------------------------------ canaries
    def add_canary(self, prompt: str, *, echo: bool = False) -> Canary:
        """Embed a canary token in a (system) prompt; pass the returned Canary to `scan_output`."""
        return self.canaries.add(prompt, echo=echo)

    # ------------------------------------------------------------------ async
    async def ascan(self, text: str, direction: Direction = "input", **kwargs: Any) -> ScanResult:
        return await _to_thread(functools.partial(self.scan, text, direction, **kwargs))

    async def ascan_input(self, prompt: str, **kwargs: Any) -> ScanResult:
        return await _to_thread(functools.partial(self.scan_input, prompt, **kwargs))

    async def ascan_output(self, response: str, **kwargs: Any) -> ScanResult:
        return await _to_thread(functools.partial(self.scan_output, response, **kwargs))

    async def ascan_context(self, content: str, **kwargs: Any) -> ScanResult:
        return await _to_thread(functools.partial(self.scan_context, content, **kwargs))

    # ------------------------------------------------------------------ wrapping LLM calls
    def protect(
        self,
        func: F | None = None,
        *,
        system_prompt: str | None = None,
        on_block: str = "raise",
        blocked_message: str = "Sorry, I can't help with that request.",
    ) -> Any:
        """Decorate `fn(prompt, *args, **kwargs) -> str` (sync or async) with input and output filtering.

        The wrapped function receives the (possibly redacted) prompt, and the caller gets the
        (possibly redacted) response. On a BLOCK it raises `GuardBlocked`, or returns
        `blocked_message` when `on_block="message"`. Non-string responses pass through unscanned.
        """
        if on_block not in {"raise", "message"}:
            raise ValueError("on_block must be 'raise' or 'message'")

        def blocked(result: ScanResult) -> str:
            if on_block == "raise":
                raise GuardBlocked(result)
            return blocked_message

        def decorator(fn: F) -> F:
            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(prompt: str, *args: Any, **kwargs: Any) -> Any:
                    inbound = await self.ascan_input(prompt, system_prompt=system_prompt)
                    if not inbound.allowed:
                        return blocked(inbound)
                    response = await fn(inbound.text, *args, **kwargs)
                    if not isinstance(response, str):
                        return response
                    outbound = await self.ascan_output(response, prompt=inbound.text, system_prompt=system_prompt)
                    return outbound.text if outbound.allowed else blocked(outbound)

                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(fn)
            def wrapper(prompt: str, *args: Any, **kwargs: Any) -> Any:
                inbound = self.scan_input(prompt, system_prompt=system_prompt)
                if not inbound.allowed:
                    return blocked(inbound)
                response = fn(inbound.text, *args, **kwargs)
                if not isinstance(response, str):
                    return response
                outbound = self.scan_output(response, prompt=inbound.text, system_prompt=system_prompt)
                return outbound.text if outbound.allowed else blocked(outbound)

            return wrapper  # type: ignore[return-value]

        return decorator(func) if func is not None else decorator

    # ------------------------------------------------------------------ internals
    def _run(self, text: str, ctx: ScanContext, *, extra: Sequence[Detection] = (), content: bool = True) -> ScanResult:
        started = time.perf_counter()
        detections: list[Detection] = list(extra)
        errors: list[str] = []
        timings: dict[str, float] = {}

        for scanner in self.scanners if content else ():
            if ctx.direction not in getattr(scanner, "directions", DIRECTIONS):
                continue
            t0 = time.perf_counter()
            try:
                detections.extend(scanner.scan(text, ctx))
            except Exception as exc:  # a broken scanner must not take the app down
                errors.append(f"{scanner.name}: {type(exc).__name__}: {exc}")
                logger.exception("scanner %s failed", scanner.name)
            timings[scanner.name] = round((time.perf_counter() - t0) * 1000, 3)

        result = self._decide(text, ctx, detections, errors)
        result.timings_ms = timings
        result.latency_ms = round((time.perf_counter() - started) * 1000, 3)

        if self.auto_learn and result.is_blocked and ctx.direction != "output":
            self._learn(text, result)
        for hook in self.hooks:
            try:
                hook(result)
            except Exception:
                logger.exception("GuardLayer hook %r failed", hook)
        return result

    def _decide(self, text: str, ctx: ScanContext, detections: list[Detection], errors: list[str]) -> ScanResult:
        policy = self.policy
        observed = [policy.is_observed(d) for d in detections]
        enforced = [d for d, obs in zip(detections, observed, strict=True) if not obs]
        verdict, _, redact = self._evaluate(ctx.direction, enforced)
        full_verdict, score, _ = self._evaluate(ctx.direction, detections)  # the score reports risk, enforced or not

        fail = bool(errors) and policy.fail_closed
        if fail and policy.mode == "enforce":
            verdict = Verdict.BLOCK
        shadow: Verdict | None = None
        if any(observed) or (fail and policy.mode == "observe"):
            shadow = Verdict.BLOCK if fail else full_verdict

        sanitized = self._redact(text, redact) if redact else text
        return ScanResult(
            verdict=verdict,
            score=round(score, 3),
            direction=ctx.direction,
            detections=detections,
            text=sanitized,
            modified=sanitized != text,
            errors=errors,
            metadata=dict(ctx.metadata),
            shadow_verdict=shadow,
            observed_rules=sorted({d.rule for d, obs in zip(detections, observed, strict=True) if obs}),
        )

    def _evaluate(self, direction: str, detections: Sequence[Detection]) -> tuple[Verdict, float, list[Detection]]:
        """Apply actions: returns (verdict, noisy-or score of the scored detections, detections to redact)."""
        scored: list[Detection] = []
        redact: list[Detection] = []
        forced = Verdict.ALLOW
        for d in detections:
            action = Action(d.action) if d.action else self.policy.action_for(direction, d.category)
            if action is Action.SCORE:
                scored.append(d)
            elif action is Action.BLOCK:
                forced = Verdict.BLOCK
            elif action is Action.REVIEW:
                forced = max(forced, Verdict.REVIEW)
            elif action is Action.FLAG:
                forced = max(forced, Verdict.FLAG)
            elif action is Action.REDACT:
                redact.append(d)
        score = self._aggregate(scored)
        return max(self._verdict(score), forced), score, redact

    @staticmethod
    def _aggregate(detections: Iterable[Detection]) -> float:
        """Noisy-or: 1 - Π(1 - severity). Only the strongest hit per rule counts."""
        best: dict[tuple[str, str], float] = {}
        for d in detections:
            key = (d.scanner, d.rule)
            best[key] = max(best.get(key, 0.0), d.severity)
        product = 1.0
        for severity in best.values():
            product *= 1.0 - severity
        return 1.0 - product

    def _verdict(self, score: float) -> Verdict:
        if score >= self.policy.block_threshold:
            return Verdict.BLOCK
        if score >= self.policy.flag_threshold:
            return Verdict.FLAG
        return Verdict.ALLOW

    def _redact(self, text: str, detections: Sequence[Detection]) -> str:
        located = [(d.span, d) for d in detections if d.span and d.span[0] < d.span[1]]
        # Every copy of a detected value goes, not only the matched one: a key glued to other text ("0AKIA...") doesn't
        # match the pattern but is the same secret (found by the property tests). One pass over the text, looking up
        # each position's first 8 characters, keeps this linear however many values there are.
        by_prefix: dict[str, list[tuple[str, Detection]]] = {}
        for (start, end), d in located:
            tokens = re.findall(r"[A-Za-z0-9_\-+/.@]{8,}", text[start:end])
            for value in {text[start:end], *([max(tokens, key=len)] if tokens else [])}:  # the match and its value token
                if len(value) >= 8 and all(v != value for v, _ in by_prefix.get(value[:8], ())):
                    by_prefix.setdefault(value[:8], []).append((value, d))
        if by_prefix:
            for i in range(len(text) - 7):
                for value, d in by_prefix.get(text[i : i + 8], ()):
                    if text.startswith(value, i):
                        located.append(((i, i + len(value)), d))
        spans = sorted(located, key=lambda pair: pair[0])
        merged: list[tuple[int, int, Detection]] = []
        for (start, end), d in spans:
            if merged and start < merged[-1][1]:
                prev_start, prev_end, prev_d = merged[-1]
                merged[-1] = (prev_start, max(prev_end, end), prev_d)
            else:
                merged.append((start, end, d))
        out, cursor = [], 0
        for start, end, d in merged:
            out.append(text[cursor:start])
            out.append(self.policy.redaction_format.format(rule=d.rule.upper(), category=d.category.upper()))
            cursor = end
        out.append(text[cursor:])
        return "".join(out)

    def _learn(self, text: str, result: ScanResult) -> None:
        # Learn only from verdicts other scanners reached, so the store can't feed on itself.
        if all(d.scanner == "similarity" for d in result.detections):
            return
        for scanner in self.scanners:
            learn = getattr(scanner, "learn", None)
            if callable(learn):
                try:
                    learn(text, result_id=result.id, rules=sorted({d.rule for d in result.detections}))
                except Exception:
                    logger.exception("auto-learn failed for %s", scanner.name)


# Short alias.
Guard = GuardLayer


async def _to_thread(fn: Callable[[], ScanResult]) -> ScanResult:
    import asyncio  # imported lazily: asyncio (and the ssl it pulls in) costs ~0.3 s at startup

    return await asyncio.to_thread(fn)
