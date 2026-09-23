"""The GuardLayer pipeline — run an ensemble of scanners and turn their signals into a decision.

Design: layered detection. No single detector is reliable against prompt injection,
so each scanner votes with Detections and a `Policy` decides what to do:

* per category/direction **actions** — score, block, flag, redact, or just log;
* a **noisy-or** aggregate of the scored severities, mapped to allow / flag / block
  via two thresholds (independent weak signals compound, never exceeding 1.0);
* **fail-open or fail-closed** when a scanner raises.

The same guard filters prompts (`scan_input`), responses (`scan_output`) and
third-party content such as RAG chunks or tool results (`scan_context`), and wraps
LLM calls and agent tool calls.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import logging
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from guardlayer.canary import Canary, CanaryManager
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
    precedence — to an `Action`. Unlisted categories are scored.
    """

    flag_threshold: float = 0.4
    block_threshold: float = 0.8
    actions: dict[str, Action] = field(default_factory=lambda: dict(DEFAULT_ACTIONS))
    fail_closed: bool = False
    redaction_format: str = "[REDACTED:{rule}]"

    def __post_init__(self) -> None:
        if not 0.0 <= self.flag_threshold <= self.block_threshold <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= flag <= block <= 1")
        self.actions = {key: Action(value) for key, value in self.actions.items()}

    def action_for(self, direction: str, category: str) -> Action:
        return self.actions.get(f"{direction}:{category}", self.actions.get(category, Action.SCORE))


class GuardBlocked(Exception):
    """Raised by `protect`-wrapped calls when a prompt or response is blocked."""

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
        hooks: Iterable[Callable[[ScanResult], None]] = (),
    ) -> None:
        self.policy = policy or Policy()
        if flag_threshold is not None or block_threshold is not None:
            self.policy = Policy(
                flag_threshold=self.policy.flag_threshold if flag_threshold is None else flag_threshold,
                block_threshold=self.policy.block_threshold if block_threshold is None else block_threshold,
                actions=self.policy.actions,
                fail_closed=self.policy.fail_closed,
                redaction_format=self.policy.redaction_format,
            )
        self.canaries = canaries if canaries is not None else CanaryManager()
        self.scanners: list[Scanner] = list(scanners) if scanners else default_scanners(self.canaries)
        for scanner in self.scanners:  # share one canary registry
            if isinstance(scanner, CanaryScanner) and canaries is None:
                self.canaries = scanner.manager
        self.auto_learn = auto_learn
        self.tool_allowlist = set(tool_allowlist) if tool_allowlist is not None else None
        self.hooks: list[Callable[[ScanResult], None]] = list(hooks)

    # ------------------------------------------------------------------ construction helpers
    @classmethod
    def from_config(cls, source: str | Path | Mapping[str, Any]) -> GuardLayer:
        """Build a guard from a TOML/JSON file path or a config dict (see `guardlayer.config`)."""
        from guardlayer.config import build_guard

        return build_guard(source)

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

    def scan_input(self, prompt: str, **context_fields: Any) -> ScanResult:
        """Scan a user prompt before it reaches the model."""
        return self.scan(prompt, "input", **context_fields)

    def scan_output(
        self,
        response: str,
        *,
        prompt: str | None = None,
        system_prompt: str | None = None,
        canary: Canary | str | None = None,
        **context_fields: Any,
    ) -> ScanResult:
        """Scan a model response before it reaches the user (or a tool)."""
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

    def scan_context(self, content: str, *, source: str | None = None, **context_fields: Any) -> ScanResult:
        """Scan third-party content (RAG chunk, web page, email, tool result) for indirect injection."""
        metadata = dict(context_fields.pop("metadata", {}) or {})
        if source:
            metadata["source"] = source
        return self.scan(content, "context", metadata=metadata, **context_fields)

    def scan_batch(self, texts: Iterable[str], direction: Direction = "input", **context_fields: Any) -> list[ScanResult]:
        return [self.scan(t, direction, **context_fields) for t in texts]

    # ------------------------------------------------------------------ agents
    def scan_tool_call(self, tool_name: str, arguments: Mapping[str, Any] | str | None = None, **context_fields: Any) -> ScanResult:
        """Scan a model-proposed tool call (name + arguments) before executing it."""
        payload = arguments if isinstance(arguments, str) else json.dumps(arguments or {}, ensure_ascii=False, default=str)
        extra: list[Detection] = []
        if self.tool_allowlist is not None and tool_name not in self.tool_allowlist:
            extra.append(
                Detection("tool_policy", "tool_not_allowed", Category.POLICY.value, 1.0, f"Tool {tool_name!r} is not in the allow-list.", metadata={"tool": tool_name})
            )
        metadata = {**dict(context_fields.pop("metadata", {}) or {}), "tool": tool_name}
        ctx = ScanContext(direction="output", metadata=metadata, **context_fields)
        return self._run(payload, ctx, extra=extra)

    def scan_tool_result(self, tool_name: str, result: Any, **context_fields: Any) -> ScanResult:
        """Scan what a tool returned before the model reads it (indirect injection channel)."""
        text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
        return self.scan_context(text, source=f"tool:{tool_name}", **context_fields)

    # ------------------------------------------------------------------ canaries
    def add_canary(self, prompt: str, *, echo: bool = False) -> Canary:
        """Embed a canary token in a (system) prompt; pass the returned Canary to `scan_output`."""
        return self.canaries.add(prompt, echo=echo)

    # ------------------------------------------------------------------ async
    async def ascan(self, text: str, direction: Direction = "input", **kwargs: Any) -> ScanResult:
        return await asyncio.to_thread(functools.partial(self.scan, text, direction, **kwargs))

    async def ascan_input(self, prompt: str, **kwargs: Any) -> ScanResult:
        return await asyncio.to_thread(functools.partial(self.scan_input, prompt, **kwargs))

    async def ascan_output(self, response: str, **kwargs: Any) -> ScanResult:
        return await asyncio.to_thread(functools.partial(self.scan_output, response, **kwargs))

    async def ascan_context(self, content: str, **kwargs: Any) -> ScanResult:
        return await asyncio.to_thread(functools.partial(self.scan_context, content, **kwargs))

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
                    if inbound.is_blocked:
                        return blocked(inbound)
                    response = await fn(inbound.text, *args, **kwargs)
                    if not isinstance(response, str):
                        return response
                    outbound = await self.ascan_output(response, prompt=inbound.text, system_prompt=system_prompt)
                    return blocked(outbound) if outbound.is_blocked else outbound.text

                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(fn)
            def wrapper(prompt: str, *args: Any, **kwargs: Any) -> Any:
                inbound = self.scan_input(prompt, system_prompt=system_prompt)
                if inbound.is_blocked:
                    return blocked(inbound)
                response = fn(inbound.text, *args, **kwargs)
                if not isinstance(response, str):
                    return response
                outbound = self.scan_output(response, prompt=inbound.text, system_prompt=system_prompt)
                return blocked(outbound) if outbound.is_blocked else outbound.text

            return wrapper  # type: ignore[return-value]

        return decorator(func) if func is not None else decorator

    # ------------------------------------------------------------------ internals
    def _run(self, text: str, ctx: ScanContext, *, extra: Sequence[Detection] = ()) -> ScanResult:
        started = time.perf_counter()
        detections: list[Detection] = list(extra)
        errors: list[str] = []
        timings: dict[str, float] = {}

        for scanner in self.scanners:
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
        scored: list[Detection] = []
        redact: list[Detection] = []
        forced = Verdict.ALLOW
        for d in detections:
            action = policy.action_for(ctx.direction, d.category)
            if action is Action.SCORE:
                scored.append(d)
            elif action is Action.BLOCK:
                forced = Verdict.BLOCK
            elif action is Action.FLAG:
                forced = max(forced, Verdict.FLAG)
            elif action is Action.REDACT:
                redact.append(d)

        score = self._aggregate(scored)
        verdict = max(self._verdict(score), forced)
        if errors and policy.fail_closed:
            verdict = Verdict.BLOCK

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
        )

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
        spans = sorted(((d.span, d) for d in detections if d.span and d.span[0] < d.span[1]), key=lambda pair: pair[0])
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
