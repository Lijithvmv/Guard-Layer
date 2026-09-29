"""Catastrophic backtracking (ReDoS) guard for every built-in rule.

Found 2026-09-29: `fake_role_header` (\\s* under MULTILINE on blank-line runs) and `fake_system_marker` (#{2,} on runs of
"#") were super-linear; a 50,000-character input could cost minutes of CPU. Each rule is now timed on repetitive
adversarial inputs at two sizes. Linear matching grows about 4x when the input grows 4x; quadratic grows 16x. The test
fails on growth above 10x (with an absolute floor so timer noise on tiny timings can't fail it).
"""

import time

import pytest

from guardlayer.rules import DEFAULT_RULES

SEEDS = [
    "a", "a ", "a-", "a.", "-", ".", "\n", " \n", "\r\n", "\t", "#", "##(", "<", "</", "<user", "<|", "(system_",
    "ignore ", "ignore previous ", "before you ", "to you, the ", "your goal is to ", "to: ai ",
    "at the end of your summary ", "summarise the email then ", "prompt safety check ", "s-e-n-d ", "A-", "a b ",
]  # fmt: skip
SMALL, LARGE = 2_000, 8_000


def _time(pattern, text: str) -> float:
    best = float("inf")
    for _ in range(3):  # best of three: robust to scheduler noise
        t0 = time.perf_counter()
        pattern.search(text)
        best = min(best, time.perf_counter() - t0)
    return best


@pytest.mark.parametrize("rule", DEFAULT_RULES, ids=lambda r: r.name)
def test_rule_matching_is_not_superlinear(rule):
    rx = rule.compile()
    worst = []
    for seed in SEEDS:
        small = (seed * (SMALL // len(seed) + 1))[:SMALL]
        large = (seed * (LARGE // len(seed) + 1))[:LARGE]
        t_small, t_large = _time(rx, small), _time(rx, large)
        if t_large > 0.01:  # below 10 ms at 8k characters nothing is catastrophic
            worst.append((t_large / max(t_small, 1e-6), t_large, seed))
    bad = [w for w in worst if w[0] > 10]
    assert not bad, f"{rule.name}: super-linear on {[(repr(s), f'x{g:.1f}', f'{t * 1000:.0f} ms') for g, t, s in bad]}"


FULL_GUARD_SEEDS = ["\n", " \n", "a-", "a.", "a_", "%20", "a%", "#", "<", "a ", "1 ", "4111 ", "@", "a@b.c ", "http://", "\u200b"]


@pytest.mark.parametrize("seed", FULL_GUARD_SEEDS, ids=repr)
def test_whole_guard_is_not_superlinear(seed):
    """Every default scanner, every direction: found `limits` (turn counter), `secrets` (generic assignment, URL
    credentials) and `pii` (email) quadratic on 2026-09-29, in addition to the two rules above."""
    from guardlayer import GuardLayer

    guard = GuardLayer()
    for scan in (guard.scan_input, guard.scan_context, guard.scan_output):
        small = (seed * (SMALL // len(seed) + 1))[:SMALL]
        large = (seed * (LARGE // len(seed) + 1))[:LARGE]
        times = []
        for text in (small, large):
            best = float("inf")
            for _ in range(2):
                t0 = time.perf_counter()
                scan(text)
                best = min(best, time.perf_counter() - t0)
            times.append(best)
        growth = times[1] / max(times[0], 1e-6)
        assert times[1] < 0.05 or growth < 10, f"{scan.__name__} on {seed!r}: x{growth:.1f}, {times[1] * 1000:.0f} ms at {LARGE}"
