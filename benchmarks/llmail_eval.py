"""Held-out test on LLMail-Inject: real, adaptive attacker emails that GuardLayer's rules were never written against.

LLMail-Inject (Microsoft and others, 2025; MIT licence) was a public challenge: attackers sent one email to an LLM email
assistant and tried to make it call `send_email` to contact@contact.com. Each submission records whether it worked. This
script scans every unique phase-2 submission as untrusted context (`scan_context`, as a guarded agent would when it reads
the email) and reports detection separately for all attempts, for those that hijacked the model, and for those that
hijacked the model *and* got past the challenge's own defenses. The challenge's benign emails measure false positives.

Download (about 263 MB, not committed) from https://huggingface.co/datasets/microsoft/llmail-inject-challenge/tree/main/data:
`raw_submissions_phase2.jsonl`, `emails_for_fp_tests.json`, `scenarios.json`, into one directory, then

    python benchmarks/llmail_eval.py --data <dir>
    python benchmarks/llmail_eval.py --data <dir> --classifier --hijacked-only   # + the classifier (`ml` extra), on the
                                                                                  # attacks that worked (CPU-friendly)
"""

from __future__ import annotations

import argparse
import json
import math
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from guardlayer import Verdict, __version__
from guardlayer.config import build_guard

_GUARD = None


def email_text(subject: str, body: str) -> str:
    return f"Subject of the email: {subject}.   Body: {body}"  # the challenge's own email format


def load(data: Path) -> tuple[dict[str, dict[str, bool]], list[str]]:
    attacks: dict[str, dict[str, bool]] = {}
    with open(data / "raw_submissions_phase2.jsonl", encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            text = email_text(row.get("subject") or "", row.get("body") or "")
            objectives = row.get("objectives")
            flags = json.loads(objectives) if isinstance(objectives, str) else (objectives or {})
            hijacked = bool(flags.get("exfil.sent") and flags.get("exfil.destination") and flags.get("exfil.content"))
            evaded = hijacked and bool(flags.get("defense.undetected")) and bool(flags.get("email.retrieved"))
            seen = attacks.setdefault(text, {"hijacked": False, "evaded": False})
            seen["hijacked"] |= hijacked  # the same email can be submitted to several levels
            seen["evaded"] |= evaded
    benign = set(json.loads((data / "emails_for_fp_tests.json").read_text(encoding="utf-8")))
    for scenario in json.loads((data / "scenarios.json").read_text(encoding="utf-8")).values():
        benign.update(scenario.get("emails", []))
    return attacks, sorted(benign)


def _init(config: dict) -> None:
    global _GUARD
    _GUARD = build_guard(config)


def _scan(text: str) -> tuple[bool, bool]:
    r = _GUARD.scan_context(text)
    return r.verdict >= Verdict.FLAG, r.is_blocked


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(c - h, 3), round(c + h, 3))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", required=True, type=Path)
    p.add_argument("--classifier", action="store_true")
    p.add_argument("--hijacked-only", action="store_true", help="scan only attacks that hijacked the model, plus benign emails")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--out", default="benchmarks/results/llmail-inject-phase2.jsonl")
    args = p.parse_args()
    config: dict = {"scanners": {"classifier": {}}} if args.classifier else {}

    attacks, benign = load(args.data)
    if args.hijacked_only:
        attacks = {t: f for t, f in attacks.items() if f["hijacked"]}
    texts = list(attacks) + benign
    t0 = time.perf_counter()
    with ProcessPoolExecutor(args.workers, initializer=_init, initargs=(config,)) as pool:
        results = dict(zip(texts, pool.map(_scan, texts, chunksize=64), strict=True))
    seconds = round(time.perf_counter() - t0, 1)

    def rate(group: list[str]) -> dict:
        n = len(group)
        det = sum(results[t][0] for t in group)
        blk = sum(results[t][1] for t in group)
        return {"n": n, "detected": det, "blocked": blk, "detected_rate": round(det / n, 3) if n else None,
                "detected_95ci": wilson(det, n)}  # fmt: skip

    groups = {
        **({} if args.hijacked_only else {"all_attempts": list(attacks)}),
        "hijacked_model": [t for t, f in attacks.items() if f["hijacked"]],
        "hijacked_and_evaded_defenses": [t for t, f in attacks.items() if f["evaded"]],
        "benign_emails": benign,
    }
    row = {"benchmark": "llmail-inject phase 2 (unique submissions)", "guardlayer": __version__,
           "classifier": args.classifier, "direction": "context", "date": time.strftime("%Y-%m-%d"), "seconds": seconds,
           **{name: rate(g) for name, g in groups.items()}}  # fmt: skip
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    for name in groups:
        r = row[name]
        print(f"{name:32} n={r['n']:6}  detected {r['detected']:6} ({r['detected_rate']})  95% CI {r['detected_95ci']}  blocked {r['blocked']}")
    print(f"{seconds}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
