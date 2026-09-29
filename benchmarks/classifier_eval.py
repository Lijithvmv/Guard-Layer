"""Should an optional classifier model be recommended? Compare the default guard with default + classifier.

For every text this records the default guard's verdict and the classifier's highest score over its chunks, then reports,
per set and per threshold, how many texts each option flags: the default alone, the classifier alone, and either (what
you get with both on). Benign sets measure false alarms (including 2,056 Indian-language texts); attack sets measure
recall. It also reports the classifier's latency.

A model is recommended only if, at its threshold, "either" adds recall on attack sets the model was *not* trained on and
adds no false alarms on any benign set. Check the model card's training data: a set it was trained on shows memory, not
generalisation, and is reported but marked.

    python benchmarks/classifier_eval.py --model <local model dir> --runtime onnx --llmail <llmail dir>
    python benchmarks/classifier_eval.py --model <dir> --runtime onnx --trained-on llmail   # mark contaminated sets
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from referee import PUBLIC_BENIGN, benign_sets  # noqa: E402

from guardlayer import Verdict, __version__  # noqa: E402
from guardlayer.config import build_guard  # noqa: E402
from guardlayer.scanners.ml import ClassifierScanner  # noqa: E402

DATA = Path(__file__).parent / "data"
ATTACK_SETS = ["deepset_test", "jailbreak_test", "gandalf_test"]  # test splits; label 1 = attack
THRESHOLDS = [0.5, 0.7, 0.9]


def attack_sets(llmail: Path | None, sample: int) -> dict[str, list[str]]:
    sets: dict[str, list[str]] = {}
    for name in ATTACK_SETS:
        path = DATA / f"{name}.jsonl"
        if path.exists():
            sets[name] = [r["text"] for r in map(json.loads, path.open(encoding="utf-8")) if int(r["label"]) == 1]
    if llmail:
        from llmail_eval import load

        attacks, _ = load(llmail)
        held = sorted(t for t, f in attacks.items() if f["hijacked"] and f["heldout"])
        sets["llmail_heldout"] = random.Random(2026).sample(held, min(sample, len(held))) if sample else held
    return sets


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model", required=True, help="model name (transformers) or local directory (onnx)")
    p.add_argument("--runtime", default="onnx", choices=["onnx", "transformers"])
    p.add_argument("--llmail", type=Path, help="directory with the LLMail-Inject files (adds held-out attacks and benign)")
    p.add_argument("--sample", type=int, default=2000, help="LLMail held-out attacks to sample (0 = all)")
    p.add_argument("--trained-on", default="", help="comma-separated set names the model was trained on (marked)")
    p.add_argument("--out", default="benchmarks/results/classifier-eval.jsonl")
    args = p.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    llmail_benign: list[str] = []
    if args.llmail:
        from llmail_eval import load

        llmail_benign = load(args.llmail)[1]
    groups = {**{f"attack_{k}": v for k, v in attack_sets(args.llmail, args.sample).items()},
              **{f"benign_{k}": v for k, v in benign_sets(llmail_benign).items() if v}}  # fmt: skip
    trained = {s.strip() for s in args.trained_on.split(",") if s.strip()}

    guard = build_guard({})
    clf = ClassifierScanner(args.model, runtime=args.runtime, threshold=0.0)
    pipe = clf._load()
    texts = sorted({t for g in groups.values() for t in g})
    base: dict[str, bool] = {}
    score: dict[str, float] = {}
    ms: list[float] = []
    t0 = time.perf_counter()
    for i, text in enumerate(texts):
        base[text] = guard.scan_context(text).verdict >= Verdict.FLAG
        start = time.perf_counter()
        chunks = clf._chunks(text) if text.strip() else []
        outs = pipe(chunks, truncation=True, max_length=clf.max_length) if chunks else []
        ms.append((time.perf_counter() - start) * 1000)
        pos = [o["score"] if o["label"].lower() in clf.positive_labels else 1 - o["score"] for o in outs]
        score[text] = max(pos, default=0.0)
        if i % 1000 == 0:
            print(f"  {i}/{len(texts)}  {time.perf_counter() - t0:.0f}s", flush=True)

    rows = {}
    for gname, group in groups.items():
        n = len(group)
        row = {"n": n, "default": sum(base[t] for t in group), "trained_on": any(s in gname for s in trained)}
        for th in THRESHOLDS:
            row[f"classifier@{th}"] = sum(score[t] >= th for t in group)
            row[f"either@{th}"] = sum(base[t] or score[t] >= th for t in group)
        rows[gname] = row
    ms.sort()
    latency = {"p50_ms": round(statistics.median(ms), 1), "p95_ms": round(ms[int(len(ms) * 0.95)], 1)}

    print(f"\n{'set':26} {'n':>6} {'default':>8}" + "".join(f" {'clf@' + str(t):>8} {'both@' + str(t):>9}" for t in THRESHOLDS))
    for gname, r in rows.items():
        mark = "  (trained on: memory, not generalisation)" if r["trained_on"] else ""
        cells = "".join(f" {r[f'classifier@{t}']:>8} {r[f'either@{t}']:>9}" for t in THRESHOLDS)
        print(f"{gname:26} {r['n']:>6} {r['default']:>8}{cells}{mark}")
    print(f"classifier latency per text: p50 {latency['p50_ms']} ms, p95 {latency['p95_ms']} ms (CPU)")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"date": time.strftime("%Y-%m-%d"), "guardlayer": __version__, "model": Path(args.model).name,
                             "runtime": args.runtime, "groups": rows, "latency": latency,
                             "public_benign": PUBLIC_BENIGN}) + "\n")  # fmt: skip
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
