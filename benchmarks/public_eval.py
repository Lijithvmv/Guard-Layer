"""Benchmark GuardLayer on public prompt-injection / jailbreak datasets.

Downloads two Apache-2.0 datasets from the Hugging Face datasets-server API (≈2 MB total)
into ./benchmarks/data/, converts them to GuardLayer's JSONL format, and prints
precision / recall / false-positive rate / latency per split.

    python benchmarks/public_eval.py                  # default config
    python benchmarks/public_eval.py --config my.toml
    python benchmarks/public_eval.py --classifier          # + transformer classifier (needs the `ml` extra)
    python benchmarks/public_eval.py --classifier-only     # the classifier on its own, for comparison

Datasets:
  * deepset/prompt-injections        — 662 prompts, injection vs benign (English, German, a few others)
  * jackhhao/jailbreak-classification — 1,306 prompts, jailbreak vs benign

Tune only against the `train` splits; report the `test` splits.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
from pathlib import Path

from guardlayer import ClassifierScanner, GuardLayer, Verdict
from guardlayer.config import build_guard
from guardlayer.evaluation import evaluate, load_samples

API = "https://datasets-server.huggingface.co/rows?dataset={ds}&config=default&split={split}&offset={offset}&length=100"
DATASETS = {
    "deepset": ("deepset/prompt-injections", ("train", "test"), lambda r: (r["text"], int(r["label"]))),
    "jailbreak": ("jackhhao/jailbreak-classification", ("train", "test"), lambda r: (r["prompt"], int(r["type"] == "jailbreak"))),
}
DATA_DIR = Path(__file__).parent / "data"


def fetch(dataset: str, split: str) -> list[dict]:
    rows, offset = [], 0
    while True:
        url = API.format(ds=dataset, split=split, offset=offset)
        for attempt in range(4):
            try:
                with urllib.request.urlopen(url, timeout=30) as resp:
                    page = json.load(resp)
                break
            except OSError:
                time.sleep(2 * (attempt + 1))
        else:
            raise SystemExit(f"could not fetch {url}")
        rows += [item["row"] for item in page["rows"]]
        offset += 100
        if len(page["rows"]) < 100:
            return rows


def ensure(name: str, split: str) -> Path:
    path = DATA_DIR / f"{name}_{split}.jsonl"
    if not path.exists():
        dataset, _, convert = DATASETS[name]
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for row in fetch(dataset, split):
                text, label = convert(row)
                fh.write(json.dumps({"text": text, "label": label}, ensure_ascii=False) + "\n")
    return path


class _Cached:
    """Scans every sample once so both verdict levels can be scored without re-running models."""

    def __init__(self, guard: GuardLayer, samples: list) -> None:
        self._results = {(s.text, s.direction): guard.scan(s.text, s.direction) for s in samples}

    def scan(self, text: str, direction: str = "input"):  # type: ignore[no-untyped-def]
        return self._results[(text, direction)]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", help="GuardLayer TOML/JSON config")
    parser.add_argument("--classifier", action="store_true", help="add the transformer classifier to the default ensemble")
    parser.add_argument("--classifier-only", action="store_true", help="run only the transformer classifier")
    parser.add_argument("--threshold", type=float, default=0.7, help="classifier threshold")
    parser.add_argument("--splits", nargs="+", help="subset to run, e.g. deepset/test jailbreak/test")
    args = parser.parse_args()
    if args.classifier_only:
        guard = GuardLayer([ClassifierScanner(threshold=args.threshold)])
    elif args.classifier:
        guard = build_guard({"scanners": {"classifier": {"threshold": args.threshold}}})
    else:
        guard = build_guard(args.config)

    print(f"{'split':<18}{'positive':<10}{'n':>6}{'precision':>11}{'recall':>8}{'f1':>7}{'fpr':>7}{'p50 ms':>8}{'p95 ms':>8}")
    for name, (_, splits, _) in DATASETS.items():
        for split in splits:
            if args.splits and f"{name}/{split}" not in args.splits:
                continue
            samples = load_samples(ensure(name, split))
            cached = _Cached(guard, samples)  # scan once, score at both verdict levels
            for positive in (Verdict.FLAG, Verdict.BLOCK):
                r = evaluate(cached, samples, positive=positive).to_dict()
                print(
                    f"{name + '/' + split:<18}{'>=' + positive.value:<10}{r['samples']:>6}{r['precision']:>11.3f}{r['recall']:>8.3f}"
                    f"{r['f1']:>7.3f}{r['false_positive_rate']:>7.3f}{r['latency_ms']['p50']:>8.2f}{r['latency_ms']['p95']:>8.2f}"
                )


if __name__ == "__main__":
    main()
