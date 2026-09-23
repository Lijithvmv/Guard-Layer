"""Benchmark GuardLayer on public prompt-injection / jailbreak datasets.

Downloads two Apache-2.0 datasets from the Hugging Face datasets-server API (≈2 MB total)
into ./benchmarks/data/, converts them to GuardLayer's JSONL format, and prints
precision / recall / false-positive rate / latency per split.

    python benchmarks/public_eval.py                  # default config
    python benchmarks/public_eval.py --config my.toml

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

from guardlayer import Verdict
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", help="GuardLayer TOML/JSON config")
    args = parser.parse_args()
    guard = build_guard(args.config)

    print(f"{'split':<18}{'positive':<10}{'n':>6}{'precision':>11}{'recall':>8}{'f1':>7}{'fpr':>7}{'p50 ms':>8}{'p95 ms':>8}")
    for name, (_, splits, _) in DATASETS.items():
        for split in splits:
            samples = load_samples(ensure(name, split))
            for positive in (Verdict.FLAG, Verdict.BLOCK):
                r = evaluate(guard, samples, positive=positive).to_dict()
                print(
                    f"{name + '/' + split:<18}{'>=' + positive.value:<10}{r['samples']:>6}{r['precision']:>11.3f}{r['recall']:>8.3f}"
                    f"{r['f1']:>7.3f}{r['false_positive_rate']:>7.3f}{r['latency_ms']['p50']:>8.2f}{r['latency_ms']['p95']:>8.2f}"
                )


if __name__ == "__main__":
    main()
