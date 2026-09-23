"""Evaluation harness: measure detection quality and latency on a labelled dataset.

Dataset format (JSONL), one sample per line:
    {"text": "...", "label": 1, "direction": "input", "category": "jailbreak"}
`label` is 1 for an attack and 0 for benign; `direction` defaults to "input".
"""

from __future__ import annotations

import json
import statistics
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from guardlayer.models import Verdict
from guardlayer.pipeline import GuardLayer


@dataclass(frozen=True)
class Sample:
    text: str
    label: bool
    direction: str = "input"
    category: str | None = None


@dataclass
class EvalReport:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    false_negatives: list[Sample] = field(default_factory=list)
    false_positives: list[Sample] = field(default_factory=list)
    missed_by_category: Counter[str] = field(default_factory=Counter)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    def latency(self, pct: float) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        return ordered[min(len(ordered) - 1, int(round(pct / 100 * (len(ordered) - 1))))]

    def to_dict(self) -> dict[str, Any]:
        return {
            "samples": self.total,
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "latency_ms": {
                "mean": round(statistics.fmean(self.latencies_ms), 3) if self.latencies_ms else 0.0,
                "p50": round(self.latency(50), 3),
                "p95": round(self.latency(95), 3),
            },
            "missed_by_category": dict(self.missed_by_category),
        }  # fmt: skip

    def summary(self) -> str:
        d = self.to_dict()
        lines = [
            f"samples   {d['samples']}   (tp {self.tp}  fp {self.fp}  tn {self.tn}  fn {self.fn})",
            f"precision {d['precision']:.3f}   recall {d['recall']:.3f}   f1 {d['f1']:.3f}   accuracy {d['accuracy']:.3f}   fpr {d['false_positive_rate']:.3f}",
            f"latency   mean {d['latency_ms']['mean']} ms   p50 {d['latency_ms']['p50']} ms   p95 {d['latency_ms']['p95']} ms",
        ]
        for label, samples in (("missed", self.false_negatives), ("false positive", self.false_positives)):
            for s in samples:
                lines.append(f"  {label:<14} [{s.direction}] {s.text[:90]!r}")
        return "\n".join(lines)


def load_samples(path: str | Path | None = None) -> list[Sample]:
    """Load a JSONL dataset; with no path, the bundled sample set."""
    if path is None:
        raw = resources.files("guardlayer.data").joinpath("eval_sample.jsonl").read_text(encoding="utf-8")
    else:
        raw = Path(path).read_text(encoding="utf-8")
    samples = []
    for line in raw.split("\n"):  # not splitlines(): JSON strings may hold U+2028 etc.
        if line.strip():
            item = json.loads(line)
            samples.append(Sample(item["text"], bool(item["label"]), item.get("direction", "input"), item.get("category")))
    return samples


def evaluate(guard: GuardLayer, samples: Iterable[Sample], *, positive: Verdict = Verdict.FLAG) -> EvalReport:
    """Run `guard` over `samples`; a prediction is positive when the verdict is >= `positive`."""
    report = EvalReport()
    for sample in samples:
        result = guard.scan(sample.text, sample.direction)  # type: ignore[arg-type]
        report.latencies_ms.append(result.latency_ms)
        predicted = result.verdict >= positive
        if sample.label and predicted:
            report.tp += 1
        elif sample.label:
            report.fn += 1
            report.false_negatives.append(sample)
            report.missed_by_category[sample.category or "uncategorised"] += 1
        elif predicted:
            report.fp += 1
            report.false_positives.append(sample)
        else:
            report.tn += 1
    return report
