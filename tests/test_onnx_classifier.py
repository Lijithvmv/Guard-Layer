"""The classifier's ONNX runtime (the `multilingual` extra): onnxruntime + tokenizers, a local model directory, no PyTorch.

The runtime is faked here, so these run without the model; set GUARDLAYER_ONNX_MODEL to a model directory to also run
the real-model check at the end.
"""

from __future__ import annotations

import json
import os
import sys
import types

import pytest

from guardlayer.config import build_guard
from guardlayer.models import ScanContext
from guardlayer.scanners.ml import ClassifierScanner, OnnxClassifier

np = pytest.importorskip("numpy")


class _Enc:
    def __init__(self, n: int) -> None:
        self.ids = [1] * n
        self.attention_mask = [1] * n
        self.type_ids = [0] * n


class _Tokenizer:
    truncation = None

    @classmethod
    def from_file(cls, path: str) -> _Tokenizer:
        return cls()

    def enable_truncation(self, n: int) -> None:
        self.truncation = n

    def no_truncation(self) -> None:
        self.truncation = None

    def enable_padding(self) -> None:
        pass

    def encode_batch(self, texts: list[str]) -> list[_Enc]:
        return [_Enc(4) for _ in texts]


class _Session:
    fed: dict = {}

    def __init__(self, path, options, providers) -> None:
        assert providers == ["CPUExecutionProvider"]

    def get_inputs(self):
        return [types.SimpleNamespace(name="input_ids"), types.SimpleNamespace(name="attention_mask")]

    def run(self, _, feed):
        _Session.fed = feed
        n = feed["input_ids"].shape[0]
        return [np.array([[-2.0, 3.0] if i % 2 == 0 else [3.0, -2.0] for i in range(n)])]


@pytest.fixture
def model_dir(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text(json.dumps({"id2label": {"0": "SAFE", "1": "INJECTION"}}), encoding="utf-8")
    ort = types.SimpleNamespace(SessionOptions=lambda: types.SimpleNamespace(), InferenceSession=_Session)
    monkeypatch.setitem(sys.modules, "onnxruntime", ort)
    monkeypatch.setitem(sys.modules, "tokenizers", types.SimpleNamespace(Tokenizer=_Tokenizer))
    return tmp_path


def test_onnx_pipeline_returns_top_label_and_softmax_score(model_dir):
    clf = OnnxClassifier(str(model_dir))
    out = clf(["a", "b"], max_length=64)
    assert [o["label"] for o in out] == ["INJECTION", "SAFE"]
    assert out[0]["score"] == pytest.approx(1 / (1 + np.exp(-5)))
    assert clf.tokenizer.truncation == 64
    assert set(_Session.fed) == {"input_ids", "attention_mask"}  # only inputs the model declares


def test_scanner_uses_onnx_runtime_and_is_not_given_the_default_pin(model_dir):
    s = ClassifierScanner(str(model_dir), runtime="onnx", threshold=0.5)
    assert s.revision is None
    detections = s.scan("some untrusted text", ScanContext(direction="context"))
    assert detections and detections[0].rule == "injection_classifier"


def test_config_accepts_the_onnx_runtime(model_dir):
    guard = build_guard({"scanners": {"classifier": {"model": str(model_dir), "runtime": "onnx", "threshold": 0.5}}})
    assert any(getattr(s, "runtime", None) == "onnx" for s in guard.scanners)


def test_unknown_runtime_is_rejected():
    with pytest.raises(ValueError, match="runtime"):
        ClassifierScanner(runtime="tensorflow")


@pytest.mark.skipif(not os.environ.get("GUARDLAYER_ONNX_MODEL"), reason="set GUARDLAYER_ONNX_MODEL to a model directory")
def test_real_model_scores_benign_text_safe():  # pragma: no cover - needs the downloaded model
    pytest.importorskip("onnxruntime")
    clf = OnnxClassifier(os.environ["GUARDLAYER_ONNX_MODEL"])
    out = clf(["Please summarise this report in three bullet points.", "मौसम आज बहुत अच्छा है।"])
    assert all(o["label"] == "SAFE" for o in out)
