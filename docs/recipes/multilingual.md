# Other languages

## What's in the core (no extra install)

The default rules include "ignore previous instructions" and its variants in several European languages, and, since 0.8,
in **Hindi, Marathi, Bengali, Gujarati, Punjabi, Tamil, Telugu, Kannada, Malayalam and romanised Hindi**, in either
word order. Checked on 2,056 normal Wikipedia introductions in those languages (256 chosen because they use the rule's
own words): the rule flagged none of them.

The containment layers don't depend on language at all: [labels](../concepts/labels.md), task profiles, the tool
policy, and the [behavioural check](../concepts/intent.md) work whatever language an attack is written in.

## Optional: a multilingual classifier on ONNX

For wider coverage you can run a multilingual prompt-injection classifier through the `classifier` scanner, on ONNX
Runtime instead of PyTorch (under 100 MB installed, instead of PyTorch's gigabytes):

```bash
pip install "guardlayer[multilingual]"
```

GuardLayer never downloads a model for you. Fetch the files at a fixed revision and check them, so what runs is what
you reviewed. For Horizon Labs' `prompt-injection-guard-small` (Apache-2.0, 30 languages, 268 MB quantized):

```bash
REV=b27472d551844d8c22ed5ad7acd72fe558831bc6
BASE=https://huggingface.co/Horizon-Labs/prompt-injection-guard-small/resolve/$REV
mkdir -p models/pig-small/onnx && cd models/pig-small
curl -fLO $BASE/config.json && curl -fLO $BASE/tokenizer.json
curl -fL -o onnx/model_quantized.onnx $BASE/onnx/model_quantized.onnx
sha256sum tokenizer.json onnx/model_quantized.onnx
# 47834a7dbbb0c4324fe9569fe47955241594a9ee539c9e478755d6fbc51e5f46  tokenizer.json
# 541471ab9de1af3e0db63b8208ec7fdc3ef74202b76c5470115e153c052dae02  onnx/model_quantized.onnx
```

```toml
[scanners.classifier]
model = "models/pig-small"   # the local directory
runtime = "onnx"
threshold = 0.9
```

### Should you turn it on? Our measurement says: not for blocking

We run every candidate model through the same test before recommending it: more attacks caught on data it wasn't trained
on, and **no new false alarms**. This one catches far more attacks, and fails the false-alarm test. Flagged texts at
threshold 0.7 (0.9 in brackets), default rules alone vs. default + classifier:

| Set | Texts | Default | + classifier |
|---|---|---|---|
| deepset test (attacks) | 60 | 14 | 32 (24) |
| jailbreak-classification test (attacks) | 139 | 101 | 120 (110) |
| Gandalf test (attacks) | 112 | 64 | 108 (106) |
| Public benign prompts | 4,509 | 0 | 3 (1) |
| AgentDojo tool outputs (benign) | 404 | 0 | **11 (8)** |
| LLMail-Inject normal emails | 238 | 0 | **92 (50)** |
| Indian-language Wikipedia (benign) | 2,056 | 7 | 8 (7) |

Latency on a laptop CPU: 78 ms median, 1.3 s at the 95th percentile (long documents are scanned in several windows).

The model's training data includes LLMail-Inject, so its perfect score on LLMail attacks isn't a fair test and isn't
shown. Even so it flags 39% of LLMail's normal emails at 0.7: for an agent that reads email, that is too many.

**Our advice:** if you want the extra recall, run it in [observe mode](../concepts/presets.md) or as a signal for review,
not as a blocker, and measure it on your own traffic first. For Indian languages the core rule already covers the common
override phrasing with no false alarms in our tests. The benchmark is in `benchmarks/classifier_eval.py`; rerun it for
any other model you consider.
