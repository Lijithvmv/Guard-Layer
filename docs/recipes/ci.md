# Gate prompts in CI

Prompt templates, system prompts and agent instructions are code. Scan them in CI so an injection (or a pasted secret)
can't be merged.

```yaml
# .github/workflows/prompts.yml
name: prompts
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - run: pip install guardlayer
      - name: Scan prompt files
        run: |
          status=0
          for f in prompts/*.txt; do
            guardlayer scan --fail-on flag < "$f" || { echo "::error file=$f::GuardLayer flagged this prompt"; status=1; }
          done
          exit $status
```

`guardlayer scan` exits with code 1 when the verdict reaches `--fail-on` (default `block`).

## Regression-test your guard

Keep a labelled dataset of the attacks and benign prompts that matter to you, and fail the build if detection
regresses:

```bash
guardlayer eval our_cases.jsonl --json > eval.json      # {"text": "...", "label": 1, "direction": "input"} per line
```

`eval` reports precision, recall, F1, false-positive rate and latency. Compare against a stored baseline in your
pipeline.
