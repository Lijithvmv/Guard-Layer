# Contributing

Thanks for helping make LLM applications safer.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q && ruff check src tests && guardlayer eval
```

## Adding a detection rule

1. Add a `Rule` to `src/guardlayer/rules.py`. Give it a category, a severity and the directions it applies to.
2. Add a test that shows it firing and a test that shows it staying silent on similar benign text
   (see `tests/test_heuristics.py`).
3. Run `guardlayer eval`. A rule that adds false positives on the benign samples needs a lower severity or a tighter pattern.

Severity guide: **≥ 0.8** blocks on its own and needs very few false positives. **0.4–0.8** flags.
**< 0.4** is a weak signal that only matters when it combines with others.

## Adding a scanner

Subclass `BaseScanner`, set `name` and `default_directions`, and return `self.detection(...)`
from `scan(text, context)`. Keep the core free of dependencies: import optional libraries lazily
inside the scanner and add them as an extra in `pyproject.toml`. Register the scanner in
`config.SCANNER_REGISTRY` if it should be available from config.

## Pull requests

- Keep each change focused, with tests and a `CHANGELOG.md` entry.
- Don't commit real secrets or personal data, even in tests. Use documented example values.
