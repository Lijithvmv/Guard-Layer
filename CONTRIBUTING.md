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

## Documentation

The docs site lives in `docs/` and builds with MkDocs Material, in its own environment:

```bash
python -m venv .venv-docs && .venv-docs/bin/pip install -e . -r docs/requirements.txt   # Windows: .venv-docs\Scripts\pip
.venv-docs/bin/mkdocs serve          # live preview at http://127.0.0.1:8000
.venv-docs/bin/mkdocs build --strict # what CI runs
```

- Every ` ```python ` block in the docs is executed by `tests/test_docs_examples.py` (blocks on one page share a namespace).
  Use ` ```py ` for snippets that need an LLM client or a framework.
- The rules, CLI, presets and compliance reference pages are generated from the code by `docs/hooks.py`; don't edit them
  by hand.
- `DEPLOYMENT.md`, `THREAT_MODEL.md`, `SECURITY.md`, `CHANGELOG.md` and the README's evaluation section are included into
  the site as they are. Use absolute GitHub URLs for links in them, so they work on GitHub, PyPI and the site alike.

## Pull requests

- Keep each change focused, with tests and a `CHANGELOG.md` entry.
- Don't commit real secrets or personal data, even in tests. Use documented example values.
