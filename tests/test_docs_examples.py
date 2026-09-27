"""Every ```python block in the docs must run. Illustrative snippets that need an LLM client or a framework use ```py.

Blocks on one page run in order in a shared namespace, like a reader following the page.
"""

import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[1] / "docs"
_BLOCK = re.compile(r"^```python[^\n]*\n(.*?)^```", re.S | re.M)

PAGES = {
    page.relative_to(DOCS).as_posix(): blocks
    for page in sorted(DOCS.rglob("*.md"))
    if (blocks := [m.group(1) for m in _BLOCK.finditer(page.read_text(encoding="utf-8"))])
}


def test_docs_have_runnable_examples():
    assert sum(len(b) for b in PAGES.values()) >= 15


@pytest.mark.parametrize("page", sorted(PAGES))
def test_docs_page_examples_run(page, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # examples that write files write them here
    namespace = {"__name__": "__docs__"}
    for i, code in enumerate(PAGES[page], 1):
        exec(compile(code, f"{page} (example {i})", "exec"), namespace)  # noqa: S102 - our own docs
