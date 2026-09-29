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


_TOML = re.compile(r"^```toml[^\n]*\n(.*?)^```", re.S | re.M)


def _toml_blocks():
    for page in sorted(DOCS.rglob("*.md")):
        for i, block in enumerate(_TOML.findall(page.read_text(encoding="utf-8"))):
            yield pytest.param(block, id=f"{page.relative_to(DOCS).as_posix()}#{i}")


@pytest.mark.parametrize("block", list(_toml_blocks()))
def test_docs_toml_examples_parse_and_load(block, tmp_path):
    """Every TOML example parses, and its session / labels / tools sections load (sample files aside)."""
    import tomllib

    from guardlayer.config import build_guard

    data = tomllib.loads(block)
    sub = {k: data[k] for k in ("session", "labels", "tools") if k in data}
    if "tools" in sub:
        sub["tools"] = {k: v for k, v in sub["tools"].items() if k != "rules_file"}
    if "dir" in sub.get("session", {}):
        sub["session"] = {**sub["session"], "dir": str(tmp_path)}  # don't create the example's folder
    build_guard(sub)
