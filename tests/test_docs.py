"""Repository hygiene: docs match the code, and the text follows the house style."""

from __future__ import annotations

import re
from pathlib import Path

from cc_plugin_lock.classify import CLASSES
from cc_plugin_lock.lockfile import LOCKFILE_VERSION
from cc_plugin_lock.scan import RULES

ROOT = Path(__file__).resolve().parent.parent
TEXT_SUFFIXES = {".md", ".py", ".toml", ".yml", ".yaml", ".json", ".txt", ""}


def _text_files() -> list[Path]:
    skip = {".git", ".venv", "dist", "build", ".pytest_cache", ".ruff_cache", "__pycache__"}
    return [
        p
        for p in ROOT.rglob("*")
        if p.is_file() and not (set(p.relative_to(ROOT).parts) & skip) and p.suffix in TEXT_SUFFIXES
    ]


def test_no_em_dashes_anywhere():
    bad = [
        str(p.relative_to(ROOT))
        for p in _text_files()
        if "\u2014" in p.read_text(encoding="utf-8", errors="ignore")
    ]
    assert bad == []


def test_lockfile_doc_matches_schema_version_and_classes():
    doc = (ROOT / "docs" / "lockfile.md").read_text(encoding="utf-8")
    assert f'"lockfileVersion": {LOCKFILE_VERSION}' in doc
    for cls in CLASSES:
        assert f"`{cls}`" in doc, cls


def test_rules_doc_lists_every_rule():
    doc = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    for rid in RULES:
        assert f"## {rid}" in doc, rid


def test_readme_leads_with_the_search_phrase():
    first = (ROOT / "README.md").read_text(encoding="utf-8").splitlines()[0]
    assert first.startswith("# ") and "Lock file for Claude Code plugins" in first


def test_version_is_consistent():
    from cc_plugin_lock import __version__

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(rf'^version = "{re.escape(__version__)}"$', pyproject, re.M)
    assert f"## [{__version__}]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_good_first_issues_has_six_tasks():
    doc = (ROOT / "docs" / "good-first-issues.md").read_text(encoding="utf-8")
    assert len(re.findall(r"^## \d+\. ", doc, re.M)) == 6
