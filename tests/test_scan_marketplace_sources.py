"""CPL404 and CPL405: plugin sources in a marketplace.json."""

from __future__ import annotations

import json
from pathlib import Path

from cc_plugin_lock.scan import scan


def _market(tmp_path: Path, plugins: list[dict]) -> Path:
    (tmp_path / ".claude-plugin").mkdir()
    doc = {"name": "team", "owner": {"name": "x"}, "plugins": plugins}
    (tmp_path / ".claude-plugin" / "marketplace.json").write_text(
        json.dumps(doc, indent=2), encoding="utf-8"
    )
    return tmp_path


def _ids(root: Path) -> list[tuple[str, str]]:
    return [(f.id, f.evidence) for f in scan(root).findings]


SHA = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
DIGEST = "6bfa50e3d2e00c052b46abe51fff89346ac803e45771f76dcf6df1ab74cca5e1"


def test_command_source_is_high(tmp_path):
    root = _market(
        tmp_path,
        [{"name": "ide", "source": {"source": "command", "command": "my-tool claude-plugin-path"}}],
    )
    result = scan(root)
    assert [(f.id, f.severity) for f in result.findings] == [("CPL404", "high")]
    assert result.findings[0].evidence == "ide: my-tool claude-plugin-path"
    assert result.findings[0].line == 8  # the line with "name": "ide"


def test_unpinned_sources_are_low(tmp_path):
    root = _market(
        tmp_path,
        [
            {"name": "a", "source": {"source": "github", "repo": "org/a", "ref": "v1"}},
            {"name": "b", "source": {"source": "git-subdir", "url": "org/mono", "path": "b"}},
            {"name": "c", "source": {"source": "archive", "url": "https://example.invalid/c.zip"}},
            {"name": "d", "source": {"source": "npm", "package": "@org/d", "version": "^2.0.0"}},
            {"name": "e", "source": {"source": "npm", "package": "@org/e"}},
        ],
    )
    found = _ids(root)
    assert [i for i, _ in found] == ["CPL405"] * 5
    assert ("CPL405", "a: github org/a ref v1, no sha") in found
    assert ("CPL405", "e: npm @org/e latest") in found


def test_pinned_sources_are_clean(tmp_path):
    root = _market(
        tmp_path,
        [
            {"name": "a", "source": {"source": "github", "repo": "org/a", "sha": SHA}},
            {
                "name": "b",
                "source": {"source": "url", "url": "https://git.example.invalid/b.git", "sha": SHA},
            },
            {
                "name": "c",
                "source": {
                    "source": "archive",
                    "url": "https://example.invalid/c.zip",
                    "sha256": DIGEST,
                },
            },
            {"name": "d", "source": {"source": "npm", "package": "@org/d", "version": "2.0.0"}},
            {"name": "e", "source": {"source": "npm", "package": "@org/e@2.1.0"}},
        ],
    )
    assert _ids(root) == []


def test_wrong_types_are_ignored(tmp_path):
    root = _market(
        tmp_path,
        [
            "not an entry",
            {"name": 3, "source": {"source": "github", "sha": 7}},
            {"name": "x", "source": {"source": "npm", "package": None, "version": ["1"]}},
            {"name": "y", "source": {"source": "command", "command": None}},
        ],
    )
    assert [i for i, _ in _ids(root)] == ["CPL405", "CPL405", "CPL404"]
