"""Shared fixtures: a plugins root assembled in a temporary directory for every test.

Nothing that looks like an attack payload is committed as a file. The planted strings
the scan tests need are assembled at run time from parts (``join``), so this repository
does not itself trip the scanners it is meant to sit beside.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from cc_plugin_lock.cli import main


def join(*parts: str) -> str:
    """Assemble a planted test string from its parts at run time."""
    return "".join(parts)


def write(root: Path, rel: str, content: str | bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content, encoding="utf-8")
    return p


def write_json(root: Path, rel: str, data: Any) -> Path:
    return write(root, rel, json.dumps(data, indent=2) + "\n")


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(list(argv))
    return rc, out.getvalue(), err.getvalue()


HOOKS_JSON = {
    "hooks": {
        "PostToolUse": [
            {
                "matcher": "Write|Edit",
                "hooks": [
                    {
                        "type": "command",
                        "command": "bash",
                        "args": ["${CLAUDE_PLUGIN_ROOT}/scripts/format.sh"],
                        "timeout": 10,
                    }
                ],
            }
        ]
    }
}


def make_formatter(path: Path, version: str = "1.0.0") -> Path:
    write_json(
        path,
        ".claude-plugin/plugin.json",
        {"name": "formatter", "version": version, "description": "Formats edited files"},
    )
    write_json(path, "hooks/hooks.json", HOOKS_JSON)
    write(path, "scripts/format.sh", "#!/bin/sh\nexit 0\n")
    write(path, "skills/style/SKILL.md", "---\nname: style\n---\nFollow the house style.\n")
    write(path, "README.md", "# formatter\n")
    write_json(
        path,
        ".mcp.json",
        {
            "mcpServers": {
                "fmt": {"command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/server/index.js"]}
            }
        },
    )
    write(path, "server/index.js", "console.log('ok')\n")
    return path


def make_notes(path: Path) -> Path:
    write_json(path, ".claude-plugin/plugin.json", {"name": "notes", "version": "2.0.0"})
    write(path, "skills/notes/SKILL.md", "---\nname: notes\n---\nTake notes.\n")
    write(path, "commands/summarise.md", "Summarise the notes.\n")
    return path


class PluginsRoot:
    """A fake ``~/.claude/plugins`` with an acme marketplace and two installed plugins."""

    def __init__(self, base: Path) -> None:
        self.root = base / "plugins"
        self.installed: dict[str, list[dict[str, Any]]] = {}
        self.marketplaces: dict[str, Any] = {}
        mkt = self.root / "marketplaces" / "acme"
        write_json(
            mkt,
            ".claude-plugin/marketplace.json",
            {
                "name": "acme",
                "owner": {"name": "Acme"},
                "plugins": [
                    {"name": "formatter", "source": {"source": "github", "repo": "acme/formatter"}},
                    {"name": "notes", "source": "./plugins/notes"},
                ],
            },
        )
        self.marketplaces["acme"] = {
            "source": {"source": "github", "repo": "acme/marketplace"},
            "installLocation": str(mkt),
            "lastUpdated": "2026-10-01T00:00:00.000Z",
        }
        self.formatter = make_formatter(self.root / "cache/acme/formatter/1.0.0")
        self.install("formatter@acme", self.formatter, "1.0.0", sha="a" * 40)
        self.notes = make_notes(self.root / "cache/acme/notes/2.0.0")
        self.install("notes@acme", self.notes, "2.0.0")
        self.save()

    def install(
        self, pid: str, path: Path, version: str, sha: str | None = None, scope: str = "user"
    ) -> None:
        rec: dict[str, Any] = {
            "scope": scope,
            "installPath": str(path),
            "version": version,
            "installedAt": "2026-10-01T00:00:00.000Z",
            "lastUpdated": "2026-10-01T00:00:00.000Z",
        }
        if sha:
            rec["gitCommitSha"] = sha
        self.installed.setdefault(pid, []).append(rec)

    def uninstall(self, pid: str) -> None:
        self.installed.pop(pid, None)

    def save(self) -> None:
        write_json(self.root, "installed_plugins.json", {"version": 2, "plugins": self.installed})
        write_json(self.root, "known_marketplaces.json", self.marketplaces)


@pytest.fixture
def plugins(tmp_path: Path) -> PluginsRoot:
    return PluginsRoot(tmp_path)


@pytest.fixture
def lock_path(tmp_path: Path) -> Path:
    return tmp_path / "work" / "cc-plugins.lock.json"


@pytest.fixture
def locked(plugins: PluginsRoot, lock_path: Path) -> tuple[PluginsRoot, Path]:
    rc, _, err = run("lock", "--root", str(plugins.root), "-o", str(lock_path), "--store", "-q")
    assert rc == 0, err
    return plugins, lock_path


def verify_json(lock_path: Path, *extra: str) -> tuple[int, dict[str, Any]]:
    rc, out, err = run("verify", "--lock", str(lock_path), "--format", "json", *extra)
    assert out, err
    return rc, json.loads(out)


def plugin_result(rep: dict[str, Any], key: str) -> dict[str, Any]:
    return next(p for p in rep["plugins"] if p["key"] == key)
