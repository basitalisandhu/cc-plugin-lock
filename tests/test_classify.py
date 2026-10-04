from __future__ import annotations

from pathlib import Path

import pytest

from cc_plugin_lock.classify import (
    CLASSES,
    HIGH,
    LOW,
    MEDIUM,
    Classifier,
    max_severity,
    plugin_root_refs,
    severity_of,
)

from .conftest import make_formatter, write, write_json


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("hooks/hooks.json", "hooks"),
        ("hooks/scripts/check.py", "hooks"),
        (".mcp.json", "mcp"),
        (".lsp.json", "lsp"),
        ("monitors/monitors.json", "monitors"),
        ("bin/tool", "executables"),
        (".claude-plugin/plugin.json", "manifest"),
        ("settings.json", "manifest"),
        ("package.json", "dependencies"),
        ("server/node_modules/lib/index.js", "dependencies"),
        ("skills/review/SKILL.md", "skills"),
        ("skills/review/scripts/run.py", "skills"),
        ("commands/deploy.md", "commands"),
        ("agents/reviewer.md", "agents"),
        ("output-styles/terse.md", "output-styles"),
        ("tools/helper.py", "code"),
        ("README.md", "docs"),
        ("LICENSE", "docs"),
        ("data/table.csv", "other"),
    ],
)
def test_default_layout_classes(tmp_path: Path, path: str, expected: str):
    assert Classifier(tmp_path).classify(path) == expected


def test_scripts_referenced_by_hooks_are_hooks(tmp_path: Path):
    make_formatter(tmp_path)
    c = Classifier(tmp_path)
    assert c.classify("scripts/format.sh") == "hooks"
    assert c.classify("server/index.js") == "mcp"


def test_manifest_paths_override_defaults(tmp_path: Path):
    write_json(
        tmp_path,
        ".claude-plugin/plugin.json",
        {
            "name": "p",
            "commands": ["./custom/cmds/"],
            "agents": ["./team/reviewer.md"],
            "skills": ["./extra-skills/"],
            "hooks": "./config/hooks.json",
            "mcpServers": {
                "s": {"command": "python3", "args": ["${CLAUDE_PLUGIN_ROOT}/srv/main.py"]}
            },
        },
    )
    write_json(
        tmp_path,
        "config/hooks.json",
        {
            "hooks": {
                "Stop": [{"hooks": [{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/x.sh"}]}]
            }
        },
    )
    c = Classifier(tmp_path)
    assert c.classify("custom/cmds/a.md") == "commands"
    assert c.classify("team/reviewer.md") == "agents"
    assert c.classify("extra-skills/s/SKILL.md") == "skills"
    assert c.classify("config/hooks.json") == "hooks"
    assert c.classify("x.sh") == "hooks"
    assert c.classify("srv/main.py") == "mcp"


def test_single_skill_plugin_root_skill_md(tmp_path: Path):
    write(tmp_path, "SKILL.md", "x")
    assert Classifier(tmp_path).classify("SKILL.md") == "skills"


def test_plugin_root_refs_ignore_escapes():
    refs = plugin_root_refs(
        {
            "command": '"${CLAUDE_PLUGIN_ROOT}"/a.sh ${CLAUDE_PLUGIN_ROOT}/b/c.py ${CLAUDE_PLUGIN_ROOT}/../x'
        }
    )
    assert refs == {"a.sh", "b/c.py"}


def test_severity_mapping():
    assert severity_of("hooks") == HIGH
    assert severity_of("mcp") == HIGH
    assert severity_of("skills") == MEDIUM
    assert severity_of("docs") == LOW
    assert all(sev in (HIGH, MEDIUM, LOW) for sev, _ in CLASSES.values())
    assert max_severity([LOW, None, MEDIUM]) == MEDIUM
    assert max_severity([]) is None
