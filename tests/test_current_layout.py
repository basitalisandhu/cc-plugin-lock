"""Behaviour that follows the plugin cache layout of current Claude Code releases."""

from __future__ import annotations

import json
import os
from pathlib import Path

from cc_plugin_lock.classify import Classifier
from cc_plugin_lock.hashing import walk
from cc_plugin_lock.hookcfg import DEFAULT_MATCHER, settings_snippet
from cc_plugin_lock.lockfile import dumps, read

from .conftest import plugin_result, run, verify_json, write


def test_in_use_markers_are_not_hashed(tmp_path: Path):
    write(tmp_path, "README.md", "x\n")
    write(tmp_path, ".in_use/12076", '{"pid": 1}\n')
    assert walk(tmp_path) == ["README.md"]


def test_in_use_marker_written_after_the_lock_is_not_a_change(locked):
    plugins, lock = locked
    # Claude Code adds and removes these while sessions use the plugin.
    write(plugins.formatter, ".in_use/4242", '{"pid": 4242}\n')
    rc, rep = verify_json(lock)
    assert rc == 0 and rep["summary"]["unchanged"] == 2


def test_lock_from_an_older_version_with_in_use_entries_still_verifies(locked):
    _, lock = locked
    doc = json.loads(lock.read_text())
    rec = doc["plugins"]["formatter@acme"]
    rec["files"][".in_use/999"] = {"sha256": "sha256:" + "0" * 64, "size": 3, "class": "other"}
    rec["contentHash"] = "sha256:" + "1" * 64
    rec["components"]["other"] = "sha256:" + "2" * 64
    rec["fileCount"] += 1
    lock.write_text(dumps(doc))
    loaded = read(lock)
    assert ".in_use/999" not in loaded["plugins"]["formatter@acme"]["files"]
    assert "other" not in loaded["plugins"]["formatter@acme"]["components"]
    rc, rep = verify_json(lock)
    assert rc == 0, rep
    assert plugin_result(rep, "formatter@acme")["status"] == "unchanged"


def test_extensionless_script_with_shebang_is_code(tmp_path: Path):
    write(tmp_path, "scripts/kimi-code", "#!/usr/bin/env python3\nprint('hi')\n")
    write(tmp_path, "scripts/notes", "plain text\n")
    c = Classifier(tmp_path, {})
    assert c.classify("scripts/kimi-code") == "code"
    assert c.classify("scripts/notes") == "other"


def test_extensionless_executable_is_code(tmp_path: Path):
    p = write(tmp_path, "tools/run", "exec node index.js\n")
    os.chmod(p, 0o755)
    assert Classifier(tmp_path, {}).classify("tools/run") == "code"


def test_missing_extensionless_file_is_other(tmp_path: Path):
    assert Classifier(tmp_path, {}).classify("gone/file") == "other"


def test_session_gate_also_matches_forked_sessions(tmp_path: Path):
    # https://code.claude.com/docs/en/hooks#sessionstart: forks report source "fork".
    assert DEFAULT_MATCHER.split("|") == ["startup", "resume", "fork"]
    group = settings_snippet(str(tmp_path / "l.json"))["hooks"]["SessionStart"][0]
    assert group["matcher"] == "startup|resume|fork"
    rc, out, _ = run("hook", "--lock", str(tmp_path / "l.json"))
    assert rc == 0 and json.loads(out)["hooks"]["SessionStart"][0]["matcher"] == DEFAULT_MATCHER
