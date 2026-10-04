from __future__ import annotations

import json
from pathlib import Path

from cc_plugin_lock.hookcfg import settings_snippet

from .conftest import run, write, write_json


def _handler(doc: dict) -> dict:
    [group] = doc["hooks"]["SessionStart"]
    [handler] = group["hooks"]
    return handler


def test_hook_prints_valid_settings_json(locked):
    _, lock = locked
    rc, out, err = run("hook", "--lock", str(lock))
    assert rc == 0 and err == ""
    doc = json.loads(out)
    assert list(doc) == ["hooks"] and list(doc["hooks"]) == ["SessionStart"]
    [group] = doc["hooks"]["SessionStart"]
    assert group["matcher"] == "startup|resume"
    h = _handler(doc)
    assert h["type"] == "command" and h["command"] == "cc-plugin-lock"
    assert h["args"][:2] == ["verify", "--strict"]
    assert h["args"][h["args"].index("--format") + 1] == "hook"
    assert h["args"][h["args"].index("--fail-on") + 1] == "high"
    assert h["args"][h["args"].index("--lock") + 1] == str(lock.resolve())
    assert isinstance(h["timeout"], int) and h["statusMessage"]


def test_hook_exe_with_prefix_and_options(tmp_path: Path):
    rc, out, err = run(
        "hook", "--lock", str(tmp_path / "x.json"), "--exe", "uvx cc-plugin-lock", "--fail-on", "medium",
        "--no-strict", "--root", str(tmp_path), "--matcher", "startup",
    )  # fmt: skip
    assert rc == 0 and "does not exist yet" in err
    h = _handler(json.loads(out))
    assert h["command"] == "uvx" and h["args"][0] == "cc-plugin-lock"
    assert "--strict" not in h["args"] and "medium" in h["args"]
    assert h["args"][-2:] == ["--root", str(tmp_path.resolve())]


def test_snippet_without_matcher_matches_every_source():
    doc = settings_snippet("/x.json", matcher="")
    assert "matcher" not in doc["hooks"]["SessionStart"][0]


def test_hook_format_clean_prints_nothing(locked):
    _, lock = locked
    assert run("verify", "--lock", str(lock), "--format", "hook", "--fail-on", "high") == (
        0,
        "",
        "",
    )


def test_hook_format_blocks_on_high(locked):
    plugins, lock = locked
    write_json(plugins.formatter, "hooks/hooks.json", {"hooks": {}})
    rc, out, _ = run(
        "verify", "--lock", str(lock), "--format", "hook", "--fail-on", "high", "--strict"
    )
    assert rc == 0
    doc = json.loads(out)
    assert doc["continue"] is False
    assert "formatter@acme" in doc["stopReason"] and "HIGH" in doc["stopReason"]


def test_hook_format_warns_below_threshold(locked):
    plugins, lock = locked
    write(plugins.notes, "skills/notes/SKILL.md", "changed\n")
    rc, out, _ = run("verify", "--lock", str(lock), "--format", "hook", "--fail-on", "high")
    doc = json.loads(out)
    assert rc == 0 and set(doc) == {"systemMessage"} and "notes@acme" in doc["systemMessage"]


def test_hook_format_missing_lock_strict_blocks(tmp_path: Path):
    rc, out, _ = run(
        "verify", "--lock", str(tmp_path / "none.json"), "--format", "hook", "--strict"
    )
    doc = json.loads(out)
    assert rc == 0 and doc["continue"] is False and "not found" in doc["stopReason"]


def test_hook_format_missing_lock_without_strict_warns(tmp_path: Path):
    rc, out, _ = run("verify", "--lock", str(tmp_path / "none.json"), "--format", "hook")
    assert rc == 0 and set(json.loads(out)) == {"systemMessage"}


def test_generated_hook_runs_end_to_end(locked):
    """Run the args the hook block contains, as Claude Code would."""
    plugins, lock = locked
    _, out, _ = run("hook", "--lock", str(lock))
    args = _handler(json.loads(out))["args"]
    assert run(*args) == (0, "", "")
    write(plugins.formatter, "scripts/format.sh", "changed\n")
    rc, out, _ = run(*args)
    assert rc == 0 and json.loads(out)["continue"] is False
