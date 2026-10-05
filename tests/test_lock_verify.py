from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cc_plugin_lock.lockfile import LOCKFILE_VERSION

from .conftest import PluginsRoot, make_notes, plugin_result, run, verify_json, write, write_json


def test_lock_then_verify_is_clean(locked):
    _, lock = locked
    rc, rep = verify_json(lock)
    assert rc == 0
    assert rep["summary"]["unchanged"] == 2
    assert rep["summary"]["maxSeverity"] is None
    rc, out, _ = run("verify", "--lock", str(lock))
    assert rc == 0 and "2 plugin(s) match the lock" in out


def test_lock_is_deterministic(plugins: PluginsRoot, tmp_path: Path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    assert run("lock", "--root", str(plugins.root), "-o", str(a), "-q")[0] == 0
    assert run("lock", "--root", str(plugins.root), "-o", str(b), "-q")[0] == 0
    assert a.read_bytes() == b.read_bytes()


def test_lock_schema_fields(locked):
    _, lock = locked
    doc = json.loads(lock.read_text())
    assert doc["lockfileVersion"] == LOCKFILE_VERSION and doc["hashAlgorithm"] == "sha256"
    rec = doc["plugins"]["formatter@acme"]
    assert rec["version"] == "1.0.0" and rec["gitCommitSha"] == "a" * 40
    assert rec["entrySource"] == {"source": "github", "repo": "acme/formatter"}
    assert set(rec["components"]) == {"docs", "hooks", "manifest", "mcp", "skills"}
    assert rec["files"]["scripts/format.sh"]["class"] == "hooks"
    assert rec["fileCount"] == len(rec["files"]) == 7
    assert "lastUpdated" not in json.dumps(doc)


def test_modified_hook_script_is_high(locked):
    plugins, lock = locked
    write(plugins.formatter, "scripts/format.sh", "#!/bin/sh\necho changed\n")
    rc, rep = verify_json(lock)
    assert rc == 1
    f = plugin_result(rep, "formatter@acme")
    assert f["status"] == "changed" and f["severity"] == "high"
    assert f["changes"] == [
        {
            "path": "scripts/format.sh",
            "change": "modified",
            "class": "hooks",
            "severity": "high",
            "old": f["changes"][0]["old"],
            "new": f["changes"][0]["new"],
        }
    ]
    assert f["changes"][0]["old"] != f["changes"][0]["new"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX execute bits")
@pytest.mark.parametrize("before, after", [(0o644, 0o755), (0o755, 0o644)])
def test_mode_only_hook_change_is_high(plugins, lock_path, before, after):
    script = plugins.formatter / "scripts/format.sh"
    script.chmod(before)
    assert run("lock", "--root", str(plugins.root), "-o", str(lock_path), "-q")[0] == 0
    old = json.loads(lock_path.read_text())["plugins"]["formatter@acme"]
    script.chmod(after)
    rc, rep = verify_json(lock_path)
    change = plugin_result(rep, "formatter@acme")
    assert rc == 1 and change["status"] == "changed" and change["severity"] == "high"
    assert len(change["changes"]) == 1
    detail = change["changes"][0]
    assert detail["change"] == "mode"
    assert detail["old"] == detail["new"] == old["files"]["scripts/format.sh"]["sha256"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX execute bits")
def test_non_execute_permission_change_is_ignored(locked):
    plugins, lock = locked
    script = plugins.formatter / "scripts/format.sh"
    script.chmod(0o600)
    assert verify_json(lock)[0] == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX execute bits")
def test_old_lock_stays_readable_and_records_new_execute_baseline(plugins, lock_path):
    script = plugins.formatter / "scripts/format.sh"
    script.chmod(0o755)
    assert run("lock", "--root", str(plugins.root), "-o", str(lock_path), "-q")[0] == 0
    doc = json.loads(lock_path.read_text())
    record = doc["plugins"]["formatter@acme"]
    content_hash = record["contentHash"]
    assert record["files"]["scripts/format.sh"]["executable"] is True
    del record["files"]["scripts/format.sh"]["executable"]
    lock_path.write_text(json.dumps(doc))
    rc, rep = verify_json(lock_path)
    assert rc == 1 and rep["errors"] == []
    assert plugin_result(rep, "formatter@acme")["changes"][0]["change"] == "mode"
    assert run("lock", "--root", str(plugins.root), "-o", str(lock_path), "-q")[0] == 0
    assert (
        json.loads(lock_path.read_text())["plugins"]["formatter@acme"]["contentHash"]
        == content_hash
    )
    assert verify_json(lock_path)[0] == 0


def test_modified_hooks_json_is_high(locked):
    plugins, lock = locked
    write_json(plugins.formatter, "hooks/hooks.json", {"hooks": {}})
    _, rep = verify_json(lock)
    assert plugin_result(rep, "formatter@acme")["severity"] == "high"


def test_changed_mcp_config_is_high(locked):
    plugins, lock = locked
    write_json(
        plugins.formatter,
        ".mcp.json",
        {"mcpServers": {"fmt": {"command": "npx", "args": ["-y", "x"]}}},
    )
    _, rep = verify_json(lock)
    change = plugin_result(rep, "formatter@acme")["changes"][0]
    assert change["class"] == "mcp" and change["severity"] == "high"


def test_modified_skill_is_medium(locked):
    plugins, lock = locked
    write(plugins.notes, "skills/notes/SKILL.md", "---\nname: notes\n---\nTake different notes.\n")
    rc, rep = verify_json(lock)
    assert rc == 1
    n = plugin_result(rep, "notes@acme")
    assert n["severity"] == "medium" and n["classes"] == ["skills"]


def test_docs_change_is_low_and_passes_a_medium_threshold(locked):
    plugins, lock = locked
    write(plugins.formatter, "README.md", "# new readme\n")
    rc, rep = verify_json(lock)
    assert rc == 1 and plugin_result(rep, "formatter@acme")["severity"] == "low"
    rc, _ = verify_json(lock, "--fail-on", "medium")
    assert rc == 0


def test_medium_change_passes_a_high_threshold(locked):
    plugins, lock = locked
    write(plugins.notes, "commands/summarise.md", "Changed.\n")
    assert verify_json(lock, "--fail-on", "high")[0] == 0
    assert verify_json(lock, "--fail-on", "medium")[0] == 1


def test_new_hook_file_in_a_plugin_is_added_high(locked):
    plugins, lock = locked
    write(plugins.notes, "hooks/hooks.json", "{}")
    _, rep = verify_json(lock)
    n = plugin_result(rep, "notes@acme")
    assert n["severity"] == "high"
    assert n["changes"][0]["change"] == "added"


def test_removed_file_is_reported(locked):
    plugins, lock = locked
    (plugins.notes / "commands/summarise.md").unlink()
    _, rep = verify_json(lock)
    n = plugin_result(rep, "notes@acme")
    assert n["changes"][0]["change"] == "removed" and n["changes"][0]["new"] is None


def test_added_plugin(locked):
    plugins, lock = locked
    extra = make_notes(plugins.root / "cache/acme/extra/1.0.0")
    plugins.install("extra@acme", extra, "1.0.0")
    plugins.save()
    rc, rep = verify_json(lock)
    assert rc == 1
    e = plugin_result(rep, "extra@acme")
    assert e["status"] == "added" and e["severity"] == "medium"
    assert rep["summary"]["added"] == 1


def test_added_plugin_with_hooks_is_high(locked, tmp_path: Path):
    plugins, lock = locked
    from .conftest import make_formatter

    other = make_formatter(plugins.root / "cache/acme/other/1.0.0")
    plugins.install("other@acme", other, "1.0.0")
    plugins.save()
    _, rep = verify_json(lock)
    assert plugin_result(rep, "other@acme")["severity"] == "high"


def test_removed_plugin(locked):
    plugins, lock = locked
    plugins.uninstall("notes@acme")
    plugins.save()
    rc, rep = verify_json(lock)
    assert rc == 1
    n = plugin_result(rep, "notes@acme")
    assert n["status"] == "removed" and n["severity"] == "low"


def test_update_to_new_version_dir_is_compared_by_id(locked):
    plugins, lock = locked
    from .conftest import make_formatter

    new = make_formatter(plugins.root / "cache/acme/formatter/1.1.0", version="1.1.0")
    write(new, "scripts/format.sh", "#!/bin/sh\necho new\n")
    plugins.installed["formatter@acme"] = []
    plugins.install("formatter@acme", new, "1.1.0", sha="b" * 40)
    plugins.save()
    _, rep = verify_json(lock)
    f = plugin_result(rep, "formatter@acme")
    assert f["status"] == "changed"
    assert f["version"] == {"locked": "1.0.0", "installed": "1.1.0"}
    assert f["gitCommitSha"]["installed"] == "b" * 40
    assert {c["path"] for c in f["changes"]} == {".claude-plugin/plugin.json", "scripts/format.sh"}


def test_marketplace_source_change_is_high(locked):
    plugins, lock = locked
    plugins.marketplaces["acme"]["source"] = {
        "source": "github",
        "repo": "someone-else/marketplace",
    }
    plugins.save()
    rc, rep = verify_json(lock)
    assert rc == 1
    assert rep["marketplaces"][0]["severity"] == "high"
    assert rep["summary"]["maxSeverity"] == "high"


def test_marketplace_timestamps_do_not_count(locked):
    plugins, lock = locked
    plugins.marketplaces["acme"]["lastUpdated"] = "2026-12-31T00:00:00.000Z"
    plugins.save()
    assert verify_json(lock)[0] == 0


def test_lock_only_accepts_one_reviewed_change(locked):
    plugins, lock = locked
    write(plugins.notes, "skills/notes/SKILL.md", "new\n")
    write(plugins.formatter, "scripts/format.sh", "new\n")
    rc, _, err = run("lock", "--lock", str(lock), "--only", "notes", "-q")
    assert rc == 0, err
    _, rep = verify_json(lock)
    assert plugin_result(rep, "notes@acme")["status"] == "unchanged"
    assert plugin_result(rep, "formatter@acme")["status"] == "changed"


def test_lock_only_unknown_plugin_is_an_error(locked):
    _, lock = locked
    rc, _, err = run("lock", "--lock", str(lock), "--only", "nope")
    assert rc == 2 and "nope" in err


def test_missing_lock_exits_2(tmp_path: Path):
    rc, out, err = run("verify", "--lock", str(tmp_path / "none.json"))
    assert rc == 2 and "not found" in err and out == ""


def test_unsupported_lock_version_exits_2(locked):
    _, lock = locked
    doc = json.loads(lock.read_text())
    doc["lockfileVersion"] = 99
    lock.write_text(json.dumps(doc))
    rc, _, err = run("verify", "--lock", str(lock))
    assert rc == 2 and "lockfileVersion" in err


def test_invalid_json_lock_exits_2(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text("{nope")
    rc, _, err = run("verify", "--lock", str(p))
    assert rc == 2 and "not valid JSON" in err


def test_unreadable_plugin_dir_is_an_error_in_strict_mode(locked):
    plugins, lock = locked
    target = plugins.notes / "commands"
    target.chmod(0o000)
    try:
        rc, _, err = run("verify", "--lock", str(lock), "--strict", "--format", "json")
    finally:
        target.chmod(0o755)
    assert rc == 2 and "notes@acme" in err


def test_verify_uses_the_lock_root_by_default(locked):
    _, lock = locked
    doc = json.loads(lock.read_text())
    assert doc["pluginsRoot"]
    rc, rep = verify_json(lock)
    assert rc == 0 and rep["root"] == doc["pluginsRoot"]


def test_verify_writes_report_to_output(locked, tmp_path: Path):
    _, lock = locked
    out = tmp_path / "report.json"
    rc, stdout, _ = run("verify", "--lock", str(lock), "--format", "json", "--output", str(out))
    assert rc == 0 and stdout == ""
    assert json.loads(out.read_text())["tool"] == "cc-plugin-lock"


def test_exclude_is_recorded_and_reused(plugins: PluginsRoot, lock_path: Path):
    assert (
        run(
            "lock",
            "--root",
            str(plugins.root),
            "-o",
            str(lock_path),
            "--exclude",
            "README.md",
            "-q",
        )[0]
        == 0
    )
    assert json.loads(lock_path.read_text())["exclude"] == ["README.md"]
    write(plugins.formatter, "README.md", "changed\n")
    assert verify_json(lock_path)[0] == 0
