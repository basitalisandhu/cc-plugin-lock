from __future__ import annotations

from pathlib import Path

from .conftest import PluginsRoot, run, write


def test_diff_shows_unified_diff_from_store(locked):
    plugins, lock = locked
    write(plugins.formatter, "scripts/format.sh", "#!/bin/sh\necho changed\n")
    rc, out, _ = run("diff", "formatter@acme", "--lock", str(lock))
    assert rc == 1
    assert "modified scripts/format.sh [hooks]" in out
    assert "--- a/scripts/format.sh (locked)" in out
    assert "-exit 0" in out and "+echo changed" in out


def test_diff_by_plain_name_and_added_file(locked):
    plugins, lock = locked
    write(plugins.notes, "skills/notes/extra.md", "new file\n")
    rc, out, _ = run("diff", "notes", "--lock", str(lock))
    assert rc == 1 and "added skills/notes/extra.md" in out and "+new file" in out


def test_diff_without_store_lists_hashes(plugins: PluginsRoot, tmp_path: Path):
    lock = tmp_path / "nostore.json"
    assert run("lock", "--root", str(plugins.root), "-o", str(lock), "-q")[0] == 0
    write(plugins.formatter, "README.md", "changed\n")
    rc, out, _ = run("diff", "formatter", "--lock", str(lock))
    assert rc == 1
    assert "modified README.md [docs]" in out and "->" in out
    assert "no stored copy" in out and "---" not in out


def test_diff_clean_plugin(locked):
    _, lock = locked
    rc, out, _ = run("diff", "notes@acme", "--lock", str(lock))
    assert rc == 0 and "no changes" in out


def test_diff_removed_plugin_shows_removed_files(locked):
    plugins, lock = locked
    plugins.uninstall("notes@acme")
    plugins.save()
    rc, out, _ = run("diff", "notes@acme", "--lock", str(lock))
    assert rc == 1 and "removed commands/summarise.md" in out and "-Summarise the notes." in out


def test_diff_unknown_plugin(locked):
    _, lock = locked
    rc, _, err = run("diff", "nope", "--lock", str(lock))
    assert rc == 2 and "nope" in err


def test_diff_binary_file(locked):
    plugins, lock = locked
    write(plugins.formatter, "img.bin", b"\x00\x01")
    rc, out, _ = run("lock", "--lock", str(lock), "--only", "formatter", "--store", "-q")
    write(plugins.formatter, "img.bin", b"\x00\x02")
    rc, out, _ = run("diff", "formatter", "--lock", str(lock))
    assert rc == 1 and "Binary file img.bin differs" in out
