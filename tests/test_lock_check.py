from pathlib import Path

import pytest

from cc_plugin_lock.lockfile import store_dir

from .conftest import run, write


def test_lock_check_identical(plugins, lock_path):
    assert run("lock", "--root", str(plugins.root), "--lock", str(lock_path))[0] == 0
    before = lock_path.read_bytes()
    modified = lock_path.stat().st_mtime_ns
    rc, out, err = run("lock", "--root", str(plugins.root), "--lock", str(lock_path), "--check")
    assert rc == 0 and not err
    assert "up to date" in out and len(out.splitlines()) == 1
    assert lock_path.read_bytes() == before and lock_path.stat().st_mtime_ns == modified


def test_lock_check_changed(plugins, lock_path):
    assert run("lock", "--root", str(plugins.root), "--lock", str(lock_path))[0] == 0
    before = lock_path.read_bytes()
    write(plugins.notes, "commands/summarise.md", "Summarise differently.\n")
    rc, out, err = run("lock", "--root", str(plugins.root), "--lock", str(lock_path), "--check")
    assert rc == 1 and not err
    assert "differs" in out and len(out.splitlines()) == 1
    assert lock_path.read_bytes() == before


def test_lock_check_compares_bytes_not_json_values(plugins, lock_path):
    assert run("lock", "--root", str(plugins.root), "--lock", str(lock_path))[0] == 0
    reformatted = lock_path.read_bytes().replace(b"\n", b"\r\n")
    lock_path.write_bytes(reformatted)
    rc, out, _ = run("lock", "--root", str(plugins.root), "--lock", str(lock_path), "--check")
    assert rc == 1 and "differs" in out
    assert lock_path.read_bytes() == reformatted


@pytest.mark.parametrize("only", [False, True])
def test_lock_check_missing_never_creates_directories(plugins, lock_path, only):
    extra = ["--only", "notes@acme"] if only else []
    rc, out, err = run(
        "lock", "--root", str(plugins.root), "--lock", str(lock_path), "--check", "--store", *extra
    )
    assert rc == 1 and not err
    assert "missing" in out and len(out.splitlines()) == 1
    assert not lock_path.parent.exists()


@pytest.mark.parametrize("changed", [False, True])
def test_lock_check_store_never_writes(plugins, lock_path, changed):
    assert run("lock", "--root", str(plugins.root), "--lock", str(lock_path))[0] == 0
    before = lock_path.read_bytes()
    modified = lock_path.stat().st_mtime_ns
    if changed:
        write(plugins.notes, "commands/summarise.md", "Summarise differently.\n")
    rc, _, _ = run(
        "lock", "--root", str(plugins.root), "--lock", str(lock_path), "--check", "--store"
    )
    assert rc == int(changed)
    assert not store_dir(lock_path).exists()
    assert lock_path.read_bytes() == before and lock_path.stat().st_mtime_ns == modified


def test_lock_check_unreadable_target_is_an_error(plugins, tmp_path: Path):
    rc, _, err = run("lock", "--root", str(plugins.root), "--lock", str(tmp_path), "--check")
    assert rc == 2 and "cannot read lock file" in err


def test_lock_check_quiet(plugins, lock_path):
    assert run("lock", "--root", str(plugins.root), "--lock", str(lock_path))[0] == 0
    rc, out, err = run(
        "lock", "--root", str(plugins.root), "--lock", str(lock_path), "--check", "--quiet"
    )
    assert rc == 0 and not out and not err


def test_lock_check_only_preserves_unselected_plugins(plugins, lock_path):
    assert run("lock", "--root", str(plugins.root), "--lock", str(lock_path))[0] == 0
    before = lock_path.read_bytes()
    write(plugins.notes, "commands/summarise.md", "Summarise differently.\n")
    rc, out, _ = run("lock", "--lock", str(lock_path), "--check", "--only", "formatter@acme")
    assert rc == 0 and "up to date" in out
    write(plugins.formatter, "scripts/format.sh", "#!/bin/sh\nexit 1\n")
    rc, out, _ = run("lock", "--lock", str(lock_path), "--check", "--only", "formatter@acme")
    assert rc == 1 and "differs" in out
    assert lock_path.read_bytes() == before
