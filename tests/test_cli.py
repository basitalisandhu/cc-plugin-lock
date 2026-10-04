from __future__ import annotations

import subprocess
import sys

import pytest

from cc_plugin_lock import __version__

from .conftest import run


@pytest.mark.parametrize("command", ["lock", "verify", "diff", "hook", "scan"])
def test_every_command_has_help(command: str, capsys):
    with pytest.raises(SystemExit) as exc:
        run(command, "--help")
    assert exc.value.code == 0


def test_top_level_help_lists_commands(capsys):
    with pytest.raises(SystemExit):
        from cc_plugin_lock.cli import main

        main(["--help"])
    out = capsys.readouterr().out
    assert out.startswith("usage: cc-plugin-lock")
    for c in ("lock", "verify", "diff", "hook", "scan"):
        assert c in out


def test_version(capsys):
    from cc_plugin_lock.cli import main

    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out.strip() == f"cc-plugin-lock {__version__}"


def test_no_command_prints_help_and_exits_2():
    rc, out, _ = run()
    assert rc == 2 and "usage:" in out


def test_python_dash_m():
    proc = subprocess.run(
        [sys.executable, "-m", "cc_plugin_lock", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0 and __version__ in proc.stdout


def test_lock_table_output(plugins, lock_path):
    rc, out, _ = run("lock", "--root", str(plugins.root), "-o", str(lock_path))
    assert rc == 0
    assert "locked 2 plugin(s) and 1 marketplace(s)" in out
    assert "formatter@acme" in out and "hooks" in out


def test_lock_notes_auto_update(plugins, lock_path):
    plugins.marketplaces["acme"]["autoUpdate"] = True
    plugins.save()
    _, out, _ = run("lock", "--root", str(plugins.root), "-o", str(lock_path))
    assert "auto-update is on for acme" in out
