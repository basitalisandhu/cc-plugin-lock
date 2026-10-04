from __future__ import annotations

import subprocess
import sys

import pytest

from cc_plugin_lock import __version__

from .conftest import run, write, write_json


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


def test_verify_markdown_clean(locked):
    _, lock = locked
    rc, out, err = run("verify", "--lock", str(lock), "--format", "markdown")
    assert rc == 0 and not err
    assert out.startswith("## cc-plugin-lock verify\n")
    assert "| Status | Severity | Plugin | Detail |" in out
    assert "2 unchanged, 0 changed, 0 added, 0 removed" in out
    assert "formatter@acme" not in out and "notes@acme" not in out
    assert "<details>" not in out


def test_verify_markdown_changed_and_added(locked):
    plugins, lock = locked
    write(plugins.formatter, "scripts/format.sh", "#!/bin/sh\nexit 1\n")
    extra = plugins.root / "cache/acme/extra/1.0.0"
    write_json(extra, ".claude-plugin/plugin.json", {"name": "extra", "version": "1.0.0"})
    write(extra, "skills/extra/SKILL.md", "Take extra notes.\n")
    plugins.install("extra@acme", extra, "1.0.0")
    plugins.save()
    rc, out, err = run("verify", "--lock", str(lock), "--format", "markdown")
    assert rc == 1 and not err
    assert "| changed | HIGH | <code>formatter@acme</code> |" in out
    assert "| added | MEDIUM | <code>extra@acme</code> |" in out
    assert "1 unchanged, 1 changed, 1 added, 0 removed" in out
    assert "notes@acme" not in out
    assert out.count("<details>") == out.count("</details>") == 1
    assert "<summary>formatter@acme (HIGH)</summary>" in out
    assert "| modified | HIGH | hooks | <code>scripts/format.sh</code> |" in out
    assert out == run("verify", "--lock", str(lock), "--format", "markdown")[1]


def test_verify_markdown_removed(locked):
    plugins, lock = locked
    plugins.uninstall("notes@acme")
    plugins.save()
    rc, out, _ = run("verify", "--lock", str(lock), "--format", "markdown")
    assert rc == 1
    assert "| removed | LOW | <code>notes@acme</code> |" in out
    assert "1 unchanged, 0 changed, 0 added, 1 removed" in out
    assert "formatter@acme" not in out and "<details>" not in out


def test_verify_markdown_output_file(locked, tmp_path):
    plugins, lock = locked
    write(plugins.formatter, "scripts/format.sh", "#!/bin/sh\nexit 1\n")
    report = tmp_path / "verify.md"
    rc, expected, _ = run("verify", "--lock", str(lock), "--format", "markdown")
    written_rc, out, err = run(
        "verify", "--lock", str(lock), "--format", "markdown", "--output", str(report)
    )
    assert written_rc == rc == 1 and not out and not err
    assert report.read_text(encoding="utf-8") == expected


def test_verify_markdown_escapes_cells_and_preserves_diagnostics():
    from cc_plugin_lock.report import render_verify
    from cc_plugin_lock.verify import FileChange, MarketplaceResult, PluginResult, Report

    rep = Report(
        lock_path="lock.json",
        root="plugins",
        plugins=[
            PluginResult(
                "plugin|<draft>",
                "changed",
                "medium",
                "plugin",
                "plugins/plugin",
                changes=[
                    FileChange("skills/a|b<draft>.md", "modified", "skills", "medium", "old", "new")
                ],
            )
        ],
        marketplaces=[MarketplaceResult("acme", "changed", "high", "source changed")],
        warnings=["missing metadata"],
        errors=["cannot read file"],
    )
    out = render_verify(rep, "markdown")
    assert "plugin&#124;&lt;draft&gt;" in out
    assert "skills/a&#124;b&lt;draft&gt;.md" in out
    assert "plugin|<draft>" not in out
    assert "### Marketplaces" in out and "| changed | HIGH |" in out
    assert "source changed" in out
    assert "Warning: missing metadata" in out
    assert "Error: cannot read file" in out


def test_verify_markdown_preserves_markdown_characters_in_file_names():
    from cc_plugin_lock.report import render_verify
    from cc_plugin_lock.verify import FileChange, PluginResult, Report

    rep = Report(
        lock_path="lock.json",
        root="plugins",
        plugins=[
            PluginResult(
                "example",
                "changed",
                "low",
                "example",
                "plugins/example",
                changes=[
                    FileChange(
                        "docs/![readme](other)*_`~\\.md", "modified", "docs", "low", "old", "new"
                    )
                ],
            )
        ],
    )
    out = render_verify(rep, "markdown")
    assert "docs/!&#91;readme&#93;(other)&#42;&#95;&#96;&#126;&#92;.md" in out
