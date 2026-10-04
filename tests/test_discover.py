from __future__ import annotations

from pathlib import Path

from cc_plugin_lock.discover import default_root, discover, display_path, split_id

from .conftest import PluginsRoot, make_notes, write, write_json


def test_reads_installed_plugins_v2(plugins: PluginsRoot):
    d = discover(plugins.root)
    by_key = {p.key: p for p in d.plugins}
    assert set(by_key) == {"formatter@acme", "notes@acme"}
    f = by_key["formatter@acme"]
    assert f.version == "1.0.0" and f.git_commit == "a" * 40 and f.scopes == ["user"]
    assert f.marketplace == "acme" and f.name == "formatter"


def test_entry_source_comes_from_the_marketplace_catalog(plugins: PluginsRoot):
    d = discover(plugins.root)
    by_key = {p.key: p for p in d.plugins}
    assert by_key["formatter@acme"].entry_source == {"source": "github", "repo": "acme/formatter"}
    assert by_key["notes@acme"].entry_source == "./plugins/notes"


def test_marketplaces_are_recorded_with_catalog_hash(plugins: PluginsRoot):
    m = discover(plugins.root).marketplaces["acme"]
    assert m.source == {"source": "github", "repo": "acme/marketplace"}
    assert m.catalog_hash and m.catalog_hash.startswith("sha256:")


def test_same_path_in_two_scopes_is_one_plugin(plugins: PluginsRoot):
    plugins.install("notes@acme", plugins.notes, "2.0.0", scope="project")
    plugins.save()
    notes = [p for p in discover(plugins.root).plugins if p.plugin_id == "notes@acme"]
    assert len(notes) == 1 and notes[0].scopes == ["user", "project"]


def test_two_versions_of_one_id_get_versioned_keys(plugins: PluginsRoot):
    other = make_notes(plugins.root / "cache/acme/notes/3.0.0")
    plugins.install("notes@acme", other, "3.0.0", scope="project")
    plugins.save()
    keys = sorted(p.key for p in discover(plugins.root).plugins)
    assert keys == ["formatter@acme", "notes@acme#2.0.0", "notes@acme#3.0.0"]


def test_missing_install_path_falls_back_to_the_cache_under_root(plugins: PluginsRoot):
    plugins.installed["formatter@acme"][0]["installPath"] = "/elsewhere/cache/acme/formatter/1.0.0"
    plugins.save()
    d = discover(plugins.root)
    assert any(p.key == "formatter@acme" and p.path == plugins.formatter for p in d.plugins)


def test_relative_install_path_resolves_against_root(plugins: PluginsRoot):
    plugins.installed["notes@acme"][0]["installPath"] = "cache/acme/notes/2.0.0"
    plugins.installed["notes@acme"][0]["version"] = "renamed"
    plugins.save()
    assert any(p.key == "notes@acme" for p in discover(plugins.root).plugins)


def test_unresolvable_install_is_a_warning(plugins: PluginsRoot):
    plugins.install("ghost@acme", Path("/nowhere/ghost"), "9.9.9")
    plugins.save()
    d = discover(plugins.root)
    assert any("ghost@acme" in w for w in d.warnings)
    assert all(p.key != "ghost@acme" for p in d.plugins)


def test_cache_scan_without_registry_skips_orphaned_versions(tmp_path: Path):
    root = tmp_path / "plugins"
    make_notes(root / "cache/acme/notes/1.0.0")
    write(root, "cache/acme/notes/1.0.0/.orphaned_at", "1")
    make_notes(root / "cache/acme/notes/2.0.0")
    d = discover(root)
    assert [(p.key, p.version, p.origin) for p in d.plugins] == [("notes@acme", "2.0.0", "cache")]


def test_plugin_dir_is_locked_as_inline(tmp_path: Path):
    write_json(
        tmp_path / "mine", ".claude-plugin/plugin.json", {"name": "mine", "version": "0.1.0"}
    )
    d = discover(tmp_path / "empty-root", [tmp_path / "mine"])
    assert [(p.key, p.origin) for p in d.plugins] == [("mine@inline", "plugin-dir")]


def test_helpers(monkeypatch, tmp_path: Path):
    assert split_id("a@b") == ("a", "b") and split_id("a") == ("a", None)
    assert display_path(Path.home() / "x") == "~/x"
    monkeypatch.setenv("CLAUDE_CODE_PLUGIN_CACHE_DIR", str(tmp_path))
    assert default_root() == tmp_path
    monkeypatch.delenv("CLAUDE_CODE_PLUGIN_CACHE_DIR")
    assert default_root() == Path.home() / ".claude" / "plugins"
