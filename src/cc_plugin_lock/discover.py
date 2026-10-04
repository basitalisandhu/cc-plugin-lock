"""Find installed plugins and known marketplaces on disk.

Claude Code keeps its plugin state under one plugins root, ``~/.claude/plugins`` unless
``CLAUDE_CODE_PLUGIN_CACHE_DIR`` is set:

- ``installed_plugins.json`` records each install (``scope``, ``installPath``, ``version``
  and, for git sources, ``gitCommitSha``) under a ``<name>@<marketplace>`` id;
- ``known_marketplaces.json`` records each marketplace's ``source``, ``installLocation``
  and ``autoUpdate``;
- ``cache/<marketplace>/<plugin>/<version>/`` holds the copied plugin files, and
  ``marketplaces/<name>/`` the marketplace clones.

When ``installed_plugins.json`` is missing, the cache directories are scanned instead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .classify import load_json, load_manifest
from .hashing import HashError, digest_bytes, read_normalised

INSTALLED_FILE = "installed_plugins.json"
MARKETPLACES_FILE = "known_marketplaces.json"
ORPHAN_MARKER = ".orphaned_at"


@dataclass
class Plugin:
    """One plugin install to lock or verify."""

    key: str
    plugin_id: str
    name: str
    marketplace: str | None
    path: Path
    version: str | None = None
    git_commit: str | None = None
    scopes: list[str] = field(default_factory=list)
    origin: str = "installed"
    entry_source: Any = None


@dataclass
class Marketplace:
    name: str
    source: Any = None
    install_location: str | None = None
    auto_update: bool | None = None
    catalog_hash: str | None = None


@dataclass
class Discovery:
    root: Path
    plugins: list[Plugin] = field(default_factory=list)
    marketplaces: dict[str, Marketplace] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def default_root() -> Path:
    """The plugins root Claude Code uses on this machine."""
    override = os.environ.get("CLAUDE_CODE_PLUGIN_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".claude" / "plugins"


def display_path(path: Path | str) -> str:
    """A path with the home directory shown as ``~``, so lock files carry no user name."""
    p = str(path)
    home = str(Path.home())
    if home and home != "/" and (p == home or p.startswith(home + os.sep)):
        return "~" + p[len(home) :].replace(os.sep, "/")
    return p.replace(os.sep, "/")


def expand_path(path: str) -> Path:
    return Path(path).expanduser()


def split_id(plugin_id: str) -> tuple[str, str | None]:
    name, sep, marketplace = plugin_id.rpartition("@")
    if not sep:
        return plugin_id, None
    return name, marketplace


def _resolve_install_path(
    root: Path, raw: Any, marketplace: str | None, name: str, version: str | None
) -> Path | None:
    candidates: list[Path] = []
    if isinstance(raw, str) and raw:
        p = Path(raw).expanduser()
        candidates.append(p if p.is_absolute() else root / p)
    if marketplace and version:
        # Portable fallback: the same install under this root (a container mount, a copy).
        candidates.append(root / "cache" / marketplace / name / version)
    for c in candidates:
        if c.is_dir():
            return c
    return None


def _catalog(location: Path) -> tuple[str | None, dict[str, Any]]:
    """Hash of a marketplace's ``marketplace.json`` and its entries by plugin name."""
    path = location / ".claude-plugin" / "marketplace.json"
    if not path.is_file():
        return None, {}
    try:
        digest = digest_bytes(read_normalised(path))
    except HashError:
        return None, {}
    data = load_json(path)
    entries: dict[str, Any] = {}
    if isinstance(data, dict) and isinstance(data.get("plugins"), list):
        for e in data["plugins"]:
            if isinstance(e, dict) and isinstance(e.get("name"), str):
                entries[e["name"]] = e
    return digest, entries


def discover(root: Path, plugin_dirs: list[Path] | None = None) -> Discovery:
    """Read the plugin registry under ``root`` and return every plugin install found."""
    d = Discovery(root=root)
    catalogs: dict[str, dict[str, Any]] = {}

    known = load_json(root / MARKETPLACES_FILE)
    if (root / MARKETPLACES_FILE).exists() and not isinstance(known, dict):
        d.warnings.append(f"{display_path(root / MARKETPLACES_FILE)} is not a JSON object")
    if isinstance(known, dict):
        for name in sorted(known):
            rec = known[name] if isinstance(known[name], dict) else {}
            loc = rec.get("installLocation")
            location = Path(loc).expanduser() if isinstance(loc, str) else None
            if location is None or not location.is_dir():
                location = root / "marketplaces" / name
            digest, entries = _catalog(location) if location.is_dir() else (None, {})
            catalogs[name] = entries
            auto = rec.get("autoUpdate")
            d.marketplaces[name] = Marketplace(
                name=name,
                source=rec.get("source"),
                install_location=display_path(loc) if isinstance(loc, str) else None,
                auto_update=auto if isinstance(auto, bool) else None,
                catalog_hash=digest,
            )

    installed_path = root / INSTALLED_FILE
    found: dict[Path, Plugin] = {}
    if installed_path.exists():
        data = load_json(installed_path)
        if not isinstance(data, dict):
            d.warnings.append(f"{display_path(installed_path)} is not valid JSON")
            data = {}
        records = data.get("plugins", {}) if "plugins" in data else data
        if not isinstance(records, dict):
            records = {}
        for plugin_id in sorted(records):
            raw = records[plugin_id]
            installs = raw if isinstance(raw, list) else [raw]
            name, marketplace = split_id(plugin_id)
            for rec in installs:
                if not isinstance(rec, dict):
                    continue
                version = rec.get("version") if isinstance(rec.get("version"), str) else None
                path = _resolve_install_path(
                    root, rec.get("installPath"), marketplace, name, version
                )
                if path is None:
                    d.warnings.append(
                        f"{plugin_id}: install path not found: {rec.get('installPath')}"
                    )
                    continue
                scope = rec.get("scope") if isinstance(rec.get("scope"), str) else "unknown"
                project = rec.get("projectPath")
                scope_label = f"{scope}:{display_path(project)}" if project else scope
                resolved = path.resolve()
                if resolved in found:
                    if scope_label not in found[resolved].scopes:
                        found[resolved].scopes.append(scope_label)
                    continue
                sha = rec.get("gitCommitSha")
                found[resolved] = Plugin(
                    key=plugin_id,
                    plugin_id=plugin_id,
                    name=name,
                    marketplace=marketplace,
                    path=path,
                    version=version,
                    git_commit=sha if isinstance(sha, str) else None,
                    scopes=[scope_label],
                    entry_source=catalogs.get(marketplace or "", {}).get(name, {}).get("source"),
                )
    elif (root / "cache").is_dir():
        for mdir in sorted(p for p in (root / "cache").iterdir() if p.is_dir()):
            for pdir in sorted(p for p in mdir.iterdir() if p.is_dir()):
                for vdir in sorted(p for p in pdir.iterdir() if p.is_dir()):
                    if (vdir / ORPHAN_MARKER).exists():
                        continue
                    pid = f"{pdir.name}@{mdir.name}"
                    found[vdir.resolve()] = Plugin(
                        key=pid,
                        plugin_id=pid,
                        name=pdir.name,
                        marketplace=mdir.name,
                        path=vdir,
                        version=vdir.name,
                        origin="cache",
                        entry_source=catalogs.get(mdir.name, {}).get(pdir.name, {}).get("source"),
                    )

    for extra in plugin_dirs or []:
        if not extra.is_dir():
            d.warnings.append(f"--plugin-dir {display_path(extra)} is not a directory")
            continue
        manifest = load_manifest(extra)
        name = manifest.get("name") if isinstance(manifest.get("name"), str) else extra.name
        version = manifest.get("version") if isinstance(manifest.get("version"), str) else None
        pid = f"{name}@inline"
        resolved = extra.resolve()
        if resolved not in found:
            found[resolved] = Plugin(
                key=pid,
                plugin_id=pid,
                name=name,
                marketplace=None,
                path=extra,
                version=version,
                scopes=["plugin-dir"],
                origin="plugin-dir",
            )

    plugins = sorted(found.values(), key=lambda p: (p.plugin_id, p.version or "", str(p.path)))
    counts: dict[str, int] = {}
    for p in plugins:
        counts[p.plugin_id] = counts.get(p.plugin_id, 0) + 1
    seen: set[str] = set()
    for p in plugins:
        if counts[p.plugin_id] > 1:
            p.key = f"{p.plugin_id}#{p.version or p.path.name}"
        while p.key in seen:
            p.key += "+"
        seen.add(p.key)
    d.plugins = plugins
    return d
