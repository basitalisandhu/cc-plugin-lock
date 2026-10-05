"""Build, write, read and validate ``cc-plugins.lock.json`` (schema in docs/lockfile.md)."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .classify import Classifier
from .discover import Discovery, Plugin, discover, display_path
from .hashing import HashError, class_hashes, hash_tree, read_normalised, tree_hash

LOCKFILE_VERSION = 1
DEFAULT_LOCK = "cc-plugins.lock.json"
STORE_DIR = ".cc-plugin-lock"


class LockError(Exception):
    """The lock file is missing, unreadable or not a lock this version understands."""


@dataclass
class Snapshot:
    """A lock document plus the paths and problems found while building it."""

    doc: dict[str, Any]
    paths: dict[str, Path] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


RUNTIME_CLASSES = ("hooks", "mcp", "lsp", "monitors", "executables", "dependencies")
MANIFEST_RUNTIME_KEYS = {
    "hooks": "hooks",
    "mcpServers": "mcp",
    "lspServers": "lsp",
    "monitors": "monitors",
}


def runtime_components(manifest: dict[str, Any], classes: set[str]) -> list[str]:
    """Component types that start processes: from files present or declared in the manifest."""
    found = {c for c in RUNTIME_CLASSES if c in classes}
    experimental = manifest.get("experimental")
    for key, cls in MANIFEST_RUNTIME_KEYS.items():
        if manifest.get(key) or (isinstance(experimental, dict) and experimental.get(key)):
            found.add(cls)
    return [c for c in RUNTIME_CLASSES if c in found]


def plugin_record(plugin: Plugin, excludes: list[str]) -> dict[str, Any]:
    """Hash one plugin and return its lock record."""
    entries = hash_tree(plugin.path, excludes)
    classifier = Classifier(plugin.path)
    classes = classifier.classify_all(e.path for e in entries)
    files: dict[str, dict[str, Any]] = {}
    for e in entries:
        rec: dict[str, Any] = {"sha256": e.digest, "size": e.size, "class": classes[e.path]}
        if e.symlink is not None:
            rec["symlink"] = e.symlink
        if e.executable:
            rec["executable"] = True
        files[e.path] = rec
    record: dict[str, Any] = {
        "id": plugin.plugin_id,
        "name": plugin.name,
        "marketplace": plugin.marketplace,
        "version": plugin.version,
        "gitCommitSha": plugin.git_commit,
        "origin": plugin.origin,
        "scopes": sorted(plugin.scopes),
        "path": display_path(plugin.path.resolve()),
        "entrySource": plugin.entry_source,
        "runtime": runtime_components(classifier.manifest, set(classes.values())),
        "contentHash": tree_hash((e.path, e.digest) for e in entries),
        "components": class_hashes(entries, classes),
        "fileCount": len(entries),
        "files": files,
    }
    return record


def build(
    root: Path,
    plugin_dirs: list[Path] | None = None,
    excludes: list[str] | None = None,
    discovery: Discovery | None = None,
) -> Snapshot:
    """Discover and hash every plugin under ``root``; never raises for one bad plugin."""
    excl = sorted(set(excludes or []))
    d = discovery or discover(root, plugin_dirs)
    snap = Snapshot(doc={}, warnings=list(d.warnings))
    plugins: dict[str, Any] = {}
    for p in d.plugins:
        try:
            plugins[p.key] = plugin_record(p, excl)
            snap.paths[p.key] = p.path
        except HashError as exc:
            snap.errors.append(f"{p.key}: {exc}")
    marketplaces = {
        name: {
            "source": m.source,
            "installLocation": m.install_location,
            "autoUpdate": m.auto_update,
            "catalogHash": m.catalog_hash,
        }
        for name, m in sorted(d.marketplaces.items())
    }
    snap.doc = {
        "lockfileVersion": LOCKFILE_VERSION,
        "generator": "cc-plugin-lock",
        "generatorVersion": __version__,
        "hashAlgorithm": "sha256",
        "pluginsRoot": display_path(root.resolve()),
        "pluginDirs": [display_path(p.resolve()) for p in plugin_dirs or []],
        "exclude": excl,
        "marketplaces": marketplaces,
        "plugins": dict(sorted(plugins.items())),
    }
    return snap


def dumps(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".cc-plugin-lock.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def read(path: Path) -> dict[str, Any]:
    """Load and validate a lock file."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LockError(
            f"lock file not found: {path} (create it with `cc-plugin-lock lock`)"
        ) from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise LockError(f"cannot read lock file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise LockError(
            f"lock file {path} is not valid JSON: {exc.msg} at line {exc.lineno}"
        ) from exc
    validate(doc, path)
    return doc


def validate(doc: Any, path: Path | str = "lock") -> None:
    if not isinstance(doc, dict):
        raise LockError(f"{path}: the lock must be a JSON object")
    version = doc.get("lockfileVersion")
    if version != LOCKFILE_VERSION:
        raise LockError(
            f"{path}: lockfileVersion {version!r} is not supported (this version reads "
            f"{LOCKFILE_VERSION}); re-create the lock with `cc-plugin-lock lock`"
        )
    if doc.get("hashAlgorithm") != "sha256":
        raise LockError(f"{path}: hashAlgorithm must be sha256")
    plugins = doc.get("plugins")
    if not isinstance(plugins, dict):
        raise LockError(f"{path}: plugins must be an object")
    for key, rec in plugins.items():
        if not isinstance(rec, dict) or not isinstance(rec.get("files"), dict):
            raise LockError(f"{path}: plugin {key!r} has no files map")
        if not isinstance(rec.get("contentHash"), str):
            raise LockError(f"{path}: plugin {key!r} has no contentHash")
        for rel, f in rec["files"].items():
            if not isinstance(f, dict) or not isinstance(f.get("sha256"), str):
                raise LockError(f"{path}: plugin {key!r} file {rel!r} has no sha256")
    if not isinstance(doc.get("marketplaces", {}), dict):
        raise LockError(f"{path}: marketplaces must be an object")


# ---------------------------------------------------------------------- content store


def store_dir(lock_path: Path) -> Path:
    return lock_path.resolve().parent / STORE_DIR


def object_path(store: Path, digest: str) -> Path:
    hexd = digest.split(":", 1)[-1]
    return store / "objects" / hexd[:2] / hexd


def store_plugin(store: Path, plugin_path: Path, record: dict[str, Any]) -> int:
    """Copy the normalised bytes of every file into the content-addressed store."""
    written = 0
    for rel, f in record["files"].items():
        obj = object_path(store, f["sha256"])
        if obj.exists():
            continue
        full = plugin_path / rel
        if "symlink" in f:
            data = f["symlink"].encode("utf-8", "surrogateescape")
        else:
            data = read_normalised(full)
        obj.parent.mkdir(parents=True, exist_ok=True)
        obj.write_bytes(data)
        written += 1
    return written


def load_object(store: Path, digest: str) -> bytes | None:
    try:
        return object_path(store, digest).read_bytes()
    except OSError:
        return None
