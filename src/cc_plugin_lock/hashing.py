"""Content hashing: one SHA-256 per file and a hash list per plugin and per component class.

The algorithm is documented in ``docs/lockfile.md``. In short:

1. Walk the plugin directory without following symbolic links, skipping the default
   exclusions (``.git/``, ``__pycache__/``, ``.orphaned_at``, ``.DS_Store``, ``*.pyc``)
   and any ``--exclude`` patterns.
2. For a regular file, read the bytes. When the first 8 KiB contain no NUL byte the file
   is treated as text and every CRLF is replaced by LF. The file digest is the SHA-256 of
   the result and the recorded size is its length.
3. For a symbolic link, the digest is the SHA-256 of ``b"symlink\\0" + target``.
4. A tree hash is the SHA-256 of the concatenation of ``<path>\\0<digest>\\n`` for each
   file, sorted by path (posix separators, compared as UTF-8 bytes).
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

HASH_PREFIX = "sha256:"
TEXT_SNIFF_BYTES = 8192

DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset({".git", "__pycache__"})
DEFAULT_EXCLUDED_FILES: frozenset[str] = frozenset({".orphaned_at", ".DS_Store"})
DEFAULT_EXCLUDED_SUFFIXES: tuple[str, ...] = (".pyc",)


class HashError(Exception):
    """A file could not be read while hashing."""


@dataclass(frozen=True)
class FileEntry:
    """One hashed file inside a plugin."""

    path: str
    digest: str
    size: int
    symlink: str | None = None
    executable: bool = False


def is_text(data: bytes) -> bool:
    """True when the first 8 KiB contain no NUL byte."""
    return b"\0" not in data[:TEXT_SNIFF_BYTES]


def normalise(data: bytes) -> bytes:
    """Return the bytes that are hashed: CRLF becomes LF for text, binary is unchanged."""
    if is_text(data):
        return data.replace(b"\r\n", b"\n")
    return data


def digest_bytes(data: bytes) -> str:
    return HASH_PREFIX + hashlib.sha256(data).hexdigest()


def symlink_digest(target: str) -> str:
    return digest_bytes(b"symlink\0" + target.encode("utf-8", "surrogateescape"))


def tree_hash(entries: Iterable[tuple[str, str]]) -> str:
    """Hash list over ``(path, digest)`` pairs, sorted by the UTF-8 bytes of the path."""
    h = hashlib.sha256()
    for path, digest in sorted(entries, key=lambda e: e[0].encode("utf-8", "surrogateescape")):
        h.update(path.encode("utf-8", "surrogateescape"))
        h.update(b"\0")
        h.update(digest.encode("ascii"))
        h.update(b"\n")
    return HASH_PREFIX + h.hexdigest()


def excluded(rel: str, patterns: Iterable[str]) -> bool:
    """True when ``rel`` (posix, relative to the plugin root) matches an exclusion."""
    parts = rel.split("/")
    if any(p in DEFAULT_EXCLUDED_DIRS for p in parts[:-1]):
        return True
    name = parts[-1]
    if name in DEFAULT_EXCLUDED_FILES or name.endswith(DEFAULT_EXCLUDED_SUFFIXES):
        return True
    for pat in patterns:
        if fnmatch.fnmatchcase(rel, pat):
            return True
        stem = pat[:-3] if pat.endswith("/**") else pat.rstrip("/")
        if stem and (rel == stem or rel.startswith(stem + "/")):
            return True
    return False


def read_normalised(path: Path) -> bytes:
    """Read a file and return the normalised bytes that its digest covers."""
    try:
        return normalise(path.read_bytes())
    except OSError as exc:
        raise HashError(f"cannot read {path}: {exc.strerror or exc}") from exc


def hash_file(root: Path, rel: str) -> FileEntry:
    full = root / rel
    if full.is_symlink():
        target = os.readlink(full)
        return FileEntry(rel, symlink_digest(target), len(target), symlink=target)
    data = read_normalised(full)
    return FileEntry(
        rel, digest_bytes(data), len(data), executable=bool(full.stat().st_mode & 0o111)
    )


def walk(root: Path, patterns: Iterable[str] = ()) -> list[str]:
    """Every file and symbolic link under ``root`` as a sorted list of posix paths."""
    pats = list(patterns)
    out: list[str] = []
    if not root.is_dir():
        raise HashError(f"not a directory: {root}")

    def onerror(exc: OSError) -> None:
        raise HashError(f"cannot list {exc.filename}: {exc.strerror or exc}")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=onerror):
        base = Path(dirpath).relative_to(root)
        keep_dirs = []
        for d in sorted(dirnames):
            rel = (base / d).as_posix()
            if (Path(dirpath) / d).is_symlink():
                if not excluded(rel, pats):
                    out.append(rel)
                continue
            if d in DEFAULT_EXCLUDED_DIRS or excluded(rel + "/x", pats):
                continue
            keep_dirs.append(d)
        dirnames[:] = keep_dirs
        for f in filenames:
            rel = (base / f).as_posix()
            if not excluded(rel, pats):
                out.append(rel)
    return sorted(out, key=lambda p: p.encode("utf-8", "surrogateescape"))


def hash_tree(root: Path, patterns: Iterable[str] = ()) -> list[FileEntry]:
    """Hash every file under ``root``."""
    return [hash_file(root, rel) for rel in walk(root, patterns)]


def class_hashes(entries: Iterable[FileEntry], classes: Mapping[str, str]) -> dict[str, str]:
    """One tree hash per component class, for classes that have at least one file."""
    groups: dict[str, list[tuple[str, str]]] = {}
    for e in entries:
        groups.setdefault(classes[e.path], []).append((e.path, e.digest))
    return {c: tree_hash(groups[c]) for c in sorted(groups)}
