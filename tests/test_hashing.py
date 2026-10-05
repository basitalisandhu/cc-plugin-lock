from __future__ import annotations

import os
from pathlib import Path

import pytest

from cc_plugin_lock.hashing import (
    HashError,
    class_hashes,
    digest_bytes,
    excluded,
    hash_tree,
    normalise,
    tree_hash,
    walk,
)

from .conftest import write


def test_crlf_and_lf_hash_the_same(tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    write(a, "x.sh", b"echo 1\r\necho 2\r\n")
    write(b, "x.sh", b"echo 1\necho 2\n")
    assert hash_tree(a) == hash_tree(b)


def test_binary_files_are_not_normalised():
    data = b"\x00\x01\r\n"
    assert normalise(data) == data
    assert normalise(b"a\r\nb") == b"a\nb"


def test_size_is_the_normalised_length(tmp_path: Path):
    write(tmp_path, "f.txt", b"a\r\nb\r\n")
    [entry] = hash_tree(tmp_path)
    assert entry.size == 4
    assert entry.digest == digest_bytes(b"a\nb\n")


def test_tree_hash_is_order_independent():
    pairs = [("b", "sha256:2"), ("a", "sha256:1")]
    assert tree_hash(pairs) == tree_hash(list(reversed(pairs)))


@pytest.mark.skipif(os.name == "nt", reason="POSIX execute bits")
def test_execute_metadata_does_not_change_content_hash(tmp_path):
    script = write(tmp_path, "x.sh", "exit 0\n")
    script.chmod(0o644)
    [before] = hash_tree(tmp_path)
    script.chmod(0o641)
    [after] = hash_tree(tmp_path)
    assert before.executable is False and after.executable is True
    assert before.digest == after.digest and before.size == after.size
    assert tree_hash([(before.path, before.digest)]) == tree_hash([(after.path, after.digest)])


def test_tree_hash_changes_with_path_or_content():
    base = tree_hash([("a", "sha256:1")])
    assert tree_hash([("b", "sha256:1")]) != base
    assert tree_hash([("a", "sha256:2")]) != base


def test_walk_is_sorted_and_skips_default_exclusions(tmp_path: Path):
    for rel in ("z.md", "a/b.md", ".git/config", "x/__pycache__/m.pyc", ".orphaned_at", "m.pyc"):
        write(tmp_path, rel, "x")
    assert walk(tmp_path) == ["a/b.md", "z.md"]


def test_user_exclusions(tmp_path: Path):
    write(tmp_path, "node_modules/pkg/index.js", "x")
    write(tmp_path, "keep.js", "x")
    assert walk(tmp_path, ["node_modules/**"]) == ["keep.js"]
    assert excluded("docs/a.md", ["docs/*"])
    assert not excluded("src/a.md", ["docs/*"])


def test_symlink_is_hashed_by_target_not_followed(tmp_path: Path):
    write(tmp_path, "real.txt", "hello")
    os.symlink("real.txt", tmp_path / "link.txt")
    entries = {e.path: e for e in hash_tree(tmp_path)}
    assert entries["link.txt"].symlink == "real.txt"
    assert entries["link.txt"].digest != entries["real.txt"].digest


def test_missing_root_raises(tmp_path: Path):
    with pytest.raises(HashError):
        walk(tmp_path / "nope")


def test_class_hashes_group_by_class(tmp_path: Path):
    write(tmp_path, "a.md", "1")
    write(tmp_path, "b.sh", "2")
    entries = hash_tree(tmp_path)
    hashes = class_hashes(entries, {"a.md": "docs", "b.sh": "hooks"})
    assert set(hashes) == {"docs", "hooks"}
    assert hashes["docs"] == tree_hash([("a.md", entries[0].digest)])
