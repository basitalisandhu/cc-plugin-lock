"""lockfile.py: validation, the content store and atomic writes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cc_plugin_lock import lockfile
from cc_plugin_lock.discover import Plugin
from cc_plugin_lock.lockfile import (
    LockError,
    atomic_write,
    build,
    load_object,
    object_path,
    read,
    runtime_components,
    store_plugin,
    validate,
)

from .conftest import run, write

GOOD = "sha256:" + "a" * 64


def doc(**over):
    base = {
        "lockfileVersion": 1,
        "hashAlgorithm": "sha256",
        "plugins": {"p@m": {"contentHash": GOOD, "files": {"a": {"sha256": GOOD}}}},
    }
    base.update(over)
    return base


@pytest.mark.parametrize(
    ("bad", "message"),
    [
        ([], "must be a JSON object"),
        (doc(lockfileVersion=2), "lockfileVersion 2 is not supported"),
        (doc(hashAlgorithm="md5"), "hashAlgorithm must be sha256"),
        (doc(plugins=[]), "plugins must be an object"),
        (doc(plugins={"p": {"contentHash": GOOD}}), "has no files map"),
        (doc(plugins={"p": {"files": {}}}), "has no contentHash"),
        (doc(plugins={"p": {"contentHash": GOOD, "files": {"a": {}}}}), "has no sha256"),
        (doc(marketplaces=[]), "marketplaces must be an object"),
        (
            doc(plugins={"p": {"contentHash": GOOD, "files": {"a": {"sha256": "sha256:../../x"}}}}),
            "invalid sha256",
        ),
        (
            doc(plugins={"p": {"contentHash": GOOD, "files": {"a": {"sha256": "sha256:ABC"}}}}),
            "invalid sha256",
        ),
    ],
)
def test_validate_rejects(bad, message):
    with pytest.raises(LockError, match=message):
        validate(bad, "x.json")


def test_validate_accepts_a_minimal_lock():
    validate(doc())


def test_read_reports_unreadable_and_non_utf8(tmp_path: Path):
    (tmp_path / "dir.json").mkdir()
    with pytest.raises(LockError, match="cannot read lock file"):
        read(tmp_path / "dir.json")
    (tmp_path / "bin.json").write_bytes(b"\xff\xfe\x00")
    with pytest.raises(LockError, match="cannot read lock file"):
        read(tmp_path / "bin.json")


def test_object_path_refuses_anything_but_a_digest(tmp_path: Path):
    assert object_path(tmp_path, GOOD) == tmp_path / "objects" / "aa" / ("a" * 64)
    for bad in ("sha256:../../etc/passwd", "../x", "sha256:" + "a" * 63, GOOD + "\n"):
        with pytest.raises(ValueError):
            object_path(tmp_path, bad)
        assert load_object(tmp_path, bad) is None


def test_diff_cannot_be_pointed_outside_the_store(locked):
    plugins, lock = locked
    outside = lock.parent / "outside.txt"
    outside.write_text("not plugin content\n")
    data = json.loads(lock.read_text())
    data["plugins"]["formatter@acme"]["files"]["README.md"]["sha256"] = "sha256:../../outside.txt"
    lock.write_text(json.dumps(data))
    write(plugins.formatter, "README.md", "changed\n")
    rc, out, err = run("diff", "formatter", "--lock", str(lock))
    assert rc == 2 and "invalid sha256" in err and "not plugin content" not in out
    rc, _, err = run("verify", "--lock", str(lock))
    assert rc == 2 and "invalid sha256" in err


def test_store_keeps_symlink_targets_and_skips_existing_objects(tmp_path: Path):
    plugin = tmp_path / "p"
    write(plugin, "a.txt", "hello\r\n")
    (plugin / "link").symlink_to("a.txt")
    store = tmp_path / "store"
    record = lockfile.plugin_record(
        Plugin(key="p@m", plugin_id="p@m", name="p", marketplace="m", path=plugin), []
    )
    assert store_plugin(store, plugin, record) == 2
    assert load_object(store, record["files"]["a.txt"]["sha256"]) == b"hello\n"
    assert load_object(store, record["files"]["link"]["sha256"]) == b"a.txt"
    assert store_plugin(store, plugin, record) == 0


def test_atomic_write_leaves_no_temp_file_on_failure(tmp_path: Path, monkeypatch):
    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(lockfile.os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        atomic_write(tmp_path / "out" / "l.json", "{}\n")
    assert list((tmp_path / "out").iterdir()) == []


def test_runtime_components_from_manifest_and_experimental():
    assert runtime_components({}, {"skills"}) == []
    assert runtime_components({"mcpServers": "./m.json"}, set()) == ["mcp"]
    assert runtime_components({"experimental": {"monitors": "./m.json"}}, {"bin"}) == ["monitors"]
    assert runtime_components({}, {"executables", "hooks"}) == ["hooks", "executables"]


def test_build_records_an_unreadable_plugin_as_an_error(tmp_path: Path):
    from cc_plugin_lock.discover import Discovery

    missing = Plugin(
        key="gone@m", plugin_id="gone@m", name="gone", marketplace="m", path=tmp_path / "nope"
    )
    snap = build(tmp_path, discovery=Discovery(root=tmp_path, plugins=[missing]))
    assert snap.doc["plugins"] == {} and snap.errors and snap.errors[0].startswith("gone@m: ")
