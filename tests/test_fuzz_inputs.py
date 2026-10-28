"""Seeded fuzz tests: bad bytes and wrong value types in every file cc-plugin-lock reads.

Each command must end with exit code 0, 1 or 2 and never a traceback; a bad lock file is exit code 2 naming it.
Each run has a time limit, so a hang fails the test instead of stalling CI.
"""

from __future__ import annotations

import contextlib
import io
import json
import random
import shutil
import threading
from pathlib import Path

import pytest

from cc_plugin_lock.cli import main

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "plugins-root"
FILES = sorted(str(p.relative_to(EXAMPLE)) for p in EXAMPLE.rglob("*") if p.is_file())
JSON_FILES = [f for f in FILES if f.endswith(".json")]
SEED = 20261028
BAD = {
    "empty": b"",
    "not-utf8": b"\xff\xfe\x00"
    + bytes(random.Random(SEED).randrange(128, 256) for _ in range(256)),
    "truncated": b'{"plugins": {"x": [',
    "deep": b"[" * 50_000 + b"]" * 50_000,
    "nul": b"---\nname: x\n---\n\x00\x00",
}
WRONG = [None, True, 7, -1.5, "x", [], {}, [1, [2]], {"a": {"b": None}}, "../../etc"]


def _run(argv: list[str], limit: float = 30.0) -> tuple[int, str]:
    out: dict[str, object] = {}

    def target() -> None:
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            try:
                out["code"] = main(argv)
            except SystemExit as e:
                out["code"] = e.code
            except BaseException as e:  # the test reports any escape as a crash
                out["crash"] = repr(e)
        out["text"] = sink.getvalue()

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(limit)
    assert not t.is_alive(), f"cc-plugin-lock {' '.join(argv)} did not finish in {limit}s"
    assert "crash" not in out, out["crash"]
    return out["code"], out["text"]  # type: ignore[return-value]


def _commands(root: Path, tmp: Path) -> list[list[str]]:
    lock = tmp / "lock.json"
    return [
        ["lock", "--root", str(root), "-o", str(lock)],
        ["verify", "--root", str(root), "--lock", str(lock)],
        ["scan", str(root / "cache" / "demo" / "formatter" / "1.0.0")],
        ["scan", str(root / "marketplaces" / "demo")],
    ]


def _check_all(root: Path, tmp: Path) -> None:
    for argv in _commands(root, tmp):
        code, text = _run(argv)
        assert code in (0, 1, 2), (argv, code, text[-400:])
        assert "Traceback" not in text, text[-800:]


@pytest.mark.parametrize("kind", sorted(BAD))
@pytest.mark.parametrize("rel", FILES)
def test_bad_bytes_never_crash(tmp_path, rel, kind):
    root = tmp_path / "root"
    shutil.copytree(EXAMPLE, root)
    (root / rel).write_bytes(BAD[kind])
    _check_all(root, tmp_path)


def _paths(node, prefix=()):
    yield prefix
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _paths(v, (*prefix, k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _paths(v, (*prefix, i))


@pytest.mark.parametrize("rel", JSON_FILES)
def test_wrong_types_never_crash(tmp_path, rel):
    rng = random.Random(f"{SEED}/{rel}")
    original = json.loads((EXAMPLE / rel).read_text(encoding="utf-8"))
    for trial in range(15):
        doc = json.loads(json.dumps(original))
        for _ in range(rng.randint(1, 3)):
            paths = [p for p in _paths(doc) if p]
            if not paths:
                doc = json.loads(json.dumps(rng.choice(WRONG)))
                break
            path = rng.choice(paths)
            node = doc
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = json.loads(json.dumps(rng.choice(WRONG)))
        root = tmp_path / f"root{trial}"
        shutil.copytree(EXAMPLE, root)
        (root / rel).write_text(json.dumps(doc), encoding="utf-8")
        _check_all(root, tmp_path / f"t{trial}")


@pytest.mark.parametrize("kind", sorted(BAD))
def test_bad_lock_file_exits_2_naming_it(tmp_path, kind):
    lock = tmp_path / "team.lock.json"
    lock.write_bytes(BAD[kind])
    code, text = _run(["verify", "--root", str(EXAMPLE), "--lock", str(lock)])
    assert code == 2, text
    assert "team.lock.json" in text


def test_wrong_types_in_lock_file(tmp_path):
    good = tmp_path / "good.json"
    assert _run(["lock", "--root", str(EXAMPLE), "-o", str(good)])[0] == 0
    original = json.loads(good.read_text(encoding="utf-8"))
    rng = random.Random(SEED)
    for trial in range(40):
        doc = json.loads(json.dumps(original))
        paths = [p for p in _paths(doc) if p]
        path = rng.choice(paths)
        node = doc
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = json.loads(json.dumps(rng.choice(WRONG)))
        lock = tmp_path / f"lock{trial}.json"
        lock.write_text(json.dumps(doc), encoding="utf-8")
        for argv in (
            ["verify", "--root", str(EXAMPLE), "--lock", str(lock)],
            ["diff", "formatter@demo", "--root", str(EXAMPLE), "--lock", str(lock)],
        ):
            code, text = _run(argv)
            assert code in (0, 1, 2), (argv, text[-400:])
