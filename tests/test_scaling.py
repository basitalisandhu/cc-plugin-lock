"""Scaling test: the example root with 30 and 300 extra installed plugins.

lock, verify (one hook script changed in every plugin) and scan must grow about linearly: 10 times the plugins
should take about 10 times as long. A quadratic loop shows up as about 100 times.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import time
from pathlib import Path

from cc_plugin_lock.cli import main

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "plugins-root"


def _root(dest: Path, n: int) -> Path:
    shutil.copytree(EXAMPLE, dest)
    installed = json.loads((dest / "installed_plugins.json").read_text(encoding="utf-8"))
    for i in range(n):
        shutil.copytree(dest / "cache/demo/formatter/1.0.0", dest / f"cache/demo/p{i}/1.0.0")
        installed["plugins"][f"p{i}@demo"] = [
            {"scope": "user", "installPath": f"cache/demo/p{i}/1.0.0", "version": "1.0.0"}
        ]
    (dest / "installed_plugins.json").write_text(json.dumps(installed), encoding="utf-8")
    return dest


def _run(argv: list[str]) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return main(argv)


def _cycle(root: Path) -> float:
    lock = root.parent / f"{root.name}.lock.json"
    start = time.perf_counter()
    assert _run(["lock", "--root", str(root), "-o", str(lock)]) == 0
    for script in root.glob("cache/demo/*/*/scripts/format.sh"):
        script.write_text(script.read_text(encoding="utf-8") + "echo changed\n", encoding="utf-8")
    assert _run(["verify", "--root", str(root), "--lock", str(lock)]) == 1
    assert _run(["scan", str(root / "cache" / "demo")]) in (0, 1)
    return time.perf_counter() - start


def test_runtime_grows_linearly(tmp_path):
    small = _cycle(_root(tmp_path / "small", 30))
    big = _cycle(_root(tmp_path / "big", 300))
    assert big < max(small, 0.05) * 30, f"30 plugins: {small:.2f}s, 300 plugins: {big:.2f}s"
