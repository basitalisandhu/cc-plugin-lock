"""Command-line interface: lock, verify, diff, hook and scan."""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .classify import LOW, SEVERITIES
from .discover import default_root, discover, display_path, expand_path
from .hashing import HashError, read_normalised
from .hookcfg import block, render_snippet, settings_snippet, warn
from .lockfile import (
    DEFAULT_LOCK,
    LockError,
    atomic_write,
    build,
    dumps,
    load_object,
    read,
    store_dir,
    store_plugin,
)
from .report import SCAN_FORMATS, VERIFY_FORMATS, render_scan, render_verify, scan_fails, short
from .scan import scan
from .verify import compare

EXIT_OK = 0
EXIT_CHANGED = 1
EXIT_ERROR = 2

# Marketplaces the plugin loading reference lists as auto-updating unless turned off.
DEFAULT_AUTO_UPDATE = frozenset({"claude-plugins-official"})

DESCRIPTION = (
    "Lock file for Claude Code plugins: pin installed marketplace plugins and skills to "
    "content hashes, verify them before a session loads them, show what changed, and scan "
    "a plugin folder before installing it."
)
EPILOG = (
    "Exit codes: 0 clean, 1 changes or findings at or above the threshold, 2 errors.\n"
    "Docs: https://github.com/basitalisandhu/cc-plugin-lock"
)


class _Formatter(argparse.RawDescriptionHelpFormatter):
    pass


def _common_root(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--root",
        type=Path,
        help="plugins root holding installed_plugins.json, known_marketplaces.json and cache/ "
        "(default: $CLAUDE_CODE_PLUGIN_CACHE_DIR or ~/.claude/plugins)",
    )
    p.add_argument(
        "--plugin-dir",
        type=Path,
        action="append",
        default=None,
        metavar="DIR",
        help="also lock a plugin directory that is not installed from a marketplace (repeatable)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cc-plugin-lock", description=DESCRIPTION, epilog=EPILOG, formatter_class=_Formatter
    )
    parser.add_argument("--version", action="version", version=f"cc-plugin-lock {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser(
        "lock",
        help="hash every installed plugin and write the lock file",
        description="Discover installed plugins and marketplaces, hash every file, and write "
        "the lock file. With --only, update just those plugins in an existing lock.",
        formatter_class=_Formatter,
    )
    _common_root(p)
    p.add_argument(
        "-o",
        "--output",
        "--lock",
        dest="lock",
        type=Path,
        default=Path(DEFAULT_LOCK),
        help=f"lock file to write (default: ./{DEFAULT_LOCK})",
    )
    p.add_argument(
        "--store",
        action="store_true",
        help="also keep a content-addressed copy of every file under .cc-plugin-lock/ "
        "next to the lock, so `diff` can show line changes",
    )
    p.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="path pattern inside each plugin to leave out (repeatable), e.g. 'node_modules/**'",
    )
    p.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="PLUGIN",
        help="update only this plugin (key, id or name) in the existing lock; repeatable",
    )
    p.add_argument("--quiet", "-q", action="store_true", help="print nothing on success")
    p.add_argument(
        "--check",
        action="store_true",
        help="compare the rebuilt lock byte for byte without writing the lock or store; "
        "exit 1 if different or missing",
    )

    p = sub.add_parser(
        "verify",
        help="recompute hashes and compare them with the lock",
        description="Recompute every installed plugin's hashes and report each one as "
        "unchanged, changed, added or removed. A changed hook, MCP, LSP, monitor, bin/, "
        "manifest or dependency file is HIGH, a changed skill, command, agent or script is "
        "MEDIUM, documentation is LOW.",
        epilog="Exit codes: 0 no change at or above --fail-on, 1 changes, 2 errors "
        "(with --format hook the exit code is always 0 and the decision is in the JSON).",
        formatter_class=_Formatter,
    )
    _common_root(p)
    p.add_argument(
        "--lock",
        type=Path,
        default=Path(DEFAULT_LOCK),
        help=f"lock file (default: ./{DEFAULT_LOCK})",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="fail closed: a missing or invalid lock, or a plugin that cannot be read, "
        "is an error (blocks the session with --format hook)",
    )
    p.add_argument(
        "--format",
        choices=VERIFY_FORMATS,
        default="table",
        help="table (default), json, sarif, or hook (SessionStart JSON)",
    )
    p.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default=LOW,
        help="lowest severity that counts as a failure (default: low, i.e. any change)",
    )
    p.add_argument("--output", type=Path, help="write the report to a file instead of stdout")

    p = sub.add_parser(
        "diff",
        help="show what changed in one plugin",
        description="Show the changed files of one plugin. With a content store (lock --store) "
        "text files are shown as a unified diff against the locked content; otherwise the "
        "changed paths are listed with their old and new hashes.",
        formatter_class=_Formatter,
    )
    p.add_argument("plugin", help="plugin key, id (name@marketplace) or name")
    _common_root(p)
    p.add_argument(
        "--lock",
        type=Path,
        default=Path(DEFAULT_LOCK),
        help=f"lock file (default: ./{DEFAULT_LOCK})",
    )
    p.add_argument(
        "--store", type=Path, help="content store (default: .cc-plugin-lock/ next to the lock)"
    )
    p.add_argument("-U", "--context", type=int, default=3, help="lines of context (default: 3)")

    p = sub.add_parser(
        "hook",
        help="print a SessionStart hook that runs verify before each session",
        description="Print a Claude Code settings block with a SessionStart hook that runs "
        "`verify --strict --format hook`. Changes at or above --fail-on stop the session "
        "with continue: false; smaller changes show a warning. Merge the block into "
        "~/.claude/settings.json.",
        formatter_class=_Formatter,
    )
    p.add_argument(
        "--lock",
        type=Path,
        default=Path(DEFAULT_LOCK),
        help="lock file the hook verifies; written as an absolute path",
    )
    p.add_argument("--root", type=Path, help="plugins root to pass to verify (default: the lock's)")
    p.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="high",
        help="lowest severity that stops the session (default: high)",
    )
    p.add_argument(
        "--exe",
        default="cc-plugin-lock",
        help="command that runs this tool, e.g. 'uvx cc-plugin-lock' (default: cc-plugin-lock)",
    )
    p.add_argument(
        "--matcher", default="startup|resume", help="SessionStart matcher (default: startup|resume)"
    )
    p.add_argument("--timeout", type=int, default=30, help="hook timeout in seconds (default: 30)")
    p.add_argument(
        "--no-strict", action="store_true", help="warn instead of blocking when the lock is missing"
    )

    p = sub.add_parser(
        "scan",
        help="static pre-install check of a plugin or marketplace folder",
        description="Check a plugin folder before installing it: hooks that pipe downloads "
        "into a shell, evaluate code, read credential stores, dump the environment or write "
        "outside the plugin; MCP servers that run unpinned npx, uvx or container packages or "
        "talk to remote URLs; skills with instruction-override, concealment or exfiltration "
        "text. A marketplace folder is scanned plugin by plugin.",
        epilog="Exit codes: 0 no finding at or above --fail-on, 1 findings, 2 errors.",
        formatter_class=_Formatter,
    )
    p.add_argument("path", type=Path, help="plugin directory (or marketplace directory)")
    p.add_argument(
        "--format", choices=SCAN_FORMATS, default="table", help="table (default), json or sarif"
    )
    p.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="medium",
        help="lowest severity that fails the scan (default: medium)",
    )
    p.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    return parser


# ---------------------------------------------------------------------- helpers


def _err(msg: str) -> None:
    print(f"cc-plugin-lock: {msg}", file=sys.stderr)


def _emit(text: str, output: Path | None) -> None:
    if output:
        atomic_write(output, text)
    else:
        sys.stdout.write(text)


def _root_from(args: argparse.Namespace, doc: dict[str, Any] | None) -> Path:
    if args.root:
        return args.root
    if doc and isinstance(doc.get("pluginsRoot"), str):
        return expand_path(doc["pluginsRoot"])
    return default_root()


def _dirs_from(args: argparse.Namespace, doc: dict[str, Any] | None) -> list[Path]:
    if args.plugin_dir:
        return list(args.plugin_dir)
    if doc and isinstance(doc.get("pluginDirs"), list):
        return [expand_path(p) for p in doc["pluginDirs"] if isinstance(p, str)]
    return []


def _resolve_key(name: str, plugins: dict[str, Any]) -> str | None:
    if name in plugins:
        return name
    by_id = [k for k, v in plugins.items() if v.get("id") == name]
    if len(by_id) == 1:
        return by_id[0]
    by_name = [k for k, v in plugins.items() if v.get("name") == name]
    if len(by_name) == 1:
        return by_name[0]
    return None


# ---------------------------------------------------------------------- commands


def cmd_lock(args: argparse.Namespace) -> int:
    existing: dict[str, Any] | None = None
    if args.only:
        try:
            existing = read(args.lock)
        except LockError as exc:
            if args.check and isinstance(exc.__cause__, FileNotFoundError):
                if not args.quiet:
                    print(f"cc-plugin-lock: {display_path(args.lock)} differs (lock file missing)")
                return EXIT_CHANGED
            _err(str(exc))
            return EXIT_ERROR
    root = _root_from(args, existing) if existing else (args.root or default_root())
    dirs = _dirs_from(args, existing) if existing else list(args.plugin_dir or [])
    excludes = args.exclude or (existing or {}).get("exclude", [])
    snap = build(root, dirs, excludes)
    for w in snap.warnings:
        _err(f"warning: {w}")
    if snap.errors:
        for e in snap.errors:
            _err(f"error: {e}")
        return EXIT_ERROR
    doc = snap.doc
    if existing is not None:
        merged = dict(existing["plugins"])
        for name in args.only:
            key = _resolve_key(name, snap.doc["plugins"]) or _resolve_key(name, merged)
            if key is None:
                _err(f"no plugin named {name!r} is installed or locked")
                return EXIT_ERROR
            if key in snap.doc["plugins"]:
                merged[key] = snap.doc["plugins"][key]
            else:
                merged.pop(key, None)
        doc = dict(existing)
        doc["plugins"] = dict(sorted(merged.items()))
        doc["generatorVersion"] = __version__
    if args.check:
        try:
            identical = args.lock.read_bytes() == dumps(doc).encode("utf-8")
        except FileNotFoundError:
            result = "differs (lock file missing)"
            identical = False
        except OSError as exc:
            _err(f"cannot read lock file {args.lock}: {exc}")
            return EXIT_ERROR
        else:
            result = "up to date" if identical else "differs from the current plugins"
        if not args.quiet:
            print(f"cc-plugin-lock: {display_path(args.lock)} {result}")
        return EXIT_OK if identical else EXIT_CHANGED
    if args.store:
        store = store_dir(args.lock)
        try:
            for key, rec in doc["plugins"].items():
                if key in snap.paths:
                    store_plugin(store, snap.paths[key], rec)
        except HashError as exc:
            _err(str(exc))
            return EXIT_ERROR
    atomic_write(args.lock, dumps(doc))
    if not args.quiet:
        plugins = doc["plugins"]
        print(
            f"cc-plugin-lock {__version__}: locked {len(plugins)} plugin(s) and "
            f"{len(doc.get('marketplaces', {}))} marketplace(s) under {doc['pluginsRoot']} "
            f"into {display_path(args.lock)}"
        )
        for key in plugins:
            rec = plugins[key]
            comps = ", ".join(sorted(rec.get("components", {})))
            print(
                f"  {key:<40} {short(rec['contentHash'])}  {rec.get('fileCount', 0):>4} file(s)  {comps}"
            )
        auto = [
            n
            for n, m in doc.get("marketplaces", {}).items()
            if m.get("autoUpdate") or (m.get("autoUpdate") is None and n in DEFAULT_AUTO_UPDATE)
        ]
        if auto:
            print(
                "note: auto-update is on for " + ", ".join(sorted(auto)) + "; updates land on "
                "disk mid-session and load at the next launch, which `verify` checks."
            )
        if args.store:
            print(f"stored file contents under {display_path(store_dir(args.lock))}")
    return EXIT_OK


def _verify_report(args: argparse.Namespace) -> tuple[Any, int | None, str | None]:
    """Return (report, early_exit_code, early_error)."""
    try:
        locked = read(args.lock)
    except LockError as exc:
        return None, EXIT_ERROR, str(exc)
    root = _root_from(args, locked)
    dirs = _dirs_from(args, locked)
    snap = build(root, dirs, locked.get("exclude", []))
    rep = compare(
        locked,
        snap.doc,
        lock_path=display_path(args.lock),
        root=display_path(root),
        abs_paths=snap.paths,
    )
    rep.errors += snap.errors
    rep.warnings += snap.warnings
    if not root.is_dir():
        rep.errors.append(f"plugins root not found: {display_path(root)}")
    return rep, None, None


def cmd_verify(args: argparse.Namespace) -> int:
    rep, code, error = _verify_report(args)
    if args.format == "hook":
        if error is not None:
            msg = f"cc-plugin-lock: cannot verify plugins: {error}"
            out = block(msg) if args.strict else warn(msg)
            sys.stdout.write(json.dumps(out) + "\n")
            return EXIT_OK
        if rep.errors and args.strict:
            msg = "cc-plugin-lock: cannot verify plugins: " + "; ".join(rep.errors)
            sys.stdout.write(json.dumps(block(msg)) + "\n")
            return EXIT_OK
        sys.stdout.write(render_verify(rep, "hook", args.fail_on))
        return EXIT_OK
    if error is not None:
        _err(error)
        return code or EXIT_ERROR
    _emit(render_verify(rep, args.format, args.fail_on), args.output)
    if rep.errors and (args.strict or not rep.plugins):
        for e in rep.errors:
            _err(f"error: {e}")
        return EXIT_ERROR
    return EXIT_CHANGED if rep.fails(args.fail_on) else EXIT_OK


def _diff_text(old: bytes | None, new: bytes | None, path: str, context: int) -> list[str]:
    def lines(b: bytes | None) -> list[str] | None:
        if b is None:
            return []
        if b"\0" in b[:8192]:
            return None
        try:
            return b.decode("utf-8").splitlines(keepends=True)
        except UnicodeDecodeError:
            return None

    a, b = lines(old), lines(new)
    if a is None or b is None:
        return [f"Binary file {path} differs\n"]
    out = list(
        difflib.unified_diff(
            a, b, fromfile=f"a/{path} (locked)", tofile=f"b/{path} (installed)", n=context
        )
    )
    return [ln if ln.endswith("\n") else ln + "\n\\ No newline at end of file\n" for ln in out]


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        locked = read(args.lock)
    except LockError as exc:
        _err(str(exc))
        return EXIT_ERROR
    root = _root_from(args, locked)
    d = discover(root, _dirs_from(args, locked))
    current_keys = {p.key: p for p in d.plugins}
    key = _resolve_key(args.plugin, locked["plugins"])
    current_key = key if key in current_keys else None
    if key is None:
        matches = [p.key for p in d.plugins if args.plugin in (p.key, p.plugin_id, p.name)]
        current_key = matches[0] if len(matches) == 1 else None
    elif current_key is None:
        pid = locked["plugins"][key].get("id")
        same = [p.key for p in d.plugins if p.plugin_id == pid]
        current_key = same[0] if len(same) == 1 else None
    if key is None and current_key is None:
        _err(f"no plugin named {args.plugin!r} in the lock or installed")
        return EXIT_ERROR
    only = [current_keys[current_key]] if current_key else []
    from .discover import Discovery

    snap = build(
        root, None, locked.get("exclude", []), discovery=Discovery(root=root, plugins=only)
    )
    if snap.errors:
        for e in snap.errors:
            _err(e)
        return EXIT_ERROR
    old_rec = locked["plugins"].get(key, {"files": {}}) if key else {"files": {}}
    new_rec = snap.doc["plugins"].get(current_key, {"files": {}}) if current_key else {"files": {}}
    store = args.store or store_dir(args.lock)
    plugin_path = current_keys[current_key].path if current_key else None
    label = current_key or key
    old_files, new_files = old_rec["files"], new_rec["files"]
    changed = sorted(
        p
        for p in set(old_files) | set(new_files)
        if old_files.get(p, {}).get("sha256") != new_files.get(p, {}).get("sha256")
    )
    if not changed:
        print(f"{label}: no changes against the lock")
        return EXIT_OK
    print(f"{label}: {len(changed)} changed file(s)")
    out: list[str] = []
    for rel in changed:
        o, n = old_files.get(rel), new_files.get(rel)
        cls = (n or o or {}).get("class", "other")
        kind = "modified" if o and n else ("added" if n else "removed")
        old_bytes = load_object(store, o["sha256"]) if o else None
        new_bytes = None
        if n and plugin_path is not None:
            try:
                p = plugin_path / rel
                new_bytes = n["symlink"].encode() if "symlink" in n else read_normalised(p)
            except (HashError, OSError):
                new_bytes = None
        out.append(
            f"{kind} {rel} [{cls}] {short(o['sha256'] if o else None)} -> {short(n['sha256'] if n else None)}\n"
        )
        if o and old_bytes is None:
            out.append(
                "  (no stored copy of the locked content; run `cc-plugin-lock lock --store` to keep one)\n"
            )
            continue
        out += _diff_text(old_bytes, new_bytes, rel, args.context)
    sys.stdout.write("".join(out))
    return EXIT_CHANGED


def cmd_hook(args: argparse.Namespace) -> int:
    lock = args.lock.expanduser().resolve()
    root = str(args.root.expanduser().resolve()) if args.root else None
    snippet = settings_snippet(
        str(lock),
        exe=args.exe,
        root=root,
        fail_on=args.fail_on,
        matcher=args.matcher,
        timeout=args.timeout,
        strict=not args.no_strict,
    )
    sys.stdout.write(render_snippet(snippet))
    if not lock.exists():
        _err(
            f"note: {display_path(lock)} does not exist yet; run `cc-plugin-lock lock -o {display_path(lock)}` first"
        )
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    res = scan(args.path)
    _emit(render_scan(res, args.format), args.output)
    if res.errors and not res.files:
        for e in res.errors:
            _err(e)
        return EXIT_ERROR
    return EXIT_CHANGED if scan_fails(res, args.fail_on) else EXIT_OK


COMMANDS = {
    "lock": cmd_lock,
    "verify": cmd_verify,
    "diff": cmd_diff,
    "hook": cmd_hook,
    "scan": cmd_scan,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_ERROR
    try:
        return COMMANDS[args.command](args)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
