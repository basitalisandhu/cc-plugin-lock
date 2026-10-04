"""Renderers for verify and scan results: table, Markdown, JSON, SARIF and hook JSON."""

from __future__ import annotations

import hashlib
import html
import json
import re
from pathlib import Path
from typing import Any

from . import __version__
from .classify import CLASSES, HIGH, LOW, MEDIUM, SEVERITY_RANK, at_least
from .hookcfg import block, warn
from .scan import HELP_URI, RULES, ScanResult
from .verify import ADDED, CHANGED, REMOVED, UNCHANGED, Report

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/basitalisandhu/cc-plugin-lock"
SARIF_LEVELS = {HIGH: "error", MEDIUM: "warning", LOW: "note"}
SECURITY_SEVERITY = {HIGH: "8.0", MEDIUM: "5.0", LOW: "2.0"}
VERIFY_FORMATS = ("table", "markdown", "json", "sarif", "hook")
SCAN_FORMATS = ("table", "json", "sarif")


def short(digest: str | None) -> str:
    if not digest:
        return "-"
    return digest.split(":", 1)[-1][:12]


def _table(rows: list[tuple[str, ...]], header: tuple[str, ...]) -> list[str]:
    widths = [max(len(r[i]) for r in [header, *rows]) for i in range(len(header) - 1)]

    def fmt(r: tuple[str, ...]) -> str:
        cells = [f"{r[i]:<{widths[i]}}" for i in range(len(widths))]
        return "  ".join([*cells, r[-1]]).rstrip()

    line = fmt(header)
    return [line, "-" * len(line), *(fmt(r) for r in rows)]


# ---------------------------------------------------------------------- verify


def _plugin_detail(p: Any) -> str:
    bits: list[str] = []
    if p.status == CHANGED:
        counts: dict[str, int] = {}
        for c in p.changes:
            counts[c.cls] = counts.get(c.cls, 0) + 1
        bits.append(
            f"{len(p.changes)} file(s): "
            + ", ".join(f"{c} {counts[c]}" for c in CLASSES if c in counts)
        )
    elif p.status == ADDED:
        bits.append("not in the lock; contains " + (", ".join(p.classes) or "no files"))
    elif p.status == REMOVED:
        bits.append("in the lock but not installed")
    if p.version_from != p.version_to and p.status == CHANGED:
        bits.append(f"version {p.version_from} -> {p.version_to}")
    if p.commit_from != p.commit_to and p.status == CHANGED and p.commit_from and p.commit_to:
        bits.append(f"commit {p.commit_from[:12]} -> {p.commit_to[:12]}")
    return "; ".join(bits)


def verify_table(rep: Report, *, verbose_unchanged: bool = True) -> str:
    s = rep.summary()
    lines = [
        f"cc-plugin-lock {__version__} verify: {len(rep.plugins)} plugin(s) compared with {rep.lock_path}",
        "",
    ]
    rows: list[tuple[str, ...]] = []
    for p in rep.plugins:
        if p.status == UNCHANGED and not verbose_unchanged:
            continue
        rows.append((p.status, (p.severity or "-").upper(), p.key, _plugin_detail(p)))
    if rows:
        lines += _table(rows, ("STATUS", "SEVERITY", "PLUGIN", "DETAIL"))
    for p in rep.plugins:
        if p.status not in (CHANGED, ADDED) or not p.changes:
            continue
        lines += ["", f"{p.key} ({p.severity.upper() if p.severity else '-'}):"]
        ordered = sorted(p.changes, key=lambda c: (-SEVERITY_RANK[c.severity], c.path))
        shown = ordered if p.status == CHANGED else [c for c in ordered if c.severity != LOW]
        for c in shown:
            lines.append(
                f"  {c.change:<8}  {c.severity.upper():<6}  {c.cls:<13}  {c.path}  "
                f"{short(c.old)} -> {short(c.new)}"
            )
        hidden = len(p.changes) - len(shown)
        if hidden:
            lines.append(f"  ... and {hidden} low-severity file(s); --format json lists them")
    if rep.marketplaces:
        lines += ["", "Marketplaces:"]
        for m in rep.marketplaces:
            lines.append(f"  {m.status:<8}  {(m.severity or '-').upper():<6}  {m.name}: {m.detail}")
    for w in rep.warnings:
        lines.append(f"warning: {w}")
    for e in rep.errors:
        lines.append(f"error: {e}")
    lines.append("")
    changed = s[CHANGED] + s[ADDED] + s[REMOVED]
    if changed or rep.marketplaces:
        lines.append(
            f"{s[UNCHANGED]} unchanged, {s[CHANGED]} changed, {s[ADDED]} added, {s[REMOVED]} removed; "
            f"highest severity {(s['maxSeverity'] or 'none').upper()}."
        )
        lines.append(
            "Review a plugin with `cc-plugin-lock diff <plugin>`; accept a reviewed change with "
            "`cc-plugin-lock lock --only <plugin>`."
        )
    else:
        lines.append(f"{s[UNCHANGED]} plugin(s) match the lock.")
    return "\n".join(lines) + "\n"


def _markdown_cell(text: str) -> str:
    escaped = html.escape(text)
    for char in "\\[]*_`~":
        escaped = escaped.replace(char, f"&#{ord(char)};")
    return escaped.replace("|", "&#124;").replace("\r", "").replace("\n", "<br>")


def verify_markdown(rep: Report) -> str:
    s = rep.summary()
    lines = [
        "## cc-plugin-lock verify",
        "",
        f"{len(rep.plugins)} plugin(s) compared with <code>{_markdown_cell(rep.lock_path)}</code>.",
        "",
        "| Status | Severity | Plugin | Detail |",
        "| --- | --- | --- | --- |",
    ]
    for p in rep.changed():
        lines.append(
            f"| {p.status} | {(p.severity or '-').upper()} | "
            f"<code>{_markdown_cell(p.key)}</code> | {_markdown_cell(_plugin_detail(p))} |"
        )
    lines += [
        "",
        f"{s[UNCHANGED]} unchanged, {s[CHANGED]} changed, {s[ADDED]} added, {s[REMOVED]} removed; "
        f"highest severity {(s['maxSeverity'] or 'none').upper()}.",
    ]
    for p in rep.plugins:
        if p.status != CHANGED:
            continue
        lines += [
            "",
            "<details>",
            f"<summary>{_markdown_cell(p.key)} ({(p.severity or '-').upper()})</summary>",
            "",
            "| Change | Severity | Class | File | Old hash | New hash |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for c in sorted(p.changes, key=lambda c: (-SEVERITY_RANK[c.severity], c.path)):
            lines.append(
                f"| {c.change} | {c.severity.upper()} | {c.cls} | "
                f"<code>{_markdown_cell(c.path)}</code> | {short(c.old)} | {short(c.new)} |"
            )
        lines += ["", "</details>"]
    if rep.marketplaces:
        lines += [
            "",
            "### Marketplaces",
            "",
            "| Status | Severity | Marketplace | Detail |",
            "| --- | --- | --- | --- |",
        ]
        for m in rep.marketplaces:
            lines.append(
                f"| {m.status} | {(m.severity or '-').upper()} | "
                f"<code>{_markdown_cell(m.name)}</code> | {_markdown_cell(m.detail)} |"
            )
    if rep.warnings or rep.errors:
        lines.append("")
        lines += [f"- Warning: {_markdown_cell(w)}" for w in rep.warnings]
        lines += [f"- Error: {_markdown_cell(e)}" for e in rep.errors]
    return "\n".join(lines) + "\n"


def verify_json(rep: Report) -> str:
    return json.dumps(rep.to_dict(), indent=2, sort_keys=False) + "\n"


VERIFY_RULES: dict[str, tuple[str, str, str]] = {
    **{
        f"changed-{c}": (
            sev,
            f"Locked {c} file changed",
            f"A file in the {c} class ({desc}) differs from the lock.",
        )
        for c, (sev, desc) in CLASSES.items()
    },
    "plugin-added": (
        MEDIUM,
        "Plugin not in the lock",
        "An installed plugin has no entry in the lock file.",
    ),
    "plugin-removed": (
        LOW,
        "Locked plugin not installed",
        "A plugin in the lock file is no longer installed.",
    ),
    "marketplace-changed": (
        MEDIUM,
        "Marketplace changed",
        "A known marketplace was added, removed or changed source or auto-update.",
    ),
}


def _uri(path: Path | str) -> str:
    p = str(path).replace("\\", "/")
    return "file://" + p if p.startswith("/") else "file:///" + p


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()[:32]


def _rules_block(rules: dict[str, tuple[str, str, str]], help_uri: str) -> list[dict[str, Any]]:
    out = []
    for rid, (sev, title, desc) in rules.items():
        out.append(
            {
                "id": rid,
                "name": "".join(
                    w[:1].upper() + w[1:] for w in re.split(r"[^A-Za-z0-9]+", title) if w
                ),
                "shortDescription": {"text": title},
                "fullDescription": {"text": desc},
                "helpUri": f"{help_uri}#{rid.lower()}",
                "help": {"text": desc},
                "defaultConfiguration": {"level": SARIF_LEVELS[sev]},
                "properties": {
                    "security-severity": SECURITY_SEVERITY[sev],
                    "tags": ["security", "supply-chain"],
                },
            }
        )
    return out


def _run(
    rules: list[dict[str, Any]],
    results: list[dict[str, Any]],
    notes: list[str],
    base: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "cc-plugin-lock",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFO_URI,
                "rules": rules,
            }
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": [
                    {"level": "warning", "message": {"text": n}} for n in notes
                ],
            }
        ],
    }
    if base:
        run["originalUriBaseIds"] = base
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def verify_sarif_doc(rep: Report) -> dict[str, Any]:
    rule_ids = list(VERIFY_RULES)
    rules = _rules_block(VERIFY_RULES, f"{INFO_URI}/blob/main/docs/lockfile.md")
    results: list[dict[str, Any]] = []
    for p in rep.plugins:
        if p.status == UNCHANGED:
            continue
        base = rep.abs_paths.get(p.key)
        if p.status == CHANGED:
            for c in p.changes:
                rid = f"changed-{c.cls}"
                loc = _uri(base / c.path) if base else c.path
                results.append(
                    {
                        "ruleId": rid,
                        "ruleIndex": rule_ids.index(rid),
                        "level": SARIF_LEVELS[c.severity],
                        "message": {
                            "text": f"{p.key}: {c.path} {c.change} ({c.cls}, {c.severity})."
                        },
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc}}}],
                        "partialFingerprints": {
                            "ccPluginLock/v1": _fingerprint(p.key, c.path, c.new or "", c.old or "")
                        },
                        "properties": {
                            "plugin": p.key,
                            "severity": c.severity,
                            "class": c.cls,
                            "change": c.change,
                            "old": c.old,
                            "new": c.new,
                        },
                    }
                )
        else:
            rid = "plugin-added" if p.status == ADDED else "plugin-removed"
            loc_uri = _uri(base) if base else (p.path or p.key)
            results.append(
                {
                    "ruleId": rid,
                    "ruleIndex": rule_ids.index(rid),
                    "level": SARIF_LEVELS[p.severity or LOW],
                    "message": {"text": f"{p.key}: {_plugin_detail(p)} ({p.severity})."},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc_uri}}}],
                    "partialFingerprints": {"ccPluginLock/v1": _fingerprint(p.key, p.status)},
                    "properties": {"plugin": p.key, "severity": p.severity, "classes": p.classes},
                }
            )
    for m in rep.marketplaces:
        results.append(
            {
                "ruleId": "marketplace-changed",
                "ruleIndex": rule_ids.index("marketplace-changed"),
                "level": SARIF_LEVELS[m.severity or LOW],
                "message": {"text": f"marketplace {m.name}: {m.detail} ({m.severity})."},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "known_marketplaces.json"}}}
                ],
                "partialFingerprints": {
                    "ccPluginLock/v1": _fingerprint("marketplace", m.name, m.detail)
                },
                "properties": {"marketplace": m.name, "severity": m.severity},
            }
        )
    return _run(rules, results, rep.warnings + rep.errors)


def verify_hook(rep: Report, fail_on: str) -> dict[str, Any] | None:
    """The SessionStart output: block at or above ``fail_on``, warn below it, nothing if clean."""
    changed = [p for p in rep.plugins if p.status != UNCHANGED]
    if not changed and not rep.marketplaces:
        return None
    parts = []
    for p in changed:
        files = ", ".join(c.path for c in p.changes[:3] if c.severity == p.severity)
        more = "" if len(p.changes) <= 3 else f" and {len(p.changes) - 3} more"
        detail = f": {files}{more}" if files else ""
        parts.append(f"{p.key} {p.status} ({(p.severity or '-').upper()}){detail}")
    for m in rep.marketplaces:
        parts.append(f"marketplace {m.name} {m.status} ({(m.severity or '-').upper()})")
    head = (
        f"cc-plugin-lock: {len(parts)} change(s) since the lock was written: "
        + "; ".join(parts)
        + "."
    )
    tail = (
        " Review with `cc-plugin-lock verify` and `cc-plugin-lock diff <plugin>`; if the change is "
        "expected, accept it with `cc-plugin-lock lock --only <plugin>`."
    )
    if rep.fails(fail_on):
        return block(
            head + " The session was stopped because a change is at or above "
            f"{fail_on.upper()}." + tail
        )
    return warn(head + tail)


def render_verify(rep: Report, fmt: str, fail_on: str = LOW) -> str:
    if fmt == "markdown":
        return verify_markdown(rep)
    if fmt == "json":
        return verify_json(rep)
    if fmt == "sarif":
        return json.dumps(verify_sarif_doc(rep), indent=1) + "\n"
    if fmt == "hook":
        out = verify_hook(rep, fail_on)
        return "" if out is None else json.dumps(out) + "\n"
    return verify_table(rep)


# ---------------------------------------------------------------------- scan

SCAN_RULES: dict[str, tuple[str, str, str]] = {
    rid: (r["severity"], r["title"], f"{r['title']}. {r['recommendation']}")
    for rid, r in RULES.items()
}


def scan_table(res: ScanResult) -> str:
    lines = [
        f"cc-plugin-lock {__version__} scan: {res.files} file(s) in {len(res.plugins)} plugin(s) under {res.root}",
        "",
    ]
    if res.findings:
        rows = [
            (
                f.severity.upper(),
                f.id,
                f"{f.file}:{f.line}" if f.line else f.file,
                f"{f.rule['title']}: {f.evidence}",
            )
            for f in res.findings
        ]
        lines += _table(rows, ("SEVERITY", "ID", "FILE", "FINDING"))
        counts = {s: sum(1 for f in res.findings if f.severity == s) for s in (HIGH, MEDIUM, LOW)}
        lines += [
            "",
            f"{len(res.findings)} finding(s): "
            + ", ".join(f"{counts[s]} {s}" for s in counts if counts[s])
            + ".",
        ]
        lines += ["", "Fixes:"]
        seen: set[str] = set()
        for f in res.findings:
            if f.id not in seen:
                seen.add(f.id)
                lines.append(f"  {f.id}: {f.rule['recommendation']}")
    else:
        lines.append(
            "No findings for the rules in docs/rules.md. This is a heuristic check, not a guarantee."
        )
    for e in res.errors:
        lines.append(f"error: {e}")
    return "\n".join(lines) + "\n"


def scan_sarif_doc(res: ScanResult) -> dict[str, Any]:
    rule_ids = list(SCAN_RULES)
    rules = _rules_block(SCAN_RULES, HELP_URI)
    for r in rules:
        r["properties"]["category"] = RULES[r["id"]]["category"]
    results = []
    for f in res.findings:
        loc: dict[str, Any] = {"artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"}}
        if f.line:
            loc["region"] = {"startLine": f.line}
        results.append(
            {
                "ruleId": f.id,
                "ruleIndex": rule_ids.index(f.id),
                "level": SARIF_LEVELS[f.severity],
                "message": {"text": f"{f.rule['title']}: {f.evidence}"},
                "locations": [{"physicalLocation": loc}],
                "partialFingerprints": {"ccPluginLock/v1": _fingerprint(f.id, f.file, f.evidence)},
                "properties": {"severity": f.severity, "category": f.rule["category"]},
            }
        )
    root = str(res.root.resolve()).replace("\\", "/")
    base = {"%SRCROOT%": {"uri": _uri(root if root.endswith("/") else root + "/")}}
    return _run(rules, results, res.errors, base)


def render_scan(res: ScanResult, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(res.to_dict(), indent=2) + "\n"
    if fmt == "sarif":
        return json.dumps(scan_sarif_doc(res), indent=1) + "\n"
    return scan_table(res)


def scan_fails(res: ScanResult, threshold: str) -> bool:
    return at_least(res.max_severity(), threshold)
