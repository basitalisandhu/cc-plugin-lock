"""Compare a lock with what is installed now."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .classify import CLASSES, HIGH, LOW, MEDIUM, at_least, max_severity, severity_of

UNCHANGED = "unchanged"
CHANGED = "changed"
ADDED = "added"
REMOVED = "removed"


@dataclass
class FileChange:
    path: str
    change: str  # modified, added, removed
    cls: str
    severity: str
    old: str | None
    new: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "change": self.change,
            "class": self.cls,
            "severity": self.severity,
            "old": self.old,
            "new": self.new,
        }


@dataclass
class PluginResult:
    key: str
    status: str
    severity: str | None
    plugin_id: str
    path: str | None
    version_from: str | None = None
    version_to: str | None = None
    commit_from: str | None = None
    commit_to: str | None = None
    changes: list[FileChange] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "id": self.plugin_id,
            "status": self.status,
            "severity": self.severity,
            "path": self.path,
            "version": {"locked": self.version_from, "installed": self.version_to},
            "gitCommitSha": {"locked": self.commit_from, "installed": self.commit_to},
            "classes": self.classes,
            "changes": [c.to_dict() for c in self.changes],
        }


@dataclass
class MarketplaceResult:
    name: str
    status: str
    severity: str | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "severity": self.severity,
            "detail": self.detail,
        }


@dataclass
class Report:
    lock_path: str
    root: str
    plugins: list[PluginResult] = field(default_factory=list)
    marketplaces: list[MarketplaceResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    abs_paths: dict[str, Path] = field(default_factory=dict)

    @property
    def max_severity(self) -> str | None:
        return max_severity(
            [p.severity for p in self.plugins] + [m.severity for m in self.marketplaces]
        )

    def changed(self) -> list[PluginResult]:
        return [p for p in self.plugins if p.status != UNCHANGED]

    def fails(self, threshold: str) -> bool:
        return at_least(self.max_severity, threshold)

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {s: 0 for s in (UNCHANGED, CHANGED, ADDED, REMOVED)}
        for p in self.plugins:
            out[p.status] += 1
        sev: dict[str, int] = {HIGH: 0, MEDIUM: 0, LOW: 0}
        for p in self.plugins:
            if p.severity:
                sev[p.severity] += 1
        for m in self.marketplaces:
            if m.severity:
                sev[m.severity] += 1
        out.update(sev)
        out["marketplaceChanges"] = len(self.marketplaces)
        out["maxSeverity"] = self.max_severity
        out["errors"] = len(self.errors)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "cc-plugin-lock",
            "version": __version__,
            "lock": self.lock_path,
            "root": self.root,
            "summary": self.summary(),
            "plugins": [p.to_dict() for p in self.plugins],
            "marketplaces": [m.to_dict() for m in self.marketplaces],
            "errors": self.errors,
            "warnings": self.warnings,
        }


def _file_changes(old: dict[str, Any], new: dict[str, Any]) -> list[FileChange]:
    changes: list[FileChange] = []
    for rel in sorted(set(old) | set(new)):
        o, n = old.get(rel), new.get(rel)
        same_content = bool(o and n and o.get("sha256") == n.get("sha256"))
        mode_changed = bool(o and n and bool(o.get("executable")) != bool(n.get("executable")))
        if same_content and not mode_changed:
            continue
        cls = (n or o or {}).get("class", "other")
        if o and n and o.get("class") != n.get("class"):
            # A file that moved into a riskier class reports the riskier one.
            cls = max((o.get("class", "other"), cls), key=lambda c: _rank(severity_of(c)))
        kind = (
            "mode" if same_content else ("modified" if o and n else ("added" if n else "removed"))
        )
        changes.append(
            FileChange(
                rel,
                kind,
                cls,
                severity_of(cls),
                o.get("sha256") if o else None,
                n.get("sha256") if n else None,
            )
        )
    return changes


def _rank(sev: str) -> int:
    return {LOW: 1, MEDIUM: 2, HIGH: 3}[sev]


def _classes_of(record: dict[str, Any]) -> list[str]:
    present = {f.get("class", "other") for f in record.get("files", {}).values()}
    return [c for c in CLASSES if c in present]


def compare(
    locked: dict[str, Any],
    current: dict[str, Any],
    *,
    lock_path: str = "",
    root: str = "",
    abs_paths: dict[str, Path] | None = None,
) -> Report:
    """Compare two lock documents: the one on disk and one built from the current install."""
    rep = Report(lock_path=lock_path, root=root, abs_paths=dict(abs_paths or {}))
    old_plugins: dict[str, Any] = locked.get("plugins", {})
    new_plugins: dict[str, Any] = current.get("plugins", {})

    # Match by key first; a key that changed only because the version is in it (several
    # installs of one id) falls back to the plugin id.
    unmatched_new = {k for k in new_plugins if k not in old_plugins}
    pairs: list[tuple[str | None, str | None]] = [
        (k, k) for k in sorted(old_plugins) if k in new_plugins
    ]
    for k in sorted(old_plugins):
        if k in new_plugins:
            continue
        pid = old_plugins[k].get("id", k)
        match = next((n for n in sorted(unmatched_new) if new_plugins[n].get("id") == pid), None)
        if match:
            unmatched_new.discard(match)
        pairs.append((k, match))
    pairs += [(None, k) for k in sorted(unmatched_new)]

    for old_key, new_key in sorted(pairs, key=lambda p: p[0] or p[1] or ""):
        o = old_plugins.get(old_key) if old_key else None
        n = new_plugins.get(new_key) if new_key else None
        key = new_key or old_key or ""
        src = n or o or {}
        res = PluginResult(
            key=key,
            status=UNCHANGED,
            severity=None,
            plugin_id=src.get("id", key),
            path=src.get("path"),
            version_from=o.get("version") if o else None,
            version_to=n.get("version") if n else None,
            commit_from=o.get("gitCommitSha") if o else None,
            commit_to=n.get("gitCommitSha") if n else None,
        )
        if o is None and n is not None:
            res.status = ADDED
            res.classes = _classes_of(n)
            # A new plugin is HIGH when it starts processes (hooks, MCP or LSP servers,
            # monitors, bin/, packages), otherwise MEDIUM: it still changes the model's context.
            res.severity = HIGH if n.get("runtime") else MEDIUM
            res.changes = _file_changes({}, n["files"])
        elif n is None and o is not None:
            res.status = REMOVED
            res.classes = _classes_of(o)
            res.severity = LOW
        elif (
            o is not None
            and n is not None
            and (
                o.get("contentHash") != n.get("contentHash")
                or _file_changes(o["files"], n["files"])
            )
        ):
            res.status = CHANGED
            res.changes = _file_changes(o["files"], n["files"])
            res.classes = [c for c in CLASSES if any(ch.cls == c for ch in res.changes)]
            res.severity = max_severity(ch.severity for ch in res.changes)
        rep.plugins.append(res)

    old_m: dict[str, Any] = locked.get("marketplaces", {})
    new_m: dict[str, Any] = current.get("marketplaces", {})
    for name in sorted(set(old_m) | set(new_m)):
        o, n = old_m.get(name), new_m.get(name)
        if o is None:
            rep.marketplaces.append(
                MarketplaceResult(name, ADDED, MEDIUM, f"new marketplace, source {n.get('source')}")
            )
        elif n is None:
            rep.marketplaces.append(MarketplaceResult(name, REMOVED, LOW, "marketplace removed"))
        elif o.get("source") != n.get("source"):
            rep.marketplaces.append(
                MarketplaceResult(
                    name,
                    CHANGED,
                    HIGH,
                    f"source changed from {o.get('source')} to {n.get('source')}",
                )
            )
        elif o.get("autoUpdate") != n.get("autoUpdate"):
            rep.marketplaces.append(
                MarketplaceResult(
                    name,
                    CHANGED,
                    MEDIUM if n.get("autoUpdate") else LOW,
                    f"autoUpdate changed from {o.get('autoUpdate')} to {n.get('autoUpdate')}",
                )
            )
        elif o.get("catalogHash") != n.get("catalogHash"):
            rep.marketplaces.append(
                MarketplaceResult(name, CHANGED, LOW, "marketplace.json catalog changed")
            )
    return rep
