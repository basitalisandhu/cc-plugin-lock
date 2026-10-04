"""Component classes and their severities.

Every file in a plugin belongs to exactly one class. The class decides how loud a change
to that file is: a changed hook or MCP configuration runs new code with your user's
permissions on the next session, a changed skill changes what the model is told, a
changed README changes nothing that runs.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
SEVERITIES: tuple[str, ...] = (HIGH, MEDIUM, LOW)
SEVERITY_RANK: dict[str, int] = {LOW: 1, MEDIUM: 2, HIGH: 3}

# class -> (severity, description). Order is the order reports use.
CLASSES: dict[str, tuple[str, str]] = {
    "hooks": (HIGH, "hook configuration and the scripts hooks run"),
    "mcp": (HIGH, "MCP server configuration, bundles and the files servers start"),
    "lsp": (HIGH, "LSP server configuration and the files servers start"),
    "monitors": (HIGH, "background monitor configuration and scripts"),
    "executables": (HIGH, "files in bin/, which are on the Bash tool's PATH"),
    "manifest": (HIGH, ".claude-plugin/ and the plugin settings.json"),
    "dependencies": (HIGH, "node_modules/, package.json and lockfiles"),
    "skills": (MEDIUM, "skills/ and any directory the manifest adds to it"),
    "commands": (MEDIUM, "commands/ or the manifest's commands"),
    "agents": (MEDIUM, "agents/ or the manifest's agents"),
    "output-styles": (MEDIUM, "output styles, themes and workflows"),
    "code": (MEDIUM, "other source files that a skill or command may run"),
    "docs": (LOW, "documentation, licences and images"),
    "other": (LOW, "anything else"),
}

PLUGIN_ROOT_VAR = re.compile(r"\$\{CLAUDE_PLUGIN_ROOT\}[\"']?/([^\s\"'`;|&<>()$]+)")

CODE_SUFFIXES = frozenset(
    {
        ".py",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".mts",
        ".cts",
        ".rb",
        ".pl",
        ".php",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".go",
        ".rs",
        ".lua",
        ".jar",
        ".wasm",
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".node",
    }
)
DOC_SUFFIXES = frozenset(
    {
        ".md",
        ".markdown",
        ".txt",
        ".rst",
        ".adoc",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".ico",
        ".pdf",
    }
)
DOC_STEMS = ("readme", "license", "licence", "changelog", "notice", "authors", "contributing")
DEPENDENCY_FILES = frozenset(
    {"package.json", "package-lock.json", "npm-shrinkwrap.json", "bun.lock", "bun.lockb"}
)


def severity_of(cls: str) -> str:
    return CLASSES.get(cls, (LOW, ""))[0]


def max_severity(severities: Iterable[str | None]) -> str | None:
    best: str | None = None
    for s in severities:
        if s and (best is None or SEVERITY_RANK[s] > SEVERITY_RANK[best]):
            best = s
    return best


def at_least(severity: str | None, threshold: str) -> bool:
    return severity is not None and SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold]


def _clean(rel: str) -> str | None:
    """Normalise a manifest path ("./x/y", "x/y/") to "x/y"; None when it escapes the root."""
    if not isinstance(rel, str) or not rel or rel.startswith(("/", "~")) or "://" in rel:
        return None
    parts = [p for p in PurePosixPath(rel.replace("\\", "/")).parts if p not in (".", "")]
    if ".." in parts:
        return None
    return "/".join(parts)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def load_manifest(root: Path) -> dict[str, Any]:
    data = load_json(root / ".claude-plugin" / "plugin.json")
    return data if isinstance(data, dict) else {}


def iter_strings(value: Any) -> Iterator[str]:
    """Every string anywhere inside a JSON value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from iter_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from iter_strings(v)


def plugin_root_refs(value: Any) -> set[str]:
    """Paths referenced as ``${CLAUDE_PLUGIN_ROOT}/<path>`` anywhere inside a JSON value."""
    out: set[str] = set()
    for s in iter_strings(value):
        for m in PLUGIN_ROOT_VAR.finditer(s):
            rel = _clean(m.group(1).rstrip("\"'"))
            if rel:
                out.add(rel)
    return out


def mcp_servers(config: Any) -> dict[str, Any]:
    """The server map of an MCP config file: ``{"mcpServers": {...}}`` or a bare map."""
    if not isinstance(config, dict):
        return {}
    inner = config.get("mcpServers")
    if isinstance(inner, dict):
        return inner
    return {k: v for k, v in config.items() if isinstance(v, dict)}


class Classifier:
    """Assigns a component class to every path inside one plugin."""

    def __init__(self, root: Path, manifest: dict[str, Any] | None = None) -> None:
        self.root = root
        self.manifest = load_manifest(root) if manifest is None else manifest
        self.exact: dict[str, str] = {}
        self.prefixes: list[tuple[str, str]] = []
        self._build()

    # ------------------------------------------------------------------ construction
    def _mark(self, rel: str | None, cls: str) -> None:
        if rel and rel not in self.exact:
            self.exact[rel] = cls

    def _prefix(self, rel: str | None, cls: str) -> None:
        if rel is not None:
            self.prefixes.append((rel, cls))

    def _config_refs(self, rel: str, cls: str) -> None:
        """Mark a JSON config file and every file it references through the root variable."""
        self._mark(rel, cls)
        data = load_json(self.root / rel)
        for ref in plugin_root_refs(data):
            self._mark(ref, cls)

    def _inline_refs(self, value: Any, cls: str) -> None:
        for ref in plugin_root_refs(value):
            self._mark(ref, cls)

    def _build(self) -> None:
        m = self.manifest
        # Hook and server configs first: the files they start are the highest-risk code.
        self._config_refs("hooks/hooks.json", "hooks")
        for item in _as_list(m.get("hooks")):
            if isinstance(item, str):
                self._config_refs(_clean(item) or "", "hooks")
            else:
                self._inline_refs(item, "hooks")
        self._config_refs(".mcp.json", "mcp")
        for item in _as_list(m.get("mcpServers")):
            if isinstance(item, str):
                rel = _clean(item)
                if rel and rel.endswith((".mcpb", ".dxt")):
                    self._mark(rel, "mcp")
                elif rel:
                    self._config_refs(rel, "mcp")
            else:
                self._inline_refs(item, "mcp")
        self._config_refs(".lsp.json", "lsp")
        for item in _as_list(m.get("lspServers")):
            if isinstance(item, str):
                self._config_refs(_clean(item) or "", "lsp")
            else:
                self._inline_refs(item, "lsp")
        experimental = m.get("experimental") if isinstance(m.get("experimental"), dict) else {}
        monitors = experimental.get("monitors", m.get("monitors"))
        self._config_refs("monitors/monitors.json", "monitors")
        for item in _as_list(monitors):
            if isinstance(item, str):
                self._config_refs(_clean(item) or "", "monitors")
            else:
                self._inline_refs(item, "monitors")
        self.exact.pop("", None)

        # Directory prefixes, most specific first.
        self._prefix(".claude-plugin", "manifest")
        self._prefix(".mcpb-cache", "mcp")
        self._prefix("hooks", "hooks")
        self._prefix("monitors", "monitors")
        self._prefix("bin", "executables")
        for key, cls in (("commands", "commands"), ("agents", "agents")):
            value = m.get(key)
            if isinstance(value, dict):
                for entry in value.values():
                    if isinstance(entry, dict):
                        self._mark(_clean(entry.get("source", "")), cls)
            else:
                for item in _as_list(value):
                    self._prefix(_clean(item) if isinstance(item, str) else None, cls)
        for item in _as_list(m.get("skills")):
            rel = _clean(item) if isinstance(item, str) else None
            if rel is not None and rel != "":
                self._prefix(rel, "skills")
        for key in ("outputStyles", "workflows"):
            for item in _as_list(m.get(key)):
                self._prefix(_clean(item) if isinstance(item, str) else None, "output-styles")
        for item in _as_list(experimental.get("themes", m.get("themes"))):
            self._prefix(_clean(item) if isinstance(item, str) else None, "output-styles")
        self._prefix("skills", "skills")
        self._prefix("commands", "commands")
        self._prefix("agents", "agents")
        for d in ("output-styles", "themes", "workflows"):
            self._prefix(d, "output-styles")
        # Longest prefix wins.
        self.prefixes.sort(key=lambda p: -len(p[0]))

    # ------------------------------------------------------------------ lookup
    def classify(self, rel: str) -> str:
        if rel in self.exact:
            return self.exact[rel]
        parts = rel.split("/")
        if "node_modules" in parts[:-1] or (len(parts) == 1 and parts[0] in DEPENDENCY_FILES):
            return "dependencies"
        if rel in ("settings.json",):
            return "manifest"
        if rel == "SKILL.md" and "skills" not in self.manifest:
            return "skills"
        for prefix, cls in self.prefixes:
            if prefix and (rel == prefix or rel.startswith(prefix + "/")):
                return cls
        name = parts[-1].lower()
        suffix = PurePosixPath(name).suffix
        if suffix in CODE_SUFFIXES:
            return "code"
        if suffix in DOC_SUFFIXES or name.startswith(DOC_STEMS):
            return "docs"
        return "other"

    def classify_all(self, paths: Iterable[str]) -> dict[str, str]:
        return {p: self.classify(p) for p in paths}
