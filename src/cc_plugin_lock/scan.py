"""Static pre-install checks on a plugin folder.

The rules are heuristics over text: they read hook configs and the scripts hooks start,
MCP and LSP server declarations, the manifest, and the Markdown of skills, commands and
agents. Nothing is executed and nothing is fetched.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from .classify import (
    HIGH,
    LOW,
    MEDIUM,
    SEVERITY_RANK,
    Classifier,
    _as_list,
    _clean,
    load_json,
    load_manifest,
    mcp_servers,
)
from .hashing import walk

HELP_URI = "https://github.com/basitalisandhu/cc-plugin-lock/blob/main/docs/rules.md"

RULES: dict[str, dict[str, str]] = {
    "CPL101": {
        "severity": HIGH,
        "category": "hooks",
        "title": "Download piped into a shell",
        "recommendation": "Ship the script inside the plugin so the lock covers it, or pin and verify the download by hash before running it.",
    },
    "CPL102": {
        "severity": MEDIUM,
        "category": "hooks",
        "title": "Dynamic code evaluation",
        "recommendation": "Replace eval or exec of built strings with direct calls; review where the evaluated text comes from.",
    },
    "CPL103": {
        "severity": HIGH,
        "category": "hooks",
        "title": "Reads a credential store",
        "recommendation": "A plugin should not read ~/.aws, ~/.ssh, ~/.netrc or similar. Remove the read or do not install the plugin.",
    },
    "CPL104": {
        "severity": HIGH,
        "category": "hooks",
        "title": "Dumps the environment",
        "recommendation": "Read only the variables the script needs by name; never serialise or print the whole environment.",
    },
    "CPL105": {
        "severity": MEDIUM,
        "category": "hooks",
        "title": "Writes outside the plugin",
        "recommendation": "Keep state in ${CLAUDE_PLUGIN_DATA}; a hook that writes elsewhere in your home directory changes your machine beyond the plugin.",
    },
    "CPL106": {
        "severity": MEDIUM,
        "category": "hooks",
        "title": "Network call from a hook or script",
        "recommendation": "Check where the request goes and what it sends; hooks receive tool inputs and outputs, which can include file contents.",
    },
    "CPL107": {
        "severity": HIGH,
        "category": "hooks",
        "title": "Writes to shell start-up files, agent settings or SSH keys",
        "recommendation": "A plugin that edits ~/.zshrc, ~/.bashrc, ~/.claude/, authorized_keys, crontab or launch agents persists beyond the plugin. Remove the write or do not install the plugin.",
    },
    "CPL201": {
        "severity": HIGH,
        "category": "mcp",
        "title": "MCP server runs an unpinned npx package",
        "recommendation": "Pin the package to an exact version (name@1.2.3) so the code that runs cannot change after the lock is written.",
    },
    "CPL202": {
        "severity": HIGH,
        "category": "mcp",
        "title": "MCP server runs an unpinned uvx or pipx package",
        "recommendation": "Pin the package to an exact version (name==1.2.3 or name@1.2.3).",
    },
    "CPL203": {
        "severity": MEDIUM,
        "category": "mcp",
        "title": "Remote MCP server",
        "recommendation": "A remote server's behaviour is not in the plugin's files, so the lock cannot cover it. Use https and confirm you trust the host.",
    },
    "CPL204": {
        "severity": MEDIUM,
        "category": "mcp",
        "title": "MCP server runs a container image not pinned by digest",
        "recommendation": "Reference the image as name@sha256:<digest>.",
    },
    "CPL205": {
        "severity": MEDIUM,
        "category": "mcp",
        "title": "MCP bundle downloaded from a URL",
        "recommendation": "Ship the .mcpb or .dxt bundle inside the plugin so its content is hashed.",
    },
    "CPL206": {
        "severity": HIGH,
        "category": "mcp",
        "title": "Remote MCP server over an unencrypted connection",
        "recommendation": "Use https or wss; http:// and ws:// to a non-loopback host expose requests and tokens on the network.",
    },
    "CPL301": {
        "severity": HIGH,
        "category": "skills",
        "title": "Instruction-override text",
        "recommendation": "Remove text that tells the model to ignore earlier instructions; legitimate skills do not need it.",
    },
    "CPL302": {
        "severity": HIGH,
        "category": "skills",
        "title": "Tells the model to hide something from the user",
        "recommendation": "Remove concealment instructions; a skill should not ask the model to keep actions from the user.",
    },
    "CPL303": {
        "severity": HIGH,
        "category": "skills",
        "title": "Possible exfiltration URL",
        "recommendation": "Check the URL: request-capture and paste hosts, and URLs that interpolate variables into the query, are common exfiltration channels.",
    },
    "CPL304": {
        "severity": MEDIUM,
        "category": "skills",
        "title": "Invisible or bidirectional control characters",
        "recommendation": "Remove zero-width, bidirectional and tag characters; they hide text from a human reviewer.",
    },
    "CPL401": {
        "severity": HIGH,
        "category": "manifest",
        "title": "Component path escapes the plugin directory",
        "recommendation": "Component paths must start with ./ and stay inside the plugin root.",
    },
    "CPL402": {
        "severity": HIGH,
        "category": "manifest",
        "title": "Symbolic link points outside the plugin",
        "recommendation": "Replace the link with the file itself so the lock hashes its content.",
    },
    "CPL403": {
        "severity": LOW,
        "category": "manifest",
        "title": "Plugin adds executables to the Bash PATH",
        "recommendation": "Files in bin/ run as bare commands while the plugin is enabled; review each one.",
    },
}

FORMATS = ("table", "json", "sarif")

# ------------------------------------------------------------------ patterns

PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:ba|z|da|k|fi)?sh\b"
    r"|\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?\$?<?\(\s*(?:curl|wget)\b"
    r"|\bbase64\s+(?:-d|--decode|-D)\b[^\n|]*\|\s*(?:ba|z)?sh\b"
    r"|\b(?:iex|Invoke-Expression)\b[^\n]*\b(?:irm|iwr|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b"
    r"|\b(?:irm|iwr|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)\b",
    re.IGNORECASE,
)
DYNAMIC_EVAL = re.compile(
    r"(?:^|[;&|(`]\s*)eval\s+[\"'$`(]|(?<![\w.\"'`])eval\s*\(\s*(?![\"')])|(?<![\w.\"'`])exec\s*\(\s*(?![\"')])"
    r"|\bnew\s+Function\s*\(|\bvm\.runInNewContext\b"
)
CREDENTIAL_STORE = re.compile(
    r"(?<![\w-])(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%)?/?\.(?:aws|ssh|gnupg|kube|azure)(?=/|\b)"
    r"|\.netrc\b|\.git-credentials\b|\.docker/config\.json|\.config/gcloud\b"
    r"|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\bkeychain\b\s+(?:dump|find-generic-password|find-internet-password)"
    r"|\bsecurity\s+(?:dump-keychain|find-generic-password|find-internet-password)\b",
    re.IGNORECASE,
)
ENV_DUMP = re.compile(
    r"(?:^|;|&&|\|\||\$\()\s*(?:printenv|env|export\s+-p|declare\s+-x)\s*(?:$|>|\|(?!\|)\s*[a-z]|;|&|\))"
    r"|\b(?:json\.dumps|str|repr|print|pprint)\(\s*(?:dict\()?\s*os\.environ\s*\)?\s*[),]"
    r"|\bJSON\.stringify\(\s*process\.env\s*\)|\bObject\.(?:entries|keys|values)\(\s*process\.env\s*\)"
    r"|\bGet-ChildItem\s+env:|\bgci\s+env:|\bdir\s+env:",
    re.IGNORECASE,
)
WRITE_TARGET = re.compile(
    r"(?:(?:^|(?<=\s))\d?>>?|\btee\s+(?:-a\s+)?|\b(?:cp|mv|install|ln|rsync)\s+(?:-{1,2}[\w-]+\s+)*\S+\s+)"
    r"\s*[\"']?(?P<target>(?:~|\$HOME|\$\{HOME\}|/)[^\s\"';|&)]*)"
)
PY_WRITE = re.compile(
    r"open\(\s*(?:os\.path\.expanduser\(\s*)?[\"'](?P<target>(?:~|/)[^\"']+)[\"']\)?\s*,\s*[\"'][wax]"
)
SAFE_WRITE_PREFIXES = ("/dev/null", "/dev/stdout", "/dev/stderr", "/tmp/", "/tmp", "/dev/fd/")
SENSITIVE_TARGET = re.compile(
    r"\.(?:bashrc|bash_profile|zshrc|zprofile|zshenv|profile|config/fish)\b|\.claude/|\.mcp\.json"
    r"|authorized_keys|known_hosts|crontab|LaunchAgents|LaunchDaemons|\.config/autostart"
    r"|/etc/|\.gitconfig|\.npmrc|\.pypirc"
)
NETWORK = re.compile(
    r"(?:^|[\s;&|(`\"'])(?:curl|wget|nc|ncat|socat|telnet|scp|ftp)\s"
    r"|\brequests\.(?:get|post|put|patch|request)\(|\burllib\.request\b|\bhttp\.client\b|\bhttpx\."
    r"|\bfetch\(\s*[\"'`]https?:|\baxios\b|\bhttps?\.request\(|\bInvoke-WebRequest\b|\bInvoke-RestMethod\b"
    r"|/dev/tcp/",
    re.IGNORECASE,
)

INSTRUCTION_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?"
    r"\b(?:previous|prior|above|earlier|preceding|all|any|your|system|safety|other)\b[^.\n]{0,25}?"
    r"\b(?:instructions?|prompts?|rules|guidelines|directives|guardrails|polic(?:y|ies))\b",
    re.IGNORECASE,
)
CONCEALMENT = re.compile(
    r"\b(?:do\s+not|don't|dont|never)\s+(?:tell|inform|notify|mention|reveal|show|disclose|alert)\b"
    r"[^.\n]{0,40}?\b(?:the\s+)?user\b"
    r"|\b(?:hide|conceal|keep)\b[^.\n]{0,30}?\b(?:from|secret\s+from)\s+(?:the\s+)?user\b",
    re.IGNORECASE,
)
URL = re.compile(r"https?://[^\s<>\"'`)\]]+", re.IGNORECASE)
CAPTURE_HOSTS = (
    "webhook.site",
    "requestbin",
    "pipedream.net",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "pastebin.com",
    "transfer.sh",
    "interact.sh",
    "oast.",
    "burpcollaborator",
    "requestcatcher.com",
    "hookbin.com",
    "beeceptor.com",
)
CAPTURE_PATHS = ("discord.com/api/webhooks", "discordapp.com/api/webhooks", "hooks.slack.com/")
TEMPLATED_QUERY = re.compile(r"[?&][^\s=&#]*=[^\s&#]*(?:\$\{|\$\(|\{\{|%24%7B|\$[A-Z_]{3,})")
HIDDEN_CHARS = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)

CODE_SUFFIXES_FOR_SCAN = frozenset(
    {
        ".sh",
        ".bash",
        ".zsh",
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".rb",
        ".pl",
        ".ps1",
        ".bat",
        ".cmd",
        "",
    }
)
MARKDOWN_CLASSES = frozenset({"skills", "commands", "agents", "output-styles"})
SCRIPT_CLASSES = frozenset({"hooks", "monitors", "executables", "mcp", "lsp", "code"})
MAX_FILE_BYTES = 2_000_000


@dataclass(frozen=True)
class Finding:
    id: str
    file: str
    line: int
    evidence: str

    @property
    def rule(self) -> dict[str, str]:
        return RULES[self.id]

    @property
    def severity(self) -> str:
        return self.rule["severity"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "category": self.rule["category"],
            "title": self.rule["title"],
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "recommendation": self.rule["recommendation"],
        }


def _evidence(text: str) -> str:
    text = HIDDEN_CHARS.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", text.strip())
    return text if len(text) <= 160 else text[:157] + "..."


def _line_of(text: str, needle: str) -> int:
    """1-based line of the first occurrence of ``needle`` (JSON-escaped form tried too)."""
    for candidate in (needle, json.dumps(needle)[1:-1]):
        idx = text.find(candidate) if candidate else -1
        if idx >= 0:
            return text.count("\n", 0, idx) + 1
    return 1


class Scanner:
    """Runs every rule over one plugin directory."""

    def __init__(self, root: Path, label: str = "") -> None:
        self.root = root
        self.label = label
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.files: list[str] = []
        self._seen: set[tuple[str, str, int]] = set()

    def add(self, rid: str, file: str, line: int, evidence: str) -> None:
        rel = f"{self.label}{file}"
        key = (rid, rel, line)
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(Finding(rid, rel, line, _evidence(evidence)))

    def _read(self, rel: str) -> str | None:
        path = self.root / rel
        try:
            if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                return None
            data = path.read_bytes()
        except OSError as exc:
            self.errors.append(f"{self.label}{rel}: {exc.strerror or exc}")
            return None
        if b"\0" in data[:8192]:
            return None
        return data.decode("utf-8", "replace")

    # ------------------------------------------------------------------ entry point
    def run(self) -> Scanner:
        try:
            self.files = walk(self.root)
        except Exception as exc:  # HashError, OSError
            self.errors.append(str(exc))
            return self
        manifest = load_manifest(self.root)
        classifier = Classifier(self.root, manifest)
        classes = classifier.classify_all(self.files)
        self._manifest_rules(manifest)
        self._symlinks()
        hook_configs = ["hooks/hooks.json"] + [
            r for r, c in classifier.exact.items() if c == "hooks" and r.endswith(".json")
        ]
        for rel in sorted(set(hook_configs)):
            if rel in self.files:
                self._hook_config(rel)
        if isinstance(manifest.get("hooks"), (dict, list)):
            for item in _as_list(manifest["hooks"]):
                if isinstance(item, dict):
                    self._command_strings(".claude-plugin/plugin.json", item)
        self._mcp(manifest, classifier)
        for rel in self.files:
            cls = classes[rel]
            suffix = PurePosixPath(rel).suffix.lower()
            if cls in MARKDOWN_CLASSES and suffix in (".md", ".markdown", ".mdx", ".txt"):
                text = self._read(rel)
                if text is not None:
                    self._markdown(rel, text)
            elif cls in SCRIPT_CLASSES and (suffix in CODE_SUFFIXES_FOR_SCAN or cls == "hooks"):
                if suffix == ".json":
                    continue
                text = self._read(rel)
                if text is not None:
                    self._script(rel, text)
            elif cls in MARKDOWN_CLASSES and suffix in CODE_SUFFIXES_FOR_SCAN:
                text = self._read(rel)
                if text is not None:
                    self._script(rel, text)
        if any(f == "bin" or f.startswith("bin/") for f in self.files):
            self.add("CPL403", "bin/", 0, "bin/ directory present")
        self.findings.sort(key=lambda f: (f.file, f.line, f.id))
        return self

    # ------------------------------------------------------------------ rule groups
    def _script_line(self, rel: str, line_no: int, line: str) -> None:
        if PIPE_TO_SHELL.search(line):
            self.add("CPL101", rel, line_no, line)
        elif NETWORK.search(line):
            self.add("CPL106", rel, line_no, line)
        if DYNAMIC_EVAL.search(line):
            self.add("CPL102", rel, line_no, line)
        if CREDENTIAL_STORE.search(line):
            self.add("CPL103", rel, line_no, line)
        if ENV_DUMP.search(line):
            self.add("CPL104", rel, line_no, line)
        for rx in (WRITE_TARGET, PY_WRITE):
            for m in rx.finditer(line):
                target = m.group("target")
                if "CLAUDE_PLUGIN_ROOT" in target or "CLAUDE_PLUGIN_DATA" in target:
                    continue
                if target.startswith(SAFE_WRITE_PREFIXES) or target in ("/", ""):
                    continue
                rid = "CPL107" if SENSITIVE_TARGET.search(target) else "CPL105"
                self.add(rid, rel, line_no, line)

    def _script(self, rel: str, text: str) -> None:
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith(("//", "--", ";;")) or (
                stripped.startswith("#") and not stripped.startswith("#!")
            ):
                continue  # comments do not run
            self._script_line(rel, i, line)

    def _command_strings(self, rel: str, value: Any, text: str | None = None) -> None:
        """Scan every ``command``/``args`` string of a hook or monitor config."""
        text = text if text is not None else (self._read(rel) or "")

        def visit(node: Any) -> None:
            if isinstance(node, dict):
                parts: list[str] = []
                if isinstance(node.get("command"), str):
                    parts.append(node["command"])
                if isinstance(node.get("args"), list):
                    parts += [a for a in node["args"] if isinstance(a, str)]
                if parts:
                    joined = " ".join(parts)
                    self._script_line(rel, _line_of(text, parts[0]), joined)
                for v in node.values():
                    visit(v)
            elif isinstance(node, list):
                for v in node:
                    visit(v)

        visit(value)

    def _hook_config(self, rel: str) -> None:
        text = self._read(rel)
        if text is None:
            return
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            self.errors.append(f"{self.label}{rel}: invalid JSON: {exc.msg} at line {exc.lineno}")
            return
        self._command_strings(rel, data, text)

    def _manifest_rules(self, manifest: dict[str, Any]) -> None:
        rel = ".claude-plugin/plugin.json"
        text = self._read(rel) if rel in self.files else ""
        keys = (
            "skills",
            "commands",
            "agents",
            "hooks",
            "mcpServers",
            "lspServers",
            "outputStyles",
            "workflows",
            "themes",
            "monitors",
        )
        experimental = (
            manifest.get("experimental") if isinstance(manifest.get("experimental"), dict) else {}
        )
        values: list[Any] = [manifest.get(k) for k in keys]
        values += [experimental.get("themes"), experimental.get("monitors")]
        for value in values:
            items: list[str] = []
            for item in _as_list(value):
                if isinstance(item, str):
                    items.append(item)
                elif isinstance(item, dict):
                    items += [
                        v["source"]
                        for v in item.values()
                        if isinstance(v, dict) and isinstance(v.get("source"), str)
                    ]
            for item in items:
                if item.startswith(("https://", "http://")):
                    if item.lower().endswith((".mcpb", ".dxt")):
                        self.add("CPL205", rel, _line_of(text or "", item), item)
                    continue
                if item in (".", "./"):
                    continue
                if _clean(item) is None:
                    self.add("CPL401", rel, _line_of(text or "", item), item)

    def _symlinks(self) -> None:
        root = self.root.resolve()
        for rel in self.files:
            p = self.root / rel
            if p.is_symlink():
                target = os.readlink(p)
                resolved = (p.parent / target).resolve()
                if resolved != root and root not in resolved.parents:
                    self.add("CPL402", rel, 0, f"{rel} -> {target}")

    def _mcp(self, manifest: dict[str, Any], classifier: Classifier) -> None:
        configs: list[tuple[str, Any]] = []
        for rel in [
            ".mcp.json",
            *sorted(
                r
                for r, c in classifier.exact.items()
                if c == "mcp" and r.endswith(".json") and r != ".mcp.json"
            ),
        ]:
            if rel in self.files:
                text = self._read(rel)
                if text is None:
                    continue
                try:
                    configs.append((rel, mcp_servers(json.loads(text))))
                except json.JSONDecodeError as exc:
                    self.errors.append(
                        f"{self.label}{rel}: invalid JSON: {exc.msg} at line {exc.lineno}"
                    )
        for item in _as_list(manifest.get("mcpServers")):
            if isinstance(item, dict):
                configs.append((".claude-plugin/plugin.json", mcp_servers({"mcpServers": item})))
        for rel, servers in configs:
            text = self._read(rel) or ""
            for name in sorted(servers):
                server = servers[name]
                if isinstance(server, dict):
                    self._mcp_server(rel, text, name, server)

    def _mcp_server(self, rel: str, text: str, name: str, server: dict[str, Any]) -> None:
        line = _line_of(text, f'"{name}"') if text else 1
        command = server.get("command") if isinstance(server.get("command"), str) else ""
        args = (
            [a for a in server.get("args", []) if isinstance(a, str)]
            if isinstance(server.get("args"), list)
            else []
        )
        words = command.split() + args if command else args
        exe = PurePosixPath(words[0]).name.lower() if words else ""
        exe = exe[:-4] if exe.endswith((".cmd", ".exe")) else exe
        rest = words[1:]
        if exe in ("npx", "bunx", "pnpx") or (exe in ("pnpm", "yarn") and rest[:1] == ["dlx"]):
            if exe in ("pnpm", "yarn"):
                rest = rest[1:]
            pkg = _first_package(rest, value_opts=("-p", "--package", "--registry", "--cache"))
            if pkg is not None and not _npm_pinned(pkg):
                auto = any(a in ("-y", "--yes") for a in rest)
                note = " (installs without asking because of -y)" if auto else ""
                self.add("CPL201", rel, line, f"{name}: {' '.join(words)}{note}")
        elif exe in ("uvx", "pipx") or (exe == "uv" and rest[:2] == ["tool", "run"]):
            if exe == "uv":
                rest = rest[2:]
            if exe == "pipx":
                rest = [] if rest[:1] != ["run"] else rest[1:]
            spec = None
            if "--from" in rest and rest.index("--from") + 1 < len(rest):
                spec = rest[rest.index("--from") + 1]
            else:
                spec = _first_package(
                    rest, value_opts=("--with", "--python", "-p", "--index", "--spec")
                )
            if spec is not None and not _py_pinned(spec):
                self.add("CPL202", rel, line, f"{name}: {' '.join(words)}")
        elif exe in ("docker", "podman") and "run" in rest:
            image = _first_package(
                rest[rest.index("run") + 1 :],
                value_opts=(
                    "-e",
                    "--env",
                    "-v",
                    "--volume",
                    "--name",
                    "-p",
                    "--publish",
                    "--network",
                    "--mount",
                    "-w",
                    "--workdir",
                    "-u",
                    "--user",
                    "--entrypoint",
                    "--env-file",
                    "--platform",
                    "-l",
                    "--label",
                    "--cpus",
                    "--memory",
                    "-m",
                ),
            )
            if image is not None and "@sha256:" not in image:
                self.add("CPL204", rel, line, f"{name}: {' '.join(words)}")
        url = server.get("url") if isinstance(server.get("url"), str) else None
        stype = str(server.get("type", "")).lower()
        if url or stype in ("http", "sse", "ws", "streamable-http"):
            if url and _insecure_remote(url):
                self.add("CPL206", rel, line, f"{name}: {url}")
            else:
                self.add("CPL203", rel, line, f"{name}: {url or stype}")

    def _markdown(self, rel: str, text: str) -> None:
        for i, line in enumerate(text.splitlines(), 1):
            m = INSTRUCTION_OVERRIDE.search(line)
            if m and not _quoted(line, m.start()):
                self.add("CPL301", rel, i, line)
            if CONCEALMENT.search(line):
                self.add("CPL302", rel, i, line)
            for m in URL.finditer(line):
                url = m.group(0)
                low = url.lower()
                host = (urlparse(url).hostname or "").lower()
                if (
                    any(h in host for h in CAPTURE_HOSTS)
                    or any(p in low for p in CAPTURE_PATHS)
                    or TEMPLATED_QUERY.search(url)
                ):
                    self.add("CPL303", rel, i, line)
                    break
            if HIDDEN_CHARS.search(line):
                self.add("CPL304", rel, i, line)
            if PIPE_TO_SHELL.search(line):
                self.add("CPL101", rel, i, line)
            if CREDENTIAL_STORE.search(line):
                self.add("CPL103", rel, i, line)


QUOTES = "\"'`\u201c\u2018"


def _quoted(line: str, start: int) -> bool:
    """True when a match starts right after an opening quote: an example, not an instruction."""
    return start > 0 and line[start - 1] in QUOTES


def _first_package(args: list[str], value_opts: tuple[str, ...]) -> str | None:
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in value_opts:
            skip = True
            continue
        if a.startswith("-"):
            continue
        return a
    return None


NPM_EXACT = re.compile(r"^(?:@[^/@\s]+/)?[^@\s]+@v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def _npm_pinned(spec: str) -> bool:
    if spec.startswith(("./", "../", "/", "${", "file:")):
        return True  # a local path is inside the plugin and covered by the lock
    return bool(NPM_EXACT.match(spec))


PY_EXACT = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]+\])?(?:==|@)v?\d+(?:\.\d+)*(?:[-+.]?[0-9A-Za-z.]+)?$"
)


def _py_pinned(spec: str) -> bool:
    if spec.startswith(("./", "../", "/", "${", "file:")):
        return True
    return bool(PY_EXACT.match(spec))


def _insecure_remote(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "ws"):
        return False
    host = (parsed.hostname or "").lower()
    if host in ("localhost",) or host.endswith(".localhost"):
        return False
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return True


def is_marketplace(root: Path) -> bool:
    return (root / ".claude-plugin" / "marketplace.json").is_file() and not (
        root / ".claude-plugin" / "plugin.json"
    ).is_file()


def marketplace_plugin_dirs(root: Path) -> list[str]:
    """Relative-path plugin sources listed in a marketplace.json."""
    data = load_json(root / ".claude-plugin" / "marketplace.json")
    out: list[str] = []
    if isinstance(data, dict):
        base = ""
        meta = data.get("metadata")
        if isinstance(meta, dict) and isinstance(meta.get("pluginRoot"), str):
            base = _clean(meta["pluginRoot"]) or ""
        for e in data.get("plugins", []) if isinstance(data.get("plugins"), list) else []:
            if isinstance(e, dict) and isinstance(e.get("source"), str):
                src = e["source"]
                if not src.startswith("./") and base:
                    src = f"{base}/{src}"
                rel = _clean(src)
                if rel is not None:
                    out.append(rel)
    return sorted(set(out))


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding]
    errors: list[str]
    files: int
    plugins: list[str]

    def max_severity(self) -> str | None:
        best = None
        for f in self.findings:
            if best is None or SEVERITY_RANK[f.severity] > SEVERITY_RANK[best]:
                best = f.severity
        return best

    def to_dict(self) -> dict[str, Any]:
        from . import __version__

        counts = {s: sum(1 for f in self.findings if f.severity == s) for s in (HIGH, MEDIUM, LOW)}
        return {
            "tool": "cc-plugin-lock",
            "version": __version__,
            "root": str(self.root),
            "plugins": self.plugins,
            "filesScanned": self.files,
            "summary": {"total": len(self.findings), **counts, "maxSeverity": self.max_severity()},
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


def scan(root: Path) -> ScanResult:
    """Scan a plugin directory, or every relative-path plugin of a marketplace directory."""
    if not root.is_dir():
        return ScanResult(root, [], [f"not a directory: {root}"], 0, [])
    targets = marketplace_plugin_dirs(root) if is_marketplace(root) else [""]
    findings: list[Finding] = []
    errors: list[str] = []
    files = 0
    for rel in targets:
        s = Scanner(root / rel if rel else root, label=f"{rel}/" if rel else "").run()
        findings += s.findings
        errors += s.errors
        files += len(s.files)
    findings.sort(key=lambda f: (f.file, f.line, f.id))
    return ScanResult(root, findings, errors, files, [t or "." for t in targets])


__all__ = ["RULES", "Finding", "ScanResult", "Scanner", "scan"]
