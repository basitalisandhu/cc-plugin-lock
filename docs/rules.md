# Scan rules

`cc-plugin-lock scan <dir>` reads a plugin folder (or every relative-path plugin of a marketplace folder) and reports text that matches the rules below, with the file and line. Nothing is executed and nothing is fetched. The rules are regular expressions over text: they find the obvious cases quickly and they will miss a determined author who obfuscates, so treat a clean scan as "nothing obvious", not as "safe".

Exit code 1 when any finding is at or above `--fail-on` (default `medium`), 0 otherwise, 2 when the folder cannot be read.

Script rules skip comment lines (starting with `#` other than a shebang, `//`, `--` or `;;`), since comments do not run. Text rules skip an instruction-override phrase that starts right after an opening quote, which is how defensive skills quote an attack as an example; an author can exploit that, so read quoted phrases yourself.

Which files each group reads:

- Hook rules (CPL101 to CPL107): every `command` and `args` string in `hooks/hooks.json` and in hook files or inline hooks the manifest declares, and every line of the scripts those hooks reference, of files under `hooks/`, `bin/` and `monitors/`, of files MCP or LSP servers start, and of other source files.
- MCP rules (CPL2xx): `.mcp.json`, files named by the manifest's `mcpServers`, and inline `mcpServers` in `plugin.json`.
- Text rules (CPL3xx): Markdown in `skills/`, `commands/`, `agents/` and output styles, plus a root `SKILL.md`.
- Manifest rules (CPL4xx): component paths in `plugin.json`, symbolic links, and `bin/`.

This overlaps on purpose with [agent-config-audit](https://github.com/basitalisandhu/agent-config-audit), which audits a project's whole agent configuration (settings permissions, secrets in `.mcp.json`, `CLAUDE.md`, `AGENTS.md`, Cursor rules). `scan` is the narrower pre-install check for one plugin; run agent-config-audit for the project around it.

## CPL101

Download piped into a shell (high). `curl ... | sh`, `wget ... | bash`, `bash <(curl ...)`, `base64 -d ... | sh`, and the PowerShell `iex (irm ...)` forms. The downloaded code is not in the plugin, so the lock cannot cover it, and it can change on every run. Also checked in skill text, since a skill can tell the model to run it.

## CPL102

Dynamic code evaluation (medium). Shell `eval` of a built string, Python `eval(` or `exec(` of a non-literal, JavaScript `new Function(` and `vm.runInNewContext`.

## CPL103

Reads a credential store (high). `~/.aws`, `~/.ssh`, `~/.gnupg`, `~/.kube`, `~/.azure`, `~/.netrc`, `~/.git-credentials`, `~/.docker/config.json`, `~/.config/gcloud`, SSH private key file names, and macOS keychain dump commands. Also checked in skill text.

## CPL104

Dumps the environment (high). Bare `printenv` or `env` as a command, `export -p`, `declare -x`, Python `os.environ` passed whole to `print`, `json.dumps`, `str` or `repr`, JavaScript `JSON.stringify(process.env)` or `Object.entries(process.env)`, PowerShell `Get-ChildItem env:`. Environment variables commonly hold tokens.

## CPL105

Writes outside the plugin (medium). Redirection, `tee`, `cp`, `mv`, `install`, `ln` or `rsync` to a path under `~`, `$HOME` or `/`, and Python `open("~/...", "w")`. Writes to `${CLAUDE_PLUGIN_ROOT}`, `${CLAUDE_PLUGIN_DATA}`, `/tmp` and `/dev/null` are not reported. Plugins should keep state in `${CLAUDE_PLUGIN_DATA}`. Writes to the sensitive targets in CPL107 are reported as CPL107 instead.

## CPL106

Network call from a hook or script (medium). `curl`, `wget`, `nc`, `socat`, `scp`, Python `requests`, `urllib.request`, `http.client`, `httpx`, JavaScript `fetch("http...")`, `axios`, `https.request`, PowerShell web cmdlets and `/dev/tcp/`. Hooks receive tool inputs and outputs on stdin, which can include file contents, so check where each request goes. Not reported on a line that already has CPL101.

## CPL107

Writes to shell start-up files, agent settings or SSH keys (high). The CPL105 patterns with a target such as `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.claude/`, `.mcp.json`, `authorized_keys`, `known_hosts`, `crontab`, `LaunchAgents`, `~/.config/autostart`, `/etc/`, `~/.gitconfig`, `~/.npmrc` or `~/.pypirc`. These persist after the plugin is disabled.

## CPL201

MCP server runs an unpinned npx package (high). `npx`, `bunx`, `pnpx`, `pnpm dlx` or `yarn dlx` with a package that is not pinned to an exact version (`name@1.2.3`); `@latest` and ranges count as unpinned. The evidence notes when `-y` makes npx install without asking. A local path inside the plugin is not reported.

## CPL202

MCP server runs an unpinned uvx or pipx package (high). `uvx`, `uv tool run` or `pipx run` with a package (or `--from` spec) without `==1.2.3` or `@1.2.3`.

## CPL203

Remote MCP server (medium). A server with a `url` or type `http`, `sse`, `ws` or `streamable-http`. What a remote server does is not in the plugin's files, so no lock can cover it.

## CPL204

MCP server runs a container image not pinned by digest (medium). `docker run` or `podman run` with an image that has no `@sha256:` digest.

## CPL205

MCP bundle downloaded from a URL (medium). An `https://` `.mcpb` or `.dxt` in the manifest's `mcpServers`; Claude Code downloads it into `.mcpb-cache/`, outside what you reviewed.

## CPL206

Remote MCP server over an unencrypted connection (high). An `http://` or `ws://` URL to a host that is not loopback.

## CPL301

Instruction-override text (high). Phrases such as "ignore previous instructions" or "disregard your rules" in a skill, command or agent, unless the phrase starts right after an opening quote.

## CPL302

Tells the model to hide something from the user (high). "Do not tell the user", "never mention ... to the user", "hide this from the user" and close variants.

## CPL303

Possible exfiltration URL (high). URLs on request-capture and paste hosts (for example webhook.site, requestbin, pipedream, ngrok, pastebin, transfer.sh, interact.sh, Discord and Slack webhook paths), and URLs whose query interpolates a variable (`${...}`, `$(...)`, `{{...}}`, `$NAME`).

## CPL304

Invisible or bidirectional control characters (medium). Zero-width characters, bidirectional overrides and isolates, the byte-order mark inside text, and Unicode tag characters. They let text that a reviewer cannot see reach the model. The evidence shows each one as `<U+XXXX>`.

## CPL401

Component path escapes the plugin directory (high). A manifest component path that is absolute, starts with `~`, or contains `..`. Claude Code refuses these at load time; a plugin that ships one is either broken or probing.

## CPL402

Symbolic link points outside the plugin (high). The lock hashes the link target string, not the file it points to, so a link out of the plugin is content the lock does not cover.

## CPL403

Plugin adds executables to the Bash PATH (low). Files in `bin/` run as bare commands while the plugin is enabled.
