# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability") rather than a public issue. Include the version, a minimal plugin tree or lock file that reproduces the problem, and what you expected to happen.

You will get an acknowledgement within 7 days and a fix or a mitigation plan within 30 days for confirmed issues. Credit is given in the release notes unless you prefer otherwise.

## Scope

cc-plugin-lock reads Claude Code's plugin directory (`installed_plugins.json`, `known_marketplaces.json`, `marketplace.json` files and the plugin files under `cache/`) and writes only the lock file you name and, with `lock --store`, a content store next to it. It executes nothing it reads, makes no network calls and has no dependencies outside the Python standard library.

Issues of interest:

- a change to a plugin file that `verify` does not report, or reports at a lower severity than [docs/lockfile.md](docs/lockfile.md) says it should;
- two different plugin trees that produce the same `contentHash`;
- a plugin layout that makes `lock` or `verify` read or write outside the plugins root, the given plugin directories, the lock file and its store;
- a lock file that makes `verify` report clean when it should not (for example by confusing the key matching);
- `--format hook` output that Claude Code reads as something other than the decision `verify` intended;
- a plugin folder that makes `scan` crash or hang.

Out of scope: plugin behaviour the lock cannot see by design (remote MCP servers, packages fetched at run time, see "Limits" in the README), and scan rules that miss deliberately obfuscated text. Reports of either are still welcome as ordinary issues.

The content store holds copies of plugin files. If a plugin contains secrets, so does the store; keep `.cc-plugin-lock/` out of version control.
