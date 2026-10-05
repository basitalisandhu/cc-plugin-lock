# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Optional executable metadata for regular files, with a `tracksExecutable` marker preserving legacy locks, and `mode` findings in verification and diff when execute bits change. Content and component hashes remain unchanged.
- `verify --format markdown` for pull request comments and CI job summaries (#7, thanks @kkinsen0314-alt).
- `lock --check` compares the rebuilt lock with the file byte for byte and exits 1 on a difference, without writing the lock or the store (#8, thanks @kkinsen0314-alt).

## [0.1.0] - 2026-10-04

### Added

- `cc-plugin-lock lock`: discovers installed Claude Code plugins from `installed_plugins.json` (or the plugin cache), known marketplaces from `known_marketplaces.json`, and extra `--plugin-dir` directories; hashes every file (SHA-256, CRLF normalised for text, symbolic links by target) into a sorted hash list per plugin and per component class; records marketplace source, catalog entry source, version, git commit and scopes in `cc-plugins.lock.json` (lock file version 1, documented in `docs/lockfile.md`). `--store` keeps a content-addressed copy of every file, `--exclude` leaves paths out, `--only` updates one plugin in an existing lock.
- Fourteen component classes with severities: hooks, MCP, LSP, monitors, `bin/`, manifest and dependencies are high; skills, commands, agents, output styles and other code are medium; documentation and other files are low. Files referenced as `${CLAUDE_PLUGIN_ROOT}/...` by hooks and servers take the class of what starts them.
- `cc-plugin-lock verify`: unchanged, changed, added and removed plugins with per-file changes and severities, marketplace source and auto-update changes; `--format table|json|sarif|hook`, `--fail-on`, `--strict`; exit codes 0, 1 and 2.
- `cc-plugin-lock diff`: unified diff against the stored locked content, or changed paths with old and new hashes.
- `cc-plugin-lock hook`: prints a `SessionStart` settings block (exec form) that runs `verify --strict --format hook`; the hook output stops the session with `continue: false` on changes at or above the threshold and warns with `systemMessage` below it.
- `cc-plugin-lock scan`: static pre-install check of a plugin or marketplace folder with 20 rules (CPL101 to CPL107, CPL201 to CPL206, CPL301 to CPL304, CPL401 to CPL403), table, JSON and SARIF output.
- Example plugins root, CI on Python 3.11 and 3.12, container image `ghcr.io/basitalisandhu/cc-plugin-lock` published on version tags with an SPDX SBOM, a build provenance attestation and a keyless cosign signature, and PyPI trusted publishing (off until the repository variable `PYPI_PUBLISH` is set).

[Unreleased]: https://github.com/basitalisandhu/cc-plugin-lock/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/basitalisandhu/cc-plugin-lock/releases/tag/v0.1.0
