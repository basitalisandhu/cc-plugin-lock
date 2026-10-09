# The lock file: `cc-plugins.lock.json`

`cc-plugin-lock lock` writes one JSON file that records, for every installed Claude Code plugin, a hash of every file it contains. `cc-plugin-lock verify` rebuilds the same document from what is on disk now and compares the two. This page is the schema and the hashing algorithm, so another tool can read or reproduce a lock.

Schema version: `"lockfileVersion": 1`. A reader that sees any other value must refuse the file; `cc-plugin-lock` exits 2 and asks you to re-create it.

## Where the inputs come from

Claude Code keeps its plugin state under one plugins root, `~/.claude/plugins` unless `CLAUDE_CODE_PLUGIN_CACHE_DIR` is set ([plugin loading reference](https://code.claude.com/docs/en/plugins/loading#find-plugins-on-disk)). `cc-plugin-lock` reads, and never writes:

| Path under the root | Used for |
| --- | --- |
| `installed_plugins.json` | Each install of `<name>@<marketplace>`: `scope`, `projectPath`, `installPath`, `version`, `gitCommitSha` |
| `known_marketplaces.json` | Each marketplace: `source`, `installLocation`, `autoUpdate` |
| `marketplaces/<name>/.claude-plugin/marketplace.json` | The catalog hash and each plugin entry's `source` |
| `cache/<marketplace>/<plugin>/<version>/` | The plugin files that are hashed |

When `installed_plugins.json` is missing, every `cache/<marketplace>/<plugin>/<version>/` directory without an `.orphaned_at` marker is locked instead. When an `installPath` does not exist (a lock taken inside a container, or a copied tree), `cache/<marketplace>/<plugin>/<version>/` under the given root is tried. A relative `installPath` is resolved against the root. `--plugin-dir DIR` adds a plugin directory that is not installed from a marketplace; it is recorded as `<name>@inline`.

Timestamps (`installedAt`, `lastUpdated`) are not recorded, so two locks of an unchanged install are byte-identical.

## Hashing

1. Walk the plugin directory without following symbolic links. Skip `.git/`, `__pycache__/`, `.orphaned_at`, `.DS_Store`, `*.pyc` and every `--exclude` pattern (matched with `fnmatch` against the posix path relative to the plugin root; `dir/**` also excludes the directory itself).
2. Regular file: read the bytes. If the first 8192 bytes contain no NUL byte the file is text and every CRLF is replaced by LF. The digest is `sha256:` plus the hex SHA-256 of the result, and `size` is its length in bytes.
3. Symbolic link: the digest is the SHA-256 of the bytes `symlink`, a NUL byte, and the link target as written; `size` is the target's length and the record carries `"symlink": "<target>"`.
4. Tree hash (`contentHash`, and each entry of `components`): sort the files by the UTF-8 bytes of their path, then SHA-256 the concatenation of `<path>`, a NUL byte, `<digest>`, and a newline for each file.

Line-ending normalisation means a plugin checked out on Windows and on macOS has the same hash. File modes are not hashed. Newly generated locks have the top-level marker `"tracksExecutable": true`; their regular-file records optionally carry `"executable": true` when any execute bit is set, with absence meaning non-executable. Verification reports an execute-bit-only difference as `mode`, with the file's class severity, without changing the content or component hashes. `diff` also prints the old and new execute state for such files.

Older locks without the marker skip execute-state comparisons, so upgrading does not raise alarms on unchanged plugins. A partial `lock --only` update preserves that legacy behavior; regenerate the complete lock after reviewing the install to opt into execute-state tracking. Content changes are still detected in legacy locks.

## Component classes

Every file gets exactly one class. The class sets the severity of a change.

| Class | Severity | Files |
| --- | --- | --- |
| `hooks` | high | `hooks/`, files named by the manifest's `hooks`, and any file a hook command references as `${CLAUDE_PLUGIN_ROOT}/...` |
| `mcp` | high | `.mcp.json`, files named by `mcpServers`, `.mcpb`/`.dxt` bundles, `.mcpb-cache/`, and files a server command references |
| `lsp` | high | `.lsp.json`, files named by `lspServers`, and files a server command references |
| `monitors` | high | `monitors/`, the manifest's monitors, and files a monitor command references |
| `executables` | high | `bin/`, which Claude Code puts on the Bash tool's `PATH` |
| `manifest` | high | `.claude-plugin/` and a root `settings.json` (the manifest can declare hooks and servers inline) |
| `dependencies` | high | any `node_modules/`, and a root `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `bun.lock` or `bun.lockb` |
| `skills` | medium | `skills/`, directories the manifest's `skills` adds, and a root `SKILL.md` |
| `commands` | medium | `commands/` or what the manifest's `commands` names |
| `agents` | medium | `agents/` or what the manifest's `agents` names |
| `output-styles` | medium | `output-styles/`, `themes/`, `workflows/` and their manifest keys |
| `code` | medium | any other source file (`.py`, `.sh`, `.js`, `.ts` and similar) |
| `docs` | low | `.md`, `.txt`, images, `README*`, `LICENSE*`, `CHANGELOG*` outside the classes above |
| `other` | low | anything else |

Precedence: an exact reference (a file a hook or server command names) wins over a directory, and a longer directory prefix wins over a shorter one. A file referenced by a hook from inside `skills/` is therefore `hooks`, not `skills`.

## Severity of a verify result

- A changed plugin takes the highest severity among its changed files. A file whose class changed reports the riskier of the two classes.
- An added plugin (installed but not in the lock) is high when its `runtime` list is not empty, otherwise medium.
- A removed plugin (in the lock but not installed) is low.
- A marketplace whose `source` changed is high; a new marketplace, or `autoUpdate` turned on, is medium; a removed marketplace, `autoUpdate` turned off, or a changed `marketplace.json` catalog is low.

`verify --fail-on` sets the lowest severity that makes the exit code 1 (default `low`, so any change).

## Document shape

```json
{
  "lockfileVersion": 1,
  "tracksExecutable": true,
  "generator": "cc-plugin-lock",
  "generatorVersion": "0.2.0",
  "hashAlgorithm": "sha256",
  "pluginsRoot": "~/.claude/plugins",
  "pluginDirs": [],
  "exclude": [],
  "marketplaces": {
    "demo": {
      "source": { "source": "github", "repo": "example-org/demo-marketplace" },
      "installLocation": "~/.claude/plugins/marketplaces/demo",
      "autoUpdate": null,
      "catalogHash": "sha256:..."
    }
  },
  "plugins": {
    "formatter@demo": {
      "id": "formatter@demo",
      "name": "formatter",
      "marketplace": "demo",
      "version": "1.0.0",
      "gitCommitSha": "0123456789abcdef0123456789abcdef01234567",
      "origin": "installed",
      "scopes": ["user"],
      "path": "~/.claude/plugins/cache/demo/formatter/1.0.0",
      "entrySource": { "source": "github", "repo": "example-org/formatter" },
      "runtime": ["hooks"],
      "contentHash": "sha256:...",
      "components": { "docs": "sha256:...", "hooks": "sha256:...", "manifest": "sha256:...", "skills": "sha256:..." },
      "fileCount": 5,
      "files": {
        "scripts/format.sh": { "sha256": "sha256:...", "size": 89, "class": "hooks" }
      }
    }
  }
}
```

| Field | Meaning |
| --- | --- |
| `pluginsRoot`, `pluginDirs`, `exclude` | What `lock` was run with; `verify` reuses them unless `--root` or `--plugin-dir` is given |
| `marketplaces.<name>` | From `known_marketplaces.json`, plus the SHA-256 of the normalised `marketplace.json` |
| `plugins.<key>` | The key is the plugin id, or `<id>#<version>` when the same id is installed at two versions in different scopes |
| `origin` | `installed` (from `installed_plugins.json`), `cache` (found by scanning the cache) or `plugin-dir` |
| `scopes` | `user`, `project:<path>`, `local:<path>` or `plugin-dir`, from each install record that points at this directory |
| `entrySource` | The plugin entry's `source` in the marketplace catalog, as written there (a `sha` pin shows here) |
| `runtime` | Component types that start processes: from files present and from manifest keys (`hooks`, `mcpServers`, `lspServers`, `monitors`) |
| `components` | One tree hash per class that has at least one file |
| `files` | Every hashed file with its digest, normalised size and class |

Paths under your home directory are written with `~`, so the lock does not carry your user name. Keys are sorted and the file ends with a newline.

## The content store

`lock --store` also copies the normalised bytes of every file to `.cc-plugin-lock/objects/<first two hex digits>/<full hex digest>` next to the lock. `diff` reads it to print a unified diff against the locked content. The store is a cache: deleting it only makes `diff` fall back to listing hashes. Keep it out of version control (it holds copies of every plugin file).
