# Good first issues

Scoped starting points, each filed as an issue under the `good first issue` label. Tasks marked done have shipped; the others are open. Each is self-contained and has acceptance criteria that `make check` can verify. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first: `ruff` must pass, the package stays standard-library only, and tests build their plugin trees in `tmp_path`.

## 1. Markdown output for `verify` (done in #7)

**Context.** A pull request comment or a CI job summary reads better as Markdown than as the fixed-width table.

**Acceptance criteria.**

- `verify --format markdown` prints a heading, a table of changed, added and removed plugins with severity, and one collapsible `<details>` block per changed plugin listing its files.
- Unchanged plugins are counted in one summary line, not listed.
- Tests cover a clean run and a run with one changed and one added plugin.

## 2. `lock --check` for CI (done in #8)

**Context.** Teams that commit the lock want CI to fail when someone edits plugins without updating it, without writing a new file.

**Acceptance criteria.**

- `lock --check` builds the lock in memory, compares it byte for byte with the file at `--lock`, prints a one-line result and exits 1 on a difference, 0 when identical.
- It never writes the lock or the store.
- Tests cover identical, different and missing lock files.

## 3. Track the executable bit (done in #12)

**Context.** File modes are not hashed (see "Limits" in the README), so a change that only makes a file executable is not reported.

**Acceptance criteria.**

- Each file record gains an optional `"executable": true` when any execute bit is set; the tree hash is unchanged so existing locks stay valid.
- `verify` reports a mode-only change as `mode` with the file's class severity.
- `docs/lockfile.md` documents the field; tests cover a mode-only change (skipped on Windows).

## 4. Scan rule for hook matchers that see every tool call (done, rule CPL108)

**Context.** A `PreToolUse` or `PostToolUse` hook with no matcher, `*` or `.*` receives the input and output of every tool call, which is worth a reviewer's attention when the hook also makes network calls.

**Acceptance criteria.**

- New rule `CPL108` (low) on a hook group with an all-matching matcher, and raised to medium when the same handler's script also triggers CPL106.
- A section in `docs/rules.md`, and a positive and a negative test in `tests/test_scan.py`.

## 5. Read `enabledPlugins` and report disabled plugins

**Context.** `lock` locks every installed plugin. A plugin that is installed but disabled in every settings file does not load, so a change to it matters less.

**Acceptance criteria.**

- Read `enabledPlugins` from `~/.claude/settings.json` and, with `--project DIR`, from `DIR/.claude/settings.json` and `DIR/.claude/settings.local.json`, applying the precedence in the Claude Code plugin loading reference.
- Record `"enabled": true|false|null` per plugin in the lock (null when unknown); `verify` shows disabled plugins in the table and does not raise their severity.
- Tests use a fake home directory set through an environment variable or a parameter, never the real one.

## 6. `scan --allow` and an allowlist file

**Context.** A plugin that legitimately calls `curl` in a hook gets CPL106 on every scan.

**Acceptance criteria.**

- `scan --allow RULE:PATH[:LINE]` (repeatable) and a `.cc-plugin-lock-allow` file in the scanned folder suppress matching findings; suppressed findings are counted in the summary.
- An allow entry that matches nothing is reported as a warning.
- Tests cover a suppressed finding, an unused entry and the summary count.

## 7. Markdown output for `scan`

**Context.** `verify --format markdown` exists for pull request comments and CI job summaries; `scan` only has table, JSON and SARIF, so a marketplace pipeline that scans each plugin cannot post a readable summary.

**Acceptance criteria.**

- `scan --format markdown` prints a heading with the scanned path, a summary line with counts per severity, and a table of findings (severity, rule ID, file:line, title, evidence) with `|` escaped in the evidence.
- A clean scan prints the heading and "No findings."; exit codes and `--fail-on` are unchanged.
- `SCAN_FORMATS` in `src/cc_plugin_lock/report.py` and the README command table list `markdown`; tests in `tests/test_scan.py` cover a clean run and a run with findings.
