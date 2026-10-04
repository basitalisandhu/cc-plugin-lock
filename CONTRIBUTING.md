# Contributing

Thanks for considering a contribution. The project is small on purpose: discovery of installed plugins, a hashing and classification step, a comparison, a static scanner and a CLI. The most useful contributions are plugin layouts that the classifier gets wrong, scan false positives and misses with a minimal reproduction, and keeping discovery in step with Claude Code's plugin documentation.

## Set up

Requires Python 3.11 or newer. With [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/basitalisandhu/cc-plugin-lock
cd cc-plugin-lock
uv venv && uv pip install -e ".[dev]"
uv run pytest -q
```

Without uv:

```bash
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install -e ".[dev]"
python3 -m pytest -q
```

## Before you open a pull request

```bash
make check      # ruff check, ruff format --check, pytest
make demo       # lock the example plugins root, plant a change, verify
```

CI runs the same on Python 3.11 and 3.12.

## Where things live

- `src/cc_plugin_lock/discover.py`: reading `installed_plugins.json`, `known_marketplaces.json` and the cache.
- `src/cc_plugin_lock/hashing.py`: the file walk, normalisation and tree hash. A change here changes every lock; it needs a `lockfileVersion` bump and a CHANGELOG entry.
- `src/cc_plugin_lock/classify.py`: component classes and severities. Update the table in `docs/lockfile.md` with any change; `tests/test_docs.py` checks the class names.
- `src/cc_plugin_lock/verify.py`: comparison of two lock documents.
- `src/cc_plugin_lock/scan.py`: scan rules. Each rule needs a section in `docs/rules.md`, a positive and a negative test.
- `src/cc_plugin_lock/report.py` and `hookcfg.py`: output formats.

## Tests and fixtures

Tests build plugin trees in a temporary directory; nothing outside `tmp_path` is touched and nothing is fetched. Planted strings that look like attacks (a download piped into a shell, an instruction-override phrase) are assembled at run time from parts with `join(...)` in `tests/conftest.py`, so the repository itself does not trip scanners. Do the same in new tests, and never commit a value in a real credential format.

## Style

- `ruff` formats and lints; line length 100.
- Standard library only. A pull request that adds a runtime dependency will be asked to remove it.
- No model names or vendor identifiers in code, docs or fixtures; Claude Code as the host product is fine.
- Plain language, no em dashes, no claims that cannot be checked against the Claude Code docs or a test.
- Deterministic output: the same install produces a byte-identical lock and the same report.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
