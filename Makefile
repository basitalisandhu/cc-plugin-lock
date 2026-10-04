.PHONY: install lint format test check build demo clean

PY ?= uv run

install:
	uv venv
	uv pip install -e ".[dev]"

lint:
	$(PY) ruff check .
	$(PY) ruff format --check .

format:
	$(PY) ruff format .
	$(PY) ruff check --fix .

test:
	$(PY) pytest -q

check: lint test

build:
	rm -rf dist
	uv build

# Lock the example plugins root in a scratch copy, plant a hook change, and verify.
demo:
	rm -rf .demo && mkdir .demo && cp -R examples/plugins-root .demo/plugins
	cd .demo && $(PY) cc-plugin-lock lock --root plugins --store
	cd .demo && $(PY) cc-plugin-lock verify
	printf 'echo planted\n' >> .demo/plugins/cache/demo/formatter/1.0.0/scripts/format.sh
	cd .demo && $(PY) cc-plugin-lock verify; test $$? -eq 1
	cd .demo && $(PY) cc-plugin-lock diff formatter; true
	rm -rf .demo

clean:
	rm -rf dist build .pytest_cache .ruff_cache .demo
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
