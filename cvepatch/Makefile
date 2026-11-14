.PHONY: help install dev test test-slow test-all lint format clean db-init smoke summary doctor setup-hooks

VENV ?= .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

help:
	@echo "cvepatch targets:"
	@echo "  install       create venv + install package + dev deps"
	@echo "  test          unit tests (no Docker, no API)"
	@echo "  test-slow     slow tests (Docker required, no API)"
	@echo "  test-all      run everything"
	@echo "  smoke         build the fixture env + run one --mock-llm episode"
	@echo "  doctor        print env / docker / deps health check"
	@echo "  summary       per-run spend / status table"
	@echo "  lint / format ruff check / format"
	@echo "  setup-hooks   install .githooks/pre-commit (refuses commits on main)"
	@echo "  clean         delete venv + caches"

install: $(VENV) setup-hooks
	$(PIP) install -e .[dev]
	@# Keep API keys in .env private to this user.
	@if [ -f .env ]; then chmod 600 .env && echo "tightened .env permissions to 600"; fi

$(VENV):
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip

dev: install

db-init:
	$(PY) -c "from cvepatch.db.schema import init_db; init_db()"

test:
	$(VENV)/bin/pytest -q -m "not slow"

test-slow:
	$(VENV)/bin/pytest -q -m "slow"

test-all:
	$(VENV)/bin/pytest -q

lint:
	$(VENV)/bin/ruff check cvepatch scripts

format:
	$(VENV)/bin/ruff format cvepatch scripts

smoke: $(VENV)
	bash testenvs/defensive-fixture/build.sh
	$(VENV)/bin/cvepatch register-defensive testenvs/defensive-fixture/env_manifest.yaml
	$(VENV)/bin/cvepatch benchmark --config benchmarks/defensive-fixture.yaml --mock-llm

summary:
	$(VENV)/bin/cvepatch summary

doctor:
	$(VENV)/bin/cvepatch doctor

clean:
	rm -rf $(VENV) build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +

setup-hooks:
	@mkdir -p "$$(git rev-parse --git-common-dir)/hooks"
	@cp .githooks/pre-commit "$$(git rev-parse --git-common-dir)/hooks/pre-commit"
	@chmod +x "$$(git rev-parse --git-common-dir)/hooks/pre-commit"
	@echo "pre-commit hook installed — refuses commits on main"
