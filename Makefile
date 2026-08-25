.DEFAULT_GOAL := help

UV ?= uv
VENV_BIN ?= .venv/bin
HAS_UV := $(shell command -v $(UV) >/dev/null 2>&1 && printf yes)
RUFF := $(if $(HAS_UV),$(UV) run ruff,$(VENV_BIN)/ruff)
MYPY := $(if $(HAS_UV),$(UV) run mypy,$(VENV_BIN)/mypy)
PYTEST := $(if $(HAS_UV),$(UV) run pytest,$(VENV_BIN)/pytest)
PYTHON := $(if $(HAS_UV),$(UV) run python,$(VENV_BIN)/python)
BANDIT := $(if $(HAS_UV),$(UV) run bandit,$(VENV_BIN)/bandit)
PIP_AUDIT := $(if $(HAS_UV),$(UV) run pip-audit,$(VENV_BIN)/pip-audit)
AEGIS := $(if $(HAS_UV),$(UV) run aegis-framework,$(VENV_BIN)/aegis-framework)

.PHONY: help bootstrap format lint type test eval docs security demo serve measure container compose-config ci

help:
	@printf '%s\n' \
	  'bootstrap       Install the locked development environment' \
	  'format          Format Python sources' \
	  'lint            Run Ruff without mutation' \
	  'type            Run strict mypy' \
	  'test            Run branch coverage tests (minimum 90%%)' \
	  'eval            Run deterministic safety evals' \
	  'docs            Validate documentation and manifests' \
	  'security        Run static and dependency vulnerability checks' \
	  'demo            Run the successful checkout investigation' \
	  'serve           Start the local API on 127.0.0.1:8000' \
	  'measure         Refresh framework comparison measurements' \
	  'container       Build the digest-pinned non-root image' \
	  'compose-config  Validate the local dependency topology' \
	  'ci              Run all fast, network-free quality gates'

bootstrap:
	$(UV) sync --locked --all-extras

format:
	$(RUFF) format .
	$(RUFF) check --fix .

lint:
	$(RUFF) format --check .
	$(RUFF) check .

type:
	$(MYPY)

test:
	$(PYTEST)

eval:
	$(AEGIS) eval --cases evals/cases.json

docs:
	$(PYTHON) tools/docs_check.py

security:
	$(BANDIT) -q -r src
	$(PIP_AUDIT) --progress-spinner=off --timeout=60 --cache-dir=.cache/pip-audit

demo:
	$(AEGIS) demo --scenario success

serve:
	$(AEGIS) serve

measure:
	$(PYTHON) tools/measure.py --write comparison/layer1-metrics.json

container:
	docker build --pull --tag aegis-framework-platform:layer1 .

compose-config:
	docker compose config --quiet

ci: lint type test eval docs
