.DEFAULT_GOAL := help

UV ?= uv

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
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

lint:
	$(UV) run ruff format --check .
	$(UV) run ruff check .

type:
	$(UV) run mypy

test:
	$(UV) run pytest

eval:
	$(UV) run aegis-framework eval --cases evals/cases.json

docs:
	$(UV) run python tools/docs_check.py

security:
	$(UV) run bandit -q -r src
	$(UV) run pip-audit --progress-spinner=off --timeout=60 --cache-dir=.cache/pip-audit

demo:
	$(UV) run aegis-framework demo --scenario success

serve:
	$(UV) run aegis-framework serve

measure:
	$(UV) run python tools/measure.py --write comparison/layer1-metrics.json

container:
	docker build --pull --tag aegis-framework-platform:layer1 .

compose-config:
	docker compose config --quiet

ci: lint type test eval docs
