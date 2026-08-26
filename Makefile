.DEFAULT_GOAL := help

UV ?= uv

.PHONY: help bootstrap format lint type test integration temporal-integration eval eval-safety eval-adversarial eval-recovery eval-baseline eval-meta docs security demo serve measure container compose-config ci

help:
	@printf '%s\n' \
	  'bootstrap       Install the locked development environment' \
	  'format          Format Python sources' \
	  'lint            Run Ruff without mutation' \
	  'type            Run strict mypy' \
	  'test            Run branch coverage tests (minimum 90%%)' \
	  'integration     Run configured local PostgreSQL/Keycloak integration tests' \
	  'temporal-integration Run configured local Temporal workflow tests' \
	  'eval            Run the complete governed deterministic evaluation suite' \
	  'eval-safety     Run non-waivable safety invariants' \
	  'eval-adversarial Run adversarial attack packs' \
	  'eval-recovery   Run deterministic recovery/chaos scenarios' \
	  'eval-baseline   Compare current results with the reviewed baseline' \
	  'eval-meta       Test evaluator repeatability, sharding, waivers, and redaction' \
	  'docs            Validate documentation and manifests' \
	  'security        Run static and dependency vulnerability checks' \
	  'demo            Run the successful checkout investigation' \
	  'serve           Start the local API on 127.0.0.1:8000' \
	  'measure         Refresh Layer 11 framework comparison measurements' \
	  'observability-config Validate Prometheus, Grafana, and OTel assets' \
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

integration:
	$(UV) run pytest -m 'postgres or keycloak' --no-cov

temporal-integration:
	$(UV) run pytest -m temporal --no-cov

eval:
	$(UV) run aegis-framework eval run --report-dir build/evals

eval-safety:
	$(UV) run aegis-framework eval run --filter safe-failure --filter deny-adversarial-input

eval-adversarial:
	$(UV) run aegis-framework eval run --filter deny-adversarial-input

eval-recovery:
	$(UV) run aegis-framework eval run --filter deterministic-recovery --filter durable-cancellation --filter ambiguous-effects

eval-baseline:
	$(UV) run aegis-framework eval compare

eval-meta:
	$(UV) run pytest tests/test_evaluation_layer10.py --no-cov

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
	$(UV) run python tools/measure.py --write comparison/layer11-metrics.json --runs 200

observability-config:
	$(UV) run python tools/observability_check.py

container:
	docker build --pull --tag aegis-framework-platform:layer11 .

compose-config:
	docker compose config --quiet

ci: lint type test eval eval-safety eval-adversarial eval-recovery eval-baseline eval-meta docs observability-config
