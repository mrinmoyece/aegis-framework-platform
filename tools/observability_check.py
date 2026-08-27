"""Validate Layer 11 observability configuration without network access."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = re.compile(
    r"(?i)(tenant_id|actor_id|user_id|request_id|run_id|incident_id|"
    r"evidence_locator|prompt|completion|authorization|cookie)"
)


def main() -> int:
    errors: list[str] = []
    collector = _yaml("observability/otel-collector.yaml", errors)
    prometheus = _yaml("observability/prometheus/prometheus.yaml", errors)
    rules = _yaml("observability/prometheus/rules/aegis-slos.yaml", errors)
    for relative in (
        "observability/grafana/provisioning/datasources/prometheus.yaml",
        "observability/grafana/provisioning/dashboards/aegis.yaml",
    ):
        _yaml(relative, errors)
    dashboards = sorted((ROOT / "observability/grafana/dashboards").glob("*.json"))
    if len(dashboards) < 4:
        errors.append("at least four bounded Aegis dashboards are required")
    for path in dashboards:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path.relative_to(ROOT)} is invalid: {type(exc).__name__}")
            continue
        if not value.get("uid") or not value.get("panels"):
            errors.append(f"{path.relative_to(ROOT)} lacks uid or panels")
        if FORBIDDEN.search(json.dumps(value)):
            errors.append(f"{path.relative_to(ROOT)} contains a forbidden dimension")
    if collector:
        processors = collector.get("processors", {})
        errors.extend(
            f"collector lacks {required} processor"
            for required in ("memory_limiter", "attributes/redact", "batch")
            if required not in processors
        )
        exporters = collector.get("exporters", {})
        if "debug" in exporters or "logging" in exporters:
            errors.append("collector must not enable a payload debug exporter")
    if prometheus and not prometheus.get("rule_files"):
        errors.append("Prometheus does not load rule files")
    alerts = _alerts(rules)
    errors.extend(
        f"missing required alert {required}"
        for required in (
            "AegisFastErrorBudgetBurn",
            "AegisSlowErrorBudgetBurn",
            "AegisSafetyViolation",
        )
        if required not in alerts
    )
    if errors:
        for error in errors:
            print(f"observability-check: {error}", file=sys.stderr)
        return 1
    print(
        "observability-check: collector, Prometheus rules, provisioning, "
        f"and {len(dashboards)} dashboards valid"
    )
    return 0


def _yaml(relative: str, errors: list[str]) -> dict[str, object]:
    path = ROOT / relative
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        errors.append(f"{relative} is invalid: {type(exc).__name__}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{relative} must contain a mapping")
        return {}
    return value


def _alerts(rules: dict[str, object]) -> set[str]:
    result: set[str] = set()
    for group in rules.get("groups", []):
        if not isinstance(group, dict):
            continue
        for rule in group.get("rules", []):
            if isinstance(rule, dict) and isinstance(rule.get("alert"), str):
                result.add(rule["alert"])
    return result


if __name__ == "__main__":
    raise SystemExit(main())
