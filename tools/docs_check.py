"""Fast, network-free documentation and supply-chain configuration checks."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DOCS = (
    "README.md",
    "AGENTS.md",
    "SECURITY.md",
    "docs/architecture.md",
    "docs/authority-boundaries.md",
    "docs/framework-selection.md",
    "docs/tutorial.md",
    "docs/failure-modes.md",
    "docs/threat-model.md",
    "docs/limitations.md",
    "docs/status.md",
    "docs/roadmap.md",
    "docs/runbook.md",
    "docs/connector-runbook.md",
    "docs/approval-effect-runbook.md",
    "docs/sandbox-runbook.md",
    "docs/interview-questions.md",
    "docs/curriculum.md",
    "docs/glossary.md",
    "docs/experiment-protocol.md",
    "docs/adr/001-langgraph-orchestration.md",
    "docs/adr/002-defer-temporal.md",
    "docs/adr/003-langfuse-and-opentelemetry.md",
    "docs/adr/004-postgresql-without-redis.md",
    "docs/adr/005-pyjwt-and-explicit-authorization.md",
    "docs/adr/006-postgresql-rls-and-application-audit.md",
    "docs/adr/007-temporal-durable-workflow.md",
    "docs/adr/008-application-event-ledger.md",
    "docs/adr/009-provider-neutral-model-gateway.md",
    "docs/adr/010-secure-evidence-connectors.md",
    "docs/adr/011-governed-specialist-orchestration.md",
    "docs/adr/012-temporal-approval-and-effects.md",
    "docs/adr/013-kubernetes-job-sandbox.md",
    "docs/adr/014-pgvector-sql-event-grounded-memory.md",
    "docs/memory-runbook.md",
)
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
ACTION_USE = re.compile(r"^\s*uses:\s*([^#\s]+)", re.MULTILINE)
SHA_PIN = re.compile(r"^[^@]+@[a-f0-9]{40}$")


def main() -> int:
    errors = [
        f"missing required document: {relative}"
        for relative in REQUIRED_DOCS
        if not (ROOT / relative).is_file()
    ]
    errors.extend(_broken_markdown_links())
    errors.extend(_manifest_errors())
    errors.extend(_measurement_errors())
    errors.extend(_workflow_pin_errors())
    errors.extend(_container_pin_errors())
    if errors:
        for error in errors:
            print(f"docs-check: {error}", file=sys.stderr)
        return 1
    print(
        f"docs-check: {len(REQUIRED_DOCS)} required documents and policy assets valid"
    )
    return 0


def _broken_markdown_links() -> list[str]:
    errors: list[str] = []
    for document in ROOT.rglob("*.md"):
        if any(part.startswith(".") for part in document.relative_to(ROOT).parts):
            continue
        for target in MARKDOWN_LINK.findall(document.read_text(encoding="utf-8")):
            clean = target.split("#", 1)[0]
            if (
                not clean
                or clean.startswith(("http://", "https://", "mailto:"))
                or " " in clean
            ):
                continue
            resolved = (document.parent / clean).resolve()
            if not resolved.is_relative_to(ROOT) or not resolved.exists():
                errors.append(
                    f"{document.relative_to(ROOT)} links to missing path {target}"
                )
    return errors


def _manifest_errors() -> list[str]:
    path = ROOT / "comparison/parity-manifest.json"
    if not path.is_file():
        return ["missing comparison/parity-manifest.json"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    capabilities = payload.get("capabilities", [])
    errors = []
    if payload.get("schema_version") != 1:
        errors.append("parity manifest schema_version must be 1")
    if len(capabilities) != 16:
        errors.append("parity manifest must contain exactly 16 capabilities")
    ids = [capability.get("id") for capability in capabilities]
    if len(ids) != len(set(ids)):
        errors.append("parity manifest capability ids must be unique")
    allowed = {"delivered", "partial", "planned", "not-applicable"}
    if any(capability.get("status") not in allowed for capability in capabilities):
        errors.append("parity manifest contains an invalid status")
    return errors


def _workflow_pin_errors() -> list[str]:
    errors: list[str] = []
    workflow_dir = ROOT / ".github/workflows"
    if not workflow_dir.is_dir():
        return ["missing .github/workflows"]
    for workflow in (*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")):
        for use in ACTION_USE.findall(workflow.read_text(encoding="utf-8")):
            if use.startswith("./"):
                continue
            if SHA_PIN.fullmatch(use) is None:
                errors.append(
                    f"{workflow.relative_to(ROOT)} has mutable action reference {use}"
                )
    return errors


def _measurement_errors() -> list[str]:
    path = ROOT / "comparison/layer9-metrics.json"
    if not path.is_file():
        return ["missing comparison/layer9-metrics.json"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    errors = []
    if payload.get("schema_version") != 9 or payload.get("layer") != 9:
        errors.append("Layer 9 metrics schema/layer is invalid")
    basis = payload.get("comparison_basis", {})
    custom_layer3 = basis.get("custom_layer3", {}) if isinstance(basis, dict) else {}
    custom_layer4 = basis.get("custom_layer4", {}) if isinstance(basis, dict) else {}
    custom_layer5 = basis.get("custom_layer5", {}) if isinstance(basis, dict) else {}
    custom_layer6 = basis.get("custom_layer6", {}) if isinstance(basis, dict) else {}
    custom_layer7 = basis.get("custom_layer7", {}) if isinstance(basis, dict) else {}
    custom_layer8 = basis.get("custom_layer8", {}) if isinstance(basis, dict) else {}
    custom_layer9 = basis.get("custom_layer9", {}) if isinstance(basis, dict) else {}
    custom_layer10 = basis.get("custom_layer10", {}) if isinstance(basis, dict) else {}
    if custom_layer3.get("sha") != ("87cefe58adbf62e6a419d38e57e0928581b7003c"):
        errors.append("Layer 3 custom comparison SHA is not pinned")
    if custom_layer5.get("sha") != ("7c22d380a66f57aad943fe926ffff3ca8fc06ed6"):
        errors.append("Layer 4 custom comparison SHA is not pinned")
    if custom_layer4.get("sha") != ("171fa485819334a892684544c0a993a6e2fc4ace"):
        errors.append("Layer 4 custom comparison SHA is not pinned")
    if custom_layer6.get("sha") != ("7a685bc52772e1c92467baba58a1c668646e9bf7"):
        errors.append("Layer 6 custom comparison SHA is not pinned")
    if custom_layer7.get("sha") != ("dce0054a40c34ab4cc9d515aa753bc71d73fab57"):
        errors.append("Layer 7 custom comparison SHA is not pinned")
    if custom_layer8.get("sha") != ("0ce9368d60f3b2fce7b805d7d7699d585f13cef2"):
        errors.append("Layer 8 custom comparison SHA is not pinned")
    if custom_layer9.get("sha") != ("ed16fb8bb62ca6d18bc53ec8ee4e0191ed6caa63"):
        errors.append("Layer 9 custom comparison SHA is not pinned")
    if custom_layer10.get("sha") != ("c9474184af756ce93d19d86360c339541e8263fb"):
        errors.append("Layer 10 custom comparison SHA is not pinned")
    if not payload.get("remaining_custom_controls"):
        errors.append("Layer 9 metrics must list remaining custom controls")
    if not payload.get("lock_in_and_escape"):
        errors.append("Layer 9 metrics must list lock-in and escape hatches")
    if payload.get("required_stateful_services") != [
        "PostgreSQL",
        "Temporal Server",
    ]:
        errors.append("Layer 9 metrics must list exact stateful services")
    if not payload.get("equivalent_gateway_benchmark"):
        errors.append("Layer 6 metrics must include the equivalent gateway benchmark")
    if not payload.get("equivalent_evidence_benchmark"):
        errors.append("Layer 6 metrics must include the evidence benchmark")
    if not payload.get("equivalent_orchestration_benchmark"):
        errors.append("Layer 7 metrics must include the orchestration benchmark")
    if not payload.get("equivalent_remediation_benchmark"):
        errors.append("Layer 7 metrics must include the remediation benchmark")
    if not payload.get("equivalent_sandbox_benchmark"):
        errors.append("Layer 8 metrics must include the sandbox benchmark")
    if not payload.get("equivalent_memory_benchmark"):
        errors.append("Layer 9 metrics must include the memory benchmark")
    return errors


def _container_pin_errors() -> list[str]:
    errors: list[str] = []
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    image_args = re.findall(r"^ARG\s+\w+_IMAGE=(\S+)$", dockerfile, re.MULTILINE)
    if not image_args or any("@sha256:" not in image for image in image_args):
        errors.append("Dockerfile base image arguments must be digest-pinned")
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    errors.extend(
        f"compose image is not digest-pinned: {image}"
        for image in re.findall(r"^\s+image:\s*(\S+)$", compose, re.MULTILINE)
        if "@sha256:" not in image
    )
    return errors


if __name__ == "__main__":
    raise SystemExit(main())
