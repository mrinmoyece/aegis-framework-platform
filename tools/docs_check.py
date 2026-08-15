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
    "docs/roadmap.md",
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
    path = ROOT / "comparison/layer2-metrics.json"
    if not path.is_file():
        return ["missing comparison/layer2-metrics.json"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    errors = []
    if payload.get("schema_version") != 2 or payload.get("layer") != 2:
        errors.append("Layer 2 metrics schema/layer is invalid")
    basis = payload.get("comparison_basis", {})
    custom = basis.get("custom", {}) if isinstance(basis, dict) else {}
    if custom.get("sha") != "81409792c97698479a9ca827a4143c6391f28d2b":
        errors.append("Layer 2 custom comparison SHA is not pinned")
    if not payload.get("remaining_custom_controls"):
        errors.append("Layer 2 metrics must list remaining custom controls")
    if not payload.get("lock_in_and_escape"):
        errors.append("Layer 2 metrics must list lock-in and escape hatches")
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
