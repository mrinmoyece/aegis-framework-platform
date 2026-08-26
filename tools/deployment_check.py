"""Deterministic checks for Layer 14 deployment and supply-chain assets."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from aegis_framework.production import (
    CapacityPlan,
    RegionTopology,
    RetentionPlan,
    TemporalBoundary,
)

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "deployment/kubernetes/overlays/production"
TERRAFORM = ROOT / "deployment/terraform/aws"
DIGEST_IMAGE = re.compile(r"^[^@\s]+@sha256:[a-f0-9]{64}$")
ACTION_PIN = re.compile(r"^\s*uses:\s*[^@\s]+@[a-f0-9]{40}(?:\s+#.*)?$", re.MULTILINE)
EXPECTED_DEPLOYMENTS = {
    "aegis-api",
    "aegis-operator",
    "aegis-outbox",
    "aegis-reconciler",
    "aegis-investigation-worker",
    "aegis-cognitive-worker",
    "aegis-evidence-worker",
    "aegis-remediation-worker",
    "aegis-memory-worker",
    "aegis-sandbox-controller",
    "aegis-protocol-gateway",
    "aegis-protocol-worker",
    "aegis-otel-collector",
}
EXPECTED_NETWORK_POLICIES = {
    "allow-dns",
    "default-deny",
    "egress-approved-protocol-peers",
    "egress-approved-providers-connectors",
    "egress-oidc",
    "egress-otlp",
    "egress-postgresql-pgvector",
    "egress-temporal-frontend",
    "ingress-api-operator",
    "ingress-otlp",
    "otel-upstream",
}


def main() -> int:
    errors = [
        *_kubernetes_errors(),
        *_terraform_errors(),
        *_supply_chain_errors(),
        *_migration_errors(),
        *_production_plan_errors(),
    ]
    if errors:
        for error in errors:
            print(f"deployment-check: {error}", file=sys.stderr)
        return 1
    print(
        "deployment-check: Kubernetes, Terraform, migration, recovery, and "
        "supply-chain foundations valid"
    )
    return 0


def _kubernetes_errors() -> list[str]:
    kubectl = shutil.which("kubectl")
    if kubectl is None:
        return ["kubectl is required to render Kustomize"]
    result = subprocess.run(  # noqa: S603
        [kubectl, "kustomize", str(OVERLAY)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return [f"Kustomize render failed: {result.stderr.strip()}"]
    resources = [
        resource
        for resource in yaml.safe_load_all(result.stdout)
        if isinstance(resource, dict)
    ]
    errors: list[str] = []
    deployments = _by_kind(resources, "Deployment")
    deployment_names = {_name(resource) for resource in deployments}
    if deployment_names != EXPECTED_DEPLOYMENTS:
        errors.append("production deployment set is incomplete or unexpected")
    plan = json.loads((ROOT / "deployment/production-plan.json").read_text())
    planned_components = {worker["component"] for worker in plan["capacity"]["workers"]}
    rendered_worker_components = {
        deployment["spec"]["template"]["metadata"]["labels"][
            "app.kubernetes.io/component"
        ]
        for deployment in deployments
        if _name(deployment)
        not in {"aegis-api", "aegis-operator", "aegis-otel-collector"}
    }
    if planned_components != rendered_worker_components:
        errors.append("capacity plan does not cover every rendered worker component")
    for deployment in deployments:
        errors.extend(_deployment_errors(deployment))

    jobs = _by_kind(resources, "Job")
    if {_name(job) for job in jobs} != {"aegis-migration"}:
        errors.append("exactly one migration Job is required")
    elif _pod_errors(jobs[0]["spec"]["template"]["spec"], "aegis-migration"):
        errors.extend(
            _pod_errors(jobs[0]["spec"]["template"]["spec"], "aegis-migration")
        )

    pdb_names = {_name(item) for item in _by_kind(resources, "PodDisruptionBudget")}
    if not EXPECTED_DEPLOYMENTS.issubset(pdb_names):
        errors.append("every long-running deployment requires a PDB")
    hpa_targets = {
        item["spec"]["scaleTargetRef"]["name"]
        for item in _by_kind(resources, "HorizontalPodAutoscaler")
    }
    required_hpa = {
        "aegis-api",
        "aegis-operator",
        "aegis-investigation-worker",
        "aegis-cognitive-worker",
        "aegis-evidence-worker",
        "aegis-remediation-worker",
        "aegis-memory-worker",
        "aegis-protocol-gateway",
        "aegis-protocol-worker",
    }
    if not required_hpa.issubset(hpa_targets):
        errors.append("API/operator/Temporal worker HPAs are incomplete")

    policies = _by_kind(resources, "NetworkPolicy")
    policy_names = {_name(item) for item in policies}
    if not EXPECTED_NETWORK_POLICIES.issubset(policy_names):
        errors.append("default-deny or explicit boundary NetworkPolicies are missing")
    default_denies = [
        item
        for item in policies
        if _name(item) == "default-deny"
        and item["spec"].get("podSelector") == {}
        and item["spec"].get("policyTypes") == ["Ingress", "Egress"]
    ]
    if len(default_denies) != 2:
        errors.append("application and sandbox namespaces must both default deny")
    ingress_policy = next(
        (item for item in policies if _name(item) == "ingress-api-operator"),
        None,
    )
    ingress_ports = {
        port["port"]
        for rule in (ingress_policy or {}).get("spec", {}).get("ingress", [])
        for port in rule.get("ports", [])
    }
    if ingress_ports != {8000, 8001}:
        errors.append("API/operator/protocol ingress ports are incomplete")
    temporal_policy = next(
        (item for item in policies if _name(item) == "egress-temporal-frontend"),
        None,
    )
    temporal_values = (
        temporal_policy["spec"]["podSelector"]["matchExpressions"][0]["values"]
        if temporal_policy is not None
        else []
    )
    if "protocol-gateway" not in temporal_values:
        errors.append("protocol gateway cannot reach the Temporal frontend boundary")

    for role in _by_kind(resources, "Role") + _by_kind(resources, "ClusterRole"):
        for rule in role.get("rules", []):
            if "*" in rule.get("verbs", []) or "*" in rule.get("resources", []):
                errors.append(f"{_name(role)} contains wildcard RBAC")
            if "secrets" in rule.get("resources", []):
                errors.append(f"{_name(role)} can read Kubernetes Secrets")
            if "networkpolicies" in rule.get("resources", []) and {
                "create",
                "update",
                "patch",
                "delete",
            }.intersection(rule.get("verbs", [])):
                errors.append(f"{_name(role)} can mutate namespace NetworkPolicies")

    ingresses = _by_kind(resources, "Ingress")
    if len(ingresses) != 1:
        errors.append("exactly one internal TLS ingress is required")
    else:
        ingress = ingresses[0]
        annotations = ingress["metadata"].get("annotations", {})
        required_annotations = {
            "nginx.ingress.kubernetes.io/force-ssl-redirect",
            "nginx.ingress.kubernetes.io/limit-rps",
            "nginx.ingress.kubernetes.io/proxy-body-size",
            "nginx.ingress.kubernetes.io/proxy-read-timeout",
        }
        if (
            not ingress["spec"].get("tls")
            or not required_annotations <= annotations.keys()
        ):
            errors.append(
                "ingress TLS, rate, body, and timeout controls are incomplete"
            )

    admission = _by_kind(resources, "ValidatingAdmissionPolicy")
    bindings = _by_kind(resources, "ValidatingAdmissionPolicyBinding")
    if len(admission) < 2 or any(
        "Deny" not in binding["spec"].get("validationActions", [])
        for binding in bindings
    ):
        errors.append("fail-closed workload and sandbox admission is incomplete")
    hardened = next(
        (policy for policy in admission if _name(policy) == "aegis-hardened-pods"),
        None,
    )
    if hardened is None or not _hardened_policy_enforces_all_container_classes(
        hardened
    ):
        errors.append("workload admission policy does not harden every container class")
    if len(_by_kind(resources, "ClusterImagePolicy")) != 1:
        errors.append("keyless signature/SBOM admission policy is not rendered")
    return errors


def _deployment_errors(deployment: dict[str, Any]) -> list[str]:
    name = _name(deployment)
    spec = deployment["spec"]
    errors = _pod_errors(spec["template"]["spec"], name)
    strategy = spec.get("strategy", {}).get("rollingUpdate", {})
    if strategy != {"maxSurge": 1, "maxUnavailable": 0}:
        errors.append(f"{name} does not use zero-unavailable rolling safety")
    if spec.get("minReadySeconds", 0) < 30:
        errors.append(f"{name} has no minimum readiness soak")
    pod_spec = spec["template"]["spec"]
    if not pod_spec.get("topologySpreadConstraints") or not pod_spec.get("affinity"):
        errors.append(f"{name} lacks topology spread or anti-affinity")
    return errors


def _pod_errors(pod_spec: dict[str, Any], owner: str) -> list[str]:
    errors: list[str] = []
    if not pod_spec.get("serviceAccountName"):
        errors.append(f"{owner} has no explicit service account")
    if pod_spec.get("automountServiceAccountToken", True):
        errors.append(f"{owner} automatically mounts a service-account token")
    if any(
        pod_spec.get(field, False) for field in ("hostNetwork", "hostPID", "hostIPC")
    ):
        errors.append(f"{owner} enables a host namespace")
    errors.extend(
        f"{owner} uses hostPath"
        for volume in pod_spec.get("volumes", [])
        if "hostPath" in volume
    )
    for container in pod_spec.get("containers", []):
        image = container.get("image", "")
        if DIGEST_IMAGE.fullmatch(image) is None:
            errors.append(f"{owner}/{container.get('name')} image is not digest-pinned")
        security = container.get("securityContext", {})
        if (
            security.get("allowPrivilegeEscalation") is not False
            or security.get("privileged", False)
            or security.get("readOnlyRootFilesystem") is not True
            or security.get("runAsNonRoot") is not True
            or "ALL" not in security.get("capabilities", {}).get("drop", [])
            or security.get("seccompProfile", {}).get("type") != "RuntimeDefault"
        ):
            errors.append(f"{owner}/{container.get('name')} is not hardened")
        resources = container.get("resources", {})
        if not all(
            resources.get(section, {}).get(key)
            for section in ("requests", "limits")
            for key in ("cpu", "memory")
        ):
            errors.append(f"{owner}/{container.get('name')} lacks CPU/memory bounds")
        if owner != "aegis-migration" and not all(
            container.get(probe)
            for probe in ("startupProbe", "readinessProbe", "livenessProbe")
        ):
            errors.append(f"{owner}/{container.get('name')} lacks complete probes")
        if owner != "aegis-migration" and not container.get("lifecycle", {}).get(
            "preStop"
        ):
            errors.append(f"{owner}/{container.get('name')} lacks drain/preStop")
    return errors


def _hardened_policy_enforces_all_container_classes(policy: dict[str, Any]) -> bool:
    expressions = " ".join(
        validation.get("expression", "")
        for validation in policy.get("spec", {}).get("validations", [])
        if isinstance(validation, dict)
    )
    required_terms = (
        "object.spec.containers.all",
        "object.spec.initContainers.all",
        "object.spec.ephemeralContainers.all",
        "runAsNonRoot == true",
        "readOnlyRootFilesystem == true",
        "allowPrivilegeEscalation == false",
    )
    return all(term in expressions for term in required_terms)


def _terraform_errors() -> list[str]:
    files = tuple(TERRAFORM.rglob("*.tf")) + tuple(TERRAFORM.rglob("*.tftest.hcl"))
    if not files:
        return ["AWS Terraform reference is missing"]
    content = "\n".join(path.read_text(encoding="utf-8") for path in files)
    errors: list[str] = []
    required_snippets = (
        'required_version = "= 1.13.3"',
        'version = "= 6.10.0"',
        'backend "s3"',
        "use_lockfile = true",
        'resource "aws_eks_cluster"',
        'resource "aws_db_instance"',
        'resource "aws_vpc_endpoint" "temporal"',
        'resource "aws_backup_vault_lock_configuration"',
        'resource "aws_ecr_repository"',
        'resource "aws_eks_pod_identity_association"',
        "prevent_destroy = true",
        "endpoint_public_access  = false",
        "manage_master_user_password",
    )
    errors.extend(
        f"Terraform missing required control: {snippet}"
        for snippet in required_snippets
        if snippet not in content
    )
    if re.search(r"(?i)(password|secret_string)\s*=\s*\"[^$]", content):
        errors.append("Terraform contains an apparent literal secret")
    if 'mock_provider "aws"' not in content:
        errors.append("Terraform reference has no credential-free mocked plan")
    return errors


def _supply_chain_errors() -> list[str]:
    workflows = (
        ROOT / ".github/workflows/supply-chain.yml",
        ROOT / ".github/workflows/promotion.yml",
        ROOT / ".github/workflows/infrastructure.yml",
        ROOT / ".github/workflows/restore-drill.yml",
    )
    errors: list[str] = []
    for workflow in workflows:
        content = workflow.read_text(encoding="utf-8")
        uses = re.findall(r"^\s*uses:\s*\S+.*$", content, re.MULTILINE)
        if any(ACTION_PIN.fullmatch(use) is None for use in uses):
            errors.append(f"{workflow.name} contains a mutable action reference")
    supply = workflows[0].read_text(encoding="utf-8")
    errors.extend(
        f"supply-chain workflow is missing {required}"
        for required in (
            "linux/amd64,linux/arm64",
            "spdx-json",
            "cosign sign",
            "attest-build-provenance",
            "scanners: secret",
            "make security python-licenses frontend-licenses",
        )
        if required not in supply
    )
    promotion = workflows[1].read_text(encoding="utf-8")
    errors.extend(
        f"promotion workflow is missing {required}"
        for required in (
            "cosign verify",
            "gh attestation verify",
            "environment: staging",
            "environment: production",
        )
        if required not in promotion
    )
    policy = (ROOT / "deployment/kubernetes/base/signature-policy.yaml").read_text(
        encoding="utf-8"
    )
    if "supply-chain.yml@refs/heads/master" not in policy or "spdx-sbom" not in policy:
        errors.append("keyless admission identity/SBOM policy is incomplete")
    waivers = json.loads(
        (ROOT / "security/vulnerability-waivers.json").read_text(encoding="utf-8")
    )
    if (
        waivers.get("schema_version") != 1
        or not isinstance(waivers.get("waivers"), list)
        or len(waivers["waivers"]) > 16
    ):
        errors.append("Layer 14 vulnerability waivers are malformed or unbounded")
    if "tools/vulnerability_check.py" not in supply:
        errors.append(
            "supply-chain workflow does not enforce exact vulnerability waivers"
        )
    if "tools/spdx_check.py" not in supply:
        errors.append("supply-chain workflow does not validate SPDX mandatory fields")
    return errors


def _migration_errors() -> list[str]:
    migration = (ROOT / "migrations/0010_layer14.sql").read_text(encoding="utf-8")
    required = (
        "pg_advisory_xact_lock",
        "deployment_generations",
        "restore_drill_records",
        "retention_executions",
        "legal_hold_checked",
        "GRANT EXECUTE ON FUNCTION aegis.current_tenant_id() TO aegis_operations",
        "reject_immutable_fact",
        "REVOKE ALL",
    )
    return [
        f"Layer 14 migration missing {item}"
        for item in required
        if item not in migration
    ]


def _production_plan_errors() -> list[str]:
    path = ROOT / "deployment/production-plan.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        capacity = CapacityPlan.model_validate(document["capacity"])
        TemporalBoundary.model_validate(document["temporal"])
        RetentionPlan.model_validate(document["retention"])
        RegionTopology.model_validate(document["region"])
    except (OSError, KeyError, json.JSONDecodeError, ValidationError) as exc:
        return [f"production plan is invalid: {type(exc).__name__}"]
    if capacity.planned_database_connections > 700:
        return ["production plan exceeds the explicit 70% database connection budget"]
    return []


def _by_kind(
    resources: Iterable[dict[str, Any]],
    kind: str,
) -> list[dict[str, Any]]:
    return [resource for resource in resources if resource.get("kind") == kind]


def _name(resource: dict[str, Any]) -> str:
    return str(resource["metadata"]["name"])


if __name__ == "__main__":
    raise SystemExit(main())
