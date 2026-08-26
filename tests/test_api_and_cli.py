from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_framework.api import ApiRuntime, AppMode, create_app
from aegis_framework.cli import main
from aegis_framework.errors import IdentityUnavailable, OptionalDependencyMissing
from aegis_framework.fixtures import demo_request
from aegis_framework.remediation_demo import (
    RemediationDemoScenario,
    build_remediation_api_demo,
)

_DEFAULT_BEARER = "demo-responder-token"


def _headers(
    *,
    request_id: str,
    identity_fixture: str = _DEFAULT_BEARER,
) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {identity_fixture}",
        "X-Request-ID": request_id,
    }


def _payload() -> dict[str, object]:
    request = demo_request()
    return {
        "incident_id": request.incident_id,
        "alert": request.alert.model_dump(mode="json"),
    }


def test_health_and_success_endpoint() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO))
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json() == {
        "status": "ok",
        "identity_mode": "demo",
        "network_connectors_enabled": False,
        "network_models_enabled": False,
        "effects_enabled": False,
    }
    response = client.post(
        "/v1/investigations",
        headers=_headers(request_id="api-success"),
        json=_payload(),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "complete"
    assert body["approval"]["status"] == "pending"
    assert body["proposal"]["requires_approval"] is True
    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"


def test_authenticated_identity_and_governance_routes_are_scoped() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO))
    responder = _headers(request_id="api-me")
    me = client.get("/v1/me", headers=responder)
    assert me.status_code == 200
    assert me.json()["tenant_id"] == "tenant-acme"
    assert me.json()["issuer"] == "https://demo.aegis.invalid"
    assert me.json()["roles"] == ["incident-responder"]

    own_tenant = client.get("/v1/tenants/tenant-acme", headers=responder)
    assert own_tenant.status_code == 200
    assert own_tenant.json()["status"] == "active"
    assert client.get("/v1/tenants/tenant-beta", headers=responder).status_code == 404
    assert client.get("/v1/policies/current", headers=responder).status_code == 200
    assert client.get("/v1/quotas/investigations", headers=responder).status_code == 200
    assert client.get("/v1/audit", headers=responder).status_code == 404

    client.post(
        "/v1/investigations",
        headers=_headers(request_id="api-audit-source"),
        json=_payload(),
    )
    audit = client.get(
        "/v1/audit",
        headers=_headers(
            request_id="api-audit-read",
            identity_fixture="demo-admin-token",
        ),
    )
    assert audit.status_code == 200
    assert [record["event_type"] for record in audit.json()] == [
        "investigation.accepted",
        "investigation.complete",
    ]
    assert "tenant_id" not in audit.text


def test_model_operations_routes_are_authorized_and_redacted() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO))
    headers = _headers(request_id="api-model-operations")
    catalog = client.get("/v1/models/catalog", headers=headers)
    assert catalog.status_code == 200
    assert catalog.json()[0]["provider"] == "fake"
    assert catalog.json()[0]["pricing_version"] == "fake-2026-08-15"
    assert "credential" not in catalog.text
    assert "tenant_id" not in catalog.text

    usage = client.get("/v1/models/usage/run:opaque", headers=headers)
    assert usage.status_code == 200
    assert usage.json() == {
        "run_id": "run:opaque",
        "reserved_cost_microunits": 0,
        "reconciled_cost_microunits": 0,
        "ambiguous_cost_microunits": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "call_count": 0,
    }
    health = client.get("/v1/models/health", headers=headers)
    assert health.status_code == 200
    assert health.json()[0]["status"] == "unknown"


def test_approval_api_is_authenticated_redacted_and_exact_scope() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO))
    approval_id = build_remediation_api_demo().approval_id
    responder = _headers(request_id="approval-read")
    pending = client.get(f"/v1/approvals/{approval_id}", headers=responder)
    assert pending.status_code == 200
    view = pending.json()
    assert view["status"] == "approval_pending"
    assert view["quorum"] == 2
    assert "tenant" not in pending.text
    assert "approver" not in pending.text
    assert "rationale" not in pending.text
    assert (
        client.get(
            f"/v1/approvals/{approval_id}",
            headers=_headers(
                request_id="approval-cross-tenant",
                identity_fixture="demo-beta-token",
            ),
        ).status_code
        == 404
    )
    first = client.post(
        f"/v1/approvals/{approval_id}/decisions",
        headers=_headers(
            request_id="approval-first",
            identity_fixture="demo-commander-token",
        ),
        json={
            "command_id": "api-approval-first",
            "disposition": "grant",
            "rationale": "Independent exact-scope approval from incident command.",
            "expected_version": view["version"],
            "plan_digest": view["plan_digest"],
            "approval_digest": view["approval_digest"],
        },
    )
    assert first.status_code == 200
    assert first.json()["status"] == "approval_pending"
    second = client.post(
        f"/v1/approvals/{approval_id}/decisions",
        headers=_headers(
            request_id="approval-second",
            identity_fixture="demo-change-approver-token",
        ),
        json={
            "command_id": "api-approval-second",
            "disposition": "grant",
            "rationale": "Independent change approval confirms the immutable digests.",
            "expected_version": first.json()["version"],
            "plan_digest": view["plan_digest"],
            "approval_digest": view["approval_digest"],
        },
    )
    assert second.status_code == 200
    assert second.json()["status"] == "approved"
    assert second.json()["grants"] == 2
    stale = client.post(
        f"/v1/approvals/{approval_id}/decisions",
        headers=_headers(
            request_id="approval-stale",
            identity_fixture="demo-admin-token",
        ),
        json={
            "command_id": "api-approval-stale",
            "disposition": "grant",
            "rationale": "This stale decision must not mutate the approval.",
            "expected_version": 3,
            "plan_digest": view["plan_digest"],
            "approval_digest": view["approval_digest"],
        },
    )
    assert stale.status_code in {404, 409}

    denied_client = TestClient(create_app(mode=AppMode.DEMO))
    denied_view = denied_client.get(
        f"/v1/approvals/{approval_id}",
        headers=_headers(request_id="approval-denial-read"),
    ).json()
    denied = denied_client.post(
        f"/v1/approvals/{approval_id}/decisions",
        headers=_headers(
            request_id="approval-denial",
            identity_fixture="demo-commander-token",
        ),
        json={
            "command_id": "api-approval-denial",
            "disposition": "deny",
            "rationale": "Current operating conditions make this exact action unsafe.",
            "expected_version": denied_view["version"],
            "plan_digest": denied_view["plan_digest"],
            "approval_digest": denied_view["approval_digest"],
        },
    )
    assert denied.status_code == 200
    terminal_race = denied_client.post(
        f"/v1/approvals/{approval_id}/decisions",
        headers=_headers(
            request_id="approval-terminal-race",
            identity_fixture="demo-change-approver-token",
        ),
        json={
            "command_id": "api-approval-after-denial",
            "disposition": "grant",
            "rationale": "This raced grant must not escape terminal denial.",
            "expected_version": denied.json()["version"],
            "plan_digest": denied_view["plan_digest"],
            "approval_digest": denied_view["approval_digest"],
        },
    )
    assert terminal_race.status_code == 409
    assert terminal_race.json()["detail"] == "approval is already terminal"


def test_production_identity_and_readiness_fail_closed() -> None:
    client = TestClient(create_app(mode=AppMode.PRODUCTION))
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["identity_mode"] == "production"
    assert client.get("/readyz").status_code == 503
    response = client.get(
        "/v1/me",
        headers=_headers(request_id="api-production-closed"),
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "identity service is unavailable"


def test_endpoint_denial_and_validation() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO))
    denied = client.post(
        "/v1/investigations",
        headers=_headers(
            request_id="api-denied",
            identity_fixture="demo-viewer-token",
        ),
        json=_payload(),
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "investigation is not authorized"
    missing_identity = client.post("/v1/investigations", json=_payload())
    assert missing_identity.status_code == 401
    malformed = client.post(
        "/v1/investigations",
        headers=_headers(request_id="api-malformed"),
        json={**_payload(), "unexpected": "authority"},
    )
    assert malformed.status_code == 422
    bad_identity = client.post(
        "/v1/investigations",
        headers={
            **_headers(request_id="api-bad-identity"),
            "Authorization": "Bearer invalid-token",
        },
        json=_payload(),
    )
    assert bad_identity.status_code == 401
    assert bad_identity.json()["detail"] == "authentication failed"
    bad_incident = client.post(
        "/v1/investigations",
        headers=_headers(request_id="api-bad-incident"),
        json={**_payload(), "incident_id": "bad incident id"},
    )
    assert bad_incident.status_code == 422
    bad_tenant = client.get(
        "/v1/tenants/bad tenant", headers=_headers(request_id="api-bad-tenant")
    )
    assert bad_tenant.status_code == 422
    malformed_request_id = client.post(
        "/v1/investigations",
        headers=_headers(request_id="bad request id"),
        json=_payload(),
    )
    assert malformed_request_id.status_code == 401
    oversized_auth = client.post(
        "/v1/investigations",
        headers={
            "Authorization": f"Bearer {'x' * 17_000}",
            "X-Request-ID": "api-oversized-auth",
        },
        json=_payload(),
    )
    assert oversized_auth.status_code == 401


def test_authorization_dependency_failures_return_503() -> None:
    bundle = create_app(mode=AppMode.DEMO).state.runtime

    class _UnavailablePolicy:
        def authorize(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            raise IdentityUnavailable("policy backend offline")

    runtime = ApiRuntime(
        authenticator=bundle.authenticator,
        governance=bundle.governance,
        policy=_UnavailablePolicy(),
        service_for=bundle.service_for,
    )
    client = TestClient(create_app(mode=AppMode.TEST, runtime=runtime))
    response = client.get(
        "/v1/tenants/tenant-acme", headers=_headers(request_id="api-policy-down")
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "authorization service is unavailable"


def test_oversized_body_is_rejected_before_validation() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO, maximum_body_bytes=1_024))
    response = client.post(
        "/v1/investigations",
        headers=_headers(request_id="api-large-body"),
        content=b"x" * 1_025,
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "request body is too large"


def test_endpoint_duplicate_and_conflict() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO))
    headers = _headers(request_id="api-duplicate")
    first = client.post("/v1/investigations", headers=headers, json=_payload())
    duplicate = client.post("/v1/investigations", headers=headers, json=_payload())
    assert first.status_code == duplicate.status_code == 200
    assert duplicate.json()["replayed"] is True
    conflicting_payload = _payload()
    conflicting_payload["incident_id"] = "checkout-20260815-099"
    conflict = client.post(
        "/v1/investigations",
        headers=headers,
        json=conflicting_payload,
    )
    assert conflict.status_code == 409


def test_apps_have_isolated_configurable_demo_budgets() -> None:
    first = TestClient(create_app(mode=AppMode.DEMO, budget_units=5))
    headers = _headers(request_id="api-budget-one")
    assert (
        first.post("/v1/investigations", headers=headers, json=_payload()).json()[
            "status"
        ]
        == "complete"
    )
    exhausted = first.post(
        "/v1/investigations",
        headers=_headers(request_id="api-budget-two"),
        json=_payload(),
    )
    assert exhausted.json()["critic"]["reasons"] == ["tenant_budget_exhausted"]

    fresh = TestClient(create_app(mode=AppMode.DEMO, budget_units=5))
    result = fresh.post(
        "/v1/investigations",
        headers=_headers(request_id="api-budget-fresh"),
        json=_payload(),
    )
    assert result.json()["status"] == "complete"
    with pytest.raises(ValueError, match="at least one"):
        create_app(mode=AppMode.DEMO, budget_units=4)


def test_concurrent_cold_start_cannot_duplicate_budget() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO, budget_units=5))

    def invoke(index: int) -> str:
        response = client.post(
            "/v1/investigations",
            headers=_headers(request_id=f"api-concurrent-{index}"),
            json=_payload(),
        )
        assert response.status_code == 200
        return str(response.json()["status"])

    with ThreadPoolExecutor(max_workers=4) as executor:
        statuses = tuple(executor.map(invoke, range(4)))
    assert statuses.count("complete") == 1
    assert statuses.count("abstained") == 3


def test_cli_demo_and_evals(capsys: object) -> None:
    assert main(["demo", "--request-id", "cli-test"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "complete"
    assert main(["eval", "--cases", "evals/cases.json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["passed"] is True
    for scenario in RemediationDemoScenario:
        assert main(["remediation-demo", "--scenario", scenario.value]) == 0
        remediation = json.loads(capsys.readouterr().out)
        assert remediation["scenario"] == scenario.value
        assert remediation["authority"] == "application-ledger"
        assert remediation["agent_authority"] == "proposal-only"


def test_cli_returns_failure_for_failed_eval(
    tmp_path: Path,
    capsys: object,
) -> None:
    cases = [
        {
            "case_id": "deliberate-mismatch",
            "scenario": "success",
            "expected_status": "abstained",
            "expected_critic": "abstained",
            "expected_reason": "not-present",
        }
    ]
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(cases), encoding="utf-8")
    assert main(["eval", "--cases", str(path)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["passed"] is False


def test_cli_publish_langfuse_requires_optional_extra(
    monkeypatch: object,
    capsys: object,
) -> None:
    def fail() -> object:
        raise OptionalDependencyMissing("langfuse support requires the extra")

    monkeypatch.setattr(
        "aegis_framework.langfuse_adapter.build_langfuse_observability",
        fail,
    )
    with pytest.raises(SystemExit) as excinfo:
        main(["eval", "--cases", "evals/cases.json", "--publish-langfuse"])
    assert excinfo.value.code == 2
    assert "langfuse support requires the extra" in capsys.readouterr().err


def test_cli_serve_passes_safe_defaults(monkeypatch: object) -> None:
    observed: dict[str, object] = {}

    def fake_run(app: str, **kwargs: object) -> None:
        observed["app"] = app
        observed.update(kwargs)

    monkeypatch.setattr("aegis_framework.cli.uvicorn.run", fake_run)
    assert main(["serve", "--port", "8123"]) == 0
    assert observed == {
        "app": "aegis_framework.api:app",
        "host": "127.0.0.1",
        "port": 8123,
        "access_log": False,
    }
