from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_framework.api import create_app
from aegis_framework.cli import main
from aegis_framework.fixtures import demo_request


def _headers(
    *,
    request_id: str,
    roles: str = "incident-responder",
) -> dict[str, str]:
    return {
        "X-Tenant-ID": "tenant-acme",
        "X-Subject-ID": "responder-alice",
        "X-Roles": roles,
        "X-Request-ID": request_id,
    }


def _payload(scenario: str = "success") -> dict[str, object]:
    request = demo_request()
    return {
        "scenario": scenario,
        "incident_id": request.incident_id,
        "alert": request.alert.model_dump(mode="json"),
    }


def test_health_and_success_endpoint() -> None:
    client = TestClient(create_app())
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json() == {
        "status": "ok",
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


def test_endpoint_denial_and_validation() -> None:
    client = TestClient(create_app())
    denied = client.post(
        "/v1/investigations",
        headers=_headers(request_id="api-denied", roles="incident-viewer"),
        json=_payload(),
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "investigation is not authorized"
    missing_identity = client.post("/v1/investigations", json=_payload())
    assert missing_identity.status_code == 422
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
            "X-Tenant-ID": "tenant acme!",
        },
        json=_payload(),
    )
    assert bad_identity.status_code == 422
    assert bad_identity.json()["detail"] == "identity headers are invalid"
    bad_incident = client.post(
        "/v1/investigations",
        headers=_headers(request_id="api-bad-incident"),
        json={**_payload(), "incident_id": "bad incident id"},
    )
    assert bad_incident.status_code == 422


def test_endpoint_duplicate_and_conflict() -> None:
    client = TestClient(create_app())
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
    first = TestClient(create_app(budget_units=5))
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

    fresh = TestClient(create_app(budget_units=5))
    result = fresh.post(
        "/v1/investigations",
        headers=_headers(request_id="api-budget-fresh"),
        json=_payload(),
    )
    assert result.json()["status"] == "complete"
    with pytest.raises(ValueError, match="at least one"):
        create_app(budget_units=4)


def test_concurrent_cold_start_cannot_duplicate_budget() -> None:
    client = TestClient(create_app(budget_units=5))

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
