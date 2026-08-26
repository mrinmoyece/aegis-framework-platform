from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegis_framework.api import AppMode, create_app
from aegis_framework.operator_api import (
    OperatorSecurityHeadersMiddleware,
    install_operator_ui,
)


def _login(client: TestClient) -> dict[str, object]:
    start = client.post("/operator/session/authorization")
    assert start.status_code == 200
    assert start.headers["content-type"].startswith("application/json")
    body = start.json()
    callback = client.post(
        "/operator/session/callback",
        json={
            "code": "deterministic-demo-code",
            "state": body["state"],
        },
    )
    assert callback.status_code == 200
    assert callback.headers["content-type"].startswith("application/json")
    assert callback.cookies.get("__Host-aegis-session")
    return callback.json()


def test_operator_production_boundary_fails_closed() -> None:
    client = TestClient(
        create_app(mode=AppMode.PRODUCTION), base_url="https://testserver"
    )
    readiness = client.get("/operator/readyz")
    assert readiness.status_code == 503
    assert readiness.json()["detail"] == {
        "status": "not_ready",
        "oidc_exchange": False,
        "durable_session_store": False,
    }
    assert client.post("/operator/session/authorization").status_code == 503
    assert client.get("/operator/api/snapshot").status_code == 503


def test_operator_oidc_emulator_rotates_session_and_rejects_replay() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO), base_url="https://testserver")
    start = client.post("/operator/session/authorization").json()
    first = client.post(
        "/operator/session/callback",
        json={
            "code": "deterministic-demo-code",
            "state": start["state"],
        },
    )
    assert first.status_code == 200
    token = first.cookies["__Host-aegis-session"]
    assert token not in first.text
    replay = client.post(
        "/operator/session/callback",
        json={
            "code": "deterministic-demo-code",
            "state": start["state"],
        },
    )
    assert replay.status_code == 401
    invalid = client.post(
        "/operator/session/callback",
        json={"code": "wrong-code", "state": "x" * 43},
    )
    assert invalid.status_code == 401


def test_operator_cookie_headers_and_bounded_snapshot() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO), base_url="https://testserver")
    session = _login(client)
    response = client.get("/operator/api/snapshot")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["strict-transport-security"].startswith("max-age=63072000")
    assert response.headers["x-csp-nonce"]
    snapshot = response.json()
    assert snapshot["synthetic"] is True
    assert snapshot["tenant_id"] == session["tenant_id"]
    assert snapshot["session_generation"] == session["session_generation"]
    assert len(snapshot["incidents"]) == 1
    assert len(snapshot["timeline"]) <= 200
    assert session["tenant_id"] == "tenant-acme"
    assert "bearer" not in response.text.lower()
    assert "tenant_id" not in snapshot["evidence"][0]


def test_operator_csrf_origin_and_tenant_teardown_contract() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO), base_url="https://testserver")
    session = _login(client)
    denied = client.post(
        "/operator/session/tenant",
        json={"tenant_id": "tenant-beta"},
        headers={"Origin": "https://testserver"},
    )
    assert denied.status_code == 403
    cross_origin = client.post(
        "/operator/session/tenant",
        json={"tenant_id": "tenant-beta"},
        headers={
            "Origin": "https://evil.invalid",
            "X-CSRF-Token": session["csrf_token"],
        },
    )
    assert cross_origin.status_code == 403
    host_header_bypass = client.post(
        "/operator/session/tenant",
        json={"tenant_id": "tenant-beta"},
        headers={
            "Host": "evil.invalid",
            "Origin": "https://evil.invalid",
            "X-CSRF-Token": session["csrf_token"],
        },
    )
    assert host_header_bypass.status_code == 403
    switched = client.post(
        "/operator/session/tenant",
        json={"tenant_id": "tenant-beta"},
        headers={
            "Origin": "https://testserver",
            "X-CSRF-Token": session["csrf_token"],
        },
    )
    assert switched.status_code == 200
    rotated = switched.json()
    assert rotated["tenant_id"] == "tenant-beta"
    assert rotated["csrf_token"] != session["csrf_token"]
    assert client.get("/operator/api/snapshot").json()["incidents"] == []
    unknown = client.post(
        "/operator/session/tenant",
        json={"tenant_id": "tenant-unknown"},
        headers={
            "Origin": "https://testserver",
            "X-CSRF-Token": rotated["csrf_token"],
        },
    )
    assert unknown.status_code == 404


def test_operator_server_denial_and_ambiguity_are_explicit() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO), base_url="https://testserver")
    session = _login(client)
    snapshot = client.get("/operator/api/snapshot").json()
    approval = snapshot["approvals"][0]
    receipt = client.post(
        f"/operator/api/approvals/{approval['approval_id']}/decisions",
        headers={
            "Origin": "https://testserver",
            "X-CSRF-Token": session["csrf_token"],
            "Idempotency-Key": "decision-001",
        },
        json={
            "command_id": "decision-001",
            "disposition": "grant",
            "rationale": "Independent exact-scope review for the synthetic checkout.",
            "expected_status": "pending",
            "plan_digest": approval["plan_digest"],
            "approval_digest": approval["approval_digest"],
            "typed_confirmation": "APPROVE CHECKOUT-API",
        },
    )
    assert receipt.status_code == 200
    assert receipt.json()["outcome"] == "denied"
    assert approval["can_decide"] is False
    ambiguous = next(
        effect for effect in snapshot["effects"] if effect["status"] == "ambiguous"
    )
    assert ambiguous["verification"] == "ambiguous"


def test_operator_injection_is_returned_only_as_bounded_data() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO), base_url="https://testserver")
    _login(client)
    snapshot = client.get("/operator/api/snapshot").json()
    hostile = next(
        item for item in snapshot["evidence"] if "<script>" in item["summary"]
    )
    assert hostile["disposition"] == "accepted"
    assert len(hostile["summary"]) <= 300


def test_operator_protocol_trust_requires_exact_pins_and_confirmation() -> None:
    client = TestClient(create_app(mode=AppMode.DEMO), base_url="https://testserver")
    session = _login(client)
    peer = client.get("/operator/api/snapshot").json()["protocol_peers"][0]
    stale = client.post(
        f"/operator/api/protocol-peers/{peer['peer_id']}/trust",
        headers={
            "Origin": "https://testserver",
            "X-CSRF-Token": session["csrf_token"],
            "Idempotency-Key": "trust-stale",
        },
        json={
            "command_id": "trust-stale",
            "action": "quarantine",
            "expected_revision": peer["revision"] + 1,
            "expected_card_digest": peer["card_digest"],
            "expected_schema_digest": peer["schema_digest"],
            "expected_certificate_digest": peer["certificate_digest"],
            "expected_key_digest": peer["key_digest"],
            "rationale": "Peer behavior requires immediate containment review.",
            "typed_confirmation": f"QUARANTINE {peer['peer_id']}",
        },
    )
    assert stale.status_code == 409
    wrong = client.post(
        f"/operator/api/protocol-peers/{peer['peer_id']}/trust",
        headers={
            "Origin": "https://testserver",
            "X-CSRF-Token": session["csrf_token"],
        },
        json={
            "command_id": "trust-wrong",
            "action": "quarantine",
            "expected_revision": peer["revision"],
            "expected_card_digest": peer["card_digest"],
            "expected_schema_digest": peer["schema_digest"],
            "expected_certificate_digest": peer["certificate_digest"],
            "expected_key_digest": peer["key_digest"],
            "rationale": "Peer behavior requires immediate containment review.",
            "typed_confirmation": "QUARANTINE wrong-peer",
        },
    )
    assert wrong.status_code == 422
    accepted = client.post(
        f"/operator/api/protocol-peers/{peer['peer_id']}/trust",
        headers={
            "Origin": "https://testserver",
            "X-CSRF-Token": session["csrf_token"],
            "Idempotency-Key": "trust-accepted",
        },
        json={
            "command_id": "trust-accepted",
            "action": "quarantine",
            "expected_revision": peer["revision"],
            "expected_card_digest": peer["card_digest"],
            "expected_schema_digest": peer["schema_digest"],
            "expected_certificate_digest": peer["certificate_digest"],
            "expected_key_digest": peer["key_digest"],
            "rationale": "Peer behavior requires immediate containment review.",
            "typed_confirmation": f"QUARANTINE {peer['peer_id']}",
        },
    )
    assert accepted.status_code == 200
    assert accepted.json()["outcome"] == "accepted"
    refreshed = client.get("/operator/api/snapshot").json()["protocol_peers"][0]
    assert refreshed["status"] == "quarantined"
    assert refreshed["revision"] == peer["revision"] + 1
    cannot_reactivate = client.post(
        f"/operator/api/protocol-peers/{peer['peer_id']}/trust",
        headers={
            "Origin": "https://testserver",
            "X-CSRF-Token": session["csrf_token"],
        },
        json={
            "command_id": "trust-reactivate",
            "action": "review",
            "expected_revision": refreshed["revision"],
            "expected_card_digest": refreshed["card_digest"],
            "expected_schema_digest": refreshed["schema_digest"],
            "expected_certificate_digest": refreshed["certificate_digest"],
            "expected_key_digest": refreshed["key_digest"],
            "rationale": "Quarantined peers require a new pending registry revision.",
            "typed_confirmation": f"TRUST {peer['peer_id']}",
        },
    )
    assert cannot_reactivate.status_code == 409


def test_operator_static_delivery_is_bounded_and_cache_aware(tmp_path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><title>Aegis</title>")
    (assets / "app-abc123.js").write_text("export {};")
    app = FastAPI()
    app.add_middleware(OperatorSecurityHeadersMiddleware)
    install_operator_ui(app, directory=tmp_path)
    client = TestClient(app, base_url="https://testserver")

    root = client.get("/")
    assert root.status_code == 200
    assert root.headers["cache-control"] == "no-store, max-age=0"
    assert client.get("/approvals").status_code == 200
    asset = client.get("/assets/app-abc123.js")
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert client.get("/unknown").status_code == 404
