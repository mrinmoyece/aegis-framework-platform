"""Fail-closed production worker bootstrap and probe coordination."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Sequence
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import Protocol, cast

from aegis_framework.domain import Identifier

_ENTRY_POINT_GROUP = "aegis_framework.production_worker"
_REQUIRED_ENVIRONMENT = (
    "AEGIS_DEPLOYMENT_GENERATION",
    "AEGIS_LANGGRAPH_AUTOMATIC_TRACING",
    "AEGIS_LANGGRAPH_GRAPH_VERSION",
    "AEGIS_LEDGER_WRITER_MODE",
    "AEGIS_POSTGRES_DSN",
    "AEGIS_TEMPORAL_ADDRESS",
    "AEGIS_TEMPORAL_NAMESPACE",
    "AEGIS_TEMPORAL_PAYLOAD_CODEC_KEY",
    "AEGIS_TEMPORAL_PAYLOAD_ENCRYPTION",
    "AEGIS_TEMPORAL_TASK_QUEUE_PREFIX",
    "AEGIS_TEMPORAL_TLS_SERVER_NAME",
    "AEGIS_TEMPORAL_WORKER_KIND",
    "AEGIS_TEMPORAL_WORKER_VERSIONING",
    "AEGIS_TELEMETRY_ATTRIBUTES",
    "AEGIS_WORKER_BUILD_ID",
)
_REQUIRED_VALUES = {
    "AEGIS_LANGGRAPH_AUTOMATIC_TRACING": "disabled",
    "AEGIS_LANGGRAPH_GRAPH_VERSION": "6.0.0",
    "AEGIS_LEDGER_WRITER_MODE": "single-home-region",
    "AEGIS_TEMPORAL_PAYLOAD_ENCRYPTION": "required",
    "AEGIS_TEMPORAL_WORKER_VERSIONING": "required",
    "AEGIS_TELEMETRY_ATTRIBUTES": "allowlist-only",
}
_TEMPORAL_CERT_PATHS = {
    "AEGIS_TEMPORAL_SERVER_CA_CERT_PATH": "Temporal CA certificate",
    "AEGIS_TEMPORAL_CLIENT_CERTIFICATE_PATH": "Temporal client certificate",
    "AEGIS_TEMPORAL_CLIENT_KEY_PATH": "Temporal client private key",
}


class WorkerBootstrap(Protocol):
    def __call__(
        self,
        *,
        profile: str,
        task_queue: str,
        control: WorkerControl,
    ) -> int: ...


class WorkerControl:
    """Coordinate readiness, liveness, and drain without exposing payloads."""

    def __init__(self, runtime_directory: Path) -> None:
        self._runtime_directory = runtime_directory
        self._runtime_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self._runtime_directory.is_symlink():
            raise ValueError("worker runtime directory cannot be a symlink")

    def mark_started(self) -> None:
        self._write("started")
        self.heartbeat()

    def mark_ready(self) -> None:
        if self.drain_requested:
            raise RuntimeError("draining worker cannot become ready")
        self._write("ready")

    def heartbeat(self) -> None:
        self._write("heartbeat")

    def request_drain(self) -> None:
        self._path("drained").unlink(missing_ok=True)
        self._write("draining")
        self._path("ready").unlink(missing_ok=True)

    def mark_drained(self) -> None:
        if not self.drain_requested:
            raise RuntimeError("worker cannot complete an unrequested drain")
        self._write("drained")

    def wait_for_drain(self, *, timeout_seconds: int) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self._path("drained").is_file():
                return True
            time.sleep(0.1)
        return self._path("drained").is_file()

    @property
    def drain_requested(self) -> bool:
        return self._path("draining").is_file()

    def healthy(self, kind: str, *, now: float | None = None) -> bool:
        if kind == "startup":
            return self._path("started").is_file()
        if kind == "ready":
            return self._path("ready").is_file() and not self.drain_requested
        if kind != "live":
            raise ValueError("worker health kind is invalid")
        heartbeat = self._path("heartbeat")
        if not self._path("started").is_file() or not heartbeat.is_file():
            return False
        observed = time.time() if now is None else now
        return 0 <= observed - heartbeat.stat().st_mtime <= 45

    def _path(self, name: str) -> Path:
        return self._runtime_directory / name

    def _write(self, name: str) -> None:
        path = self._path(name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        os.close(descriptor)


def run_production_worker(
    *,
    profile: Identifier,
    task_queue: Identifier,
    runtime_directory: Path,
    environment: dict[str, str] | None = None,
    discover: Callable[[], Sequence[EntryPoint]] | None = None,
) -> int:
    """Load one attested enterprise bootstrap; never fall back to a fake worker."""

    selected_environment = dict(os.environ) if environment is None else environment
    missing = [
        name for name in _REQUIRED_ENVIRONMENT if not selected_environment.get(name)
    ]
    api_key = selected_environment.get("AEGIS_TEMPORAL_API_KEY") or None
    certificate = selected_environment.get("AEGIS_TEMPORAL_CLIENT_CERTIFICATE") or None
    private_key = selected_environment.get("AEGIS_TEMPORAL_CLIENT_KEY") or None
    certificate_path = (
        selected_environment.get("AEGIS_TEMPORAL_CLIENT_CERTIFICATE_PATH") or None
    )
    private_key_path = (
        selected_environment.get("AEGIS_TEMPORAL_CLIENT_KEY_PATH") or None
    )
    if not api_key and not (
        (certificate and private_key) or (certificate_path and private_key_path)
    ):
        missing.append("AEGIS_TEMPORAL_API_KEY or client certificate/key")
    if missing:
        raise RuntimeError("production worker prerequisites are unavailable")
    if selected_environment["AEGIS_TEMPORAL_NAMESPACE"] == "default":
        raise RuntimeError("production Temporal namespace cannot be default")
    if any(
        selected_environment.get(name) != expected
        for name, expected in _REQUIRED_VALUES.items()
    ):
        raise RuntimeError("production worker enforcement settings are invalid")
    prefix = selected_environment["AEGIS_TEMPORAL_TASK_QUEUE_PREFIX"]
    worker_kind = selected_environment["AEGIS_TEMPORAL_WORKER_KIND"]
    if not task_queue.startswith(f"{prefix}-{worker_kind}-"):
        raise RuntimeError("Temporal task queue is outside the deployment prefix")
    try:
        generation = int(selected_environment["AEGIS_DEPLOYMENT_GENERATION"])
    except ValueError as exc:
        raise RuntimeError("deployment generation is invalid") from exc
    if generation < 1:
        raise RuntimeError("deployment generation is invalid")
    _validate_temporal_transport(
        api_key=api_key,
        tls_server_name=selected_environment["AEGIS_TEMPORAL_TLS_SERVER_NAME"],
        inline_certificate=certificate,
        inline_private_key=private_key,
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        server_ca_path=selected_environment.get("AEGIS_TEMPORAL_SERVER_CA_CERT_PATH")
        or None,
    )

    provider = discover or (
        lambda: tuple(entry_points(group=_ENTRY_POINT_GROUP, name="aegis"))
    )
    candidates = tuple(provider())
    if len(candidates) != 1:
        raise RuntimeError("exactly one production worker bootstrap is required")
    loaded = candidates[0].load()
    if not callable(loaded):
        raise RuntimeError("production worker bootstrap is not callable")
    bootstrap = cast(WorkerBootstrap, loaded)
    control = WorkerControl(runtime_directory)
    # Clear any stale state files left by a previous container instance in the
    # same emptyDir volume before marking this instance as started.
    for stale in ("started", "ready", "heartbeat", "draining", "drained"):
        (runtime_directory / stale).unlink(missing_ok=True)
    control.mark_started()
    result = bootstrap(profile=profile, task_queue=task_queue, control=control)
    if control.drain_requested:
        control.mark_drained()
    return result


def _validate_temporal_transport(
    *,
    api_key: str | None,
    tls_server_name: str,
    inline_certificate: str | None,
    inline_private_key: str | None,
    certificate_path: str | None,
    private_key_path: str | None,
    server_ca_path: str | None,
) -> None:
    if not tls_server_name or tls_server_name.startswith(("http://", "https://")):
        raise RuntimeError("Temporal TLS server name is invalid")
    if (inline_certificate is None) != (inline_private_key is None):
        raise RuntimeError("Temporal mTLS credentials must be paired")
    if (certificate_path is None) != (private_key_path is None):
        raise RuntimeError("Temporal mTLS certificate paths must be paired")
    if inline_certificate and certificate_path:
        raise RuntimeError("Temporal mTLS credentials are ambiguous")
    if api_key is None and inline_certificate is None and certificate_path is None:
        raise RuntimeError("Temporal authenticated transport is unavailable")
    for name, label in _TEMPORAL_CERT_PATHS.items():
        value = {
            "AEGIS_TEMPORAL_SERVER_CA_CERT_PATH": server_ca_path,
            "AEGIS_TEMPORAL_CLIENT_CERTIFICATE_PATH": certificate_path,
            "AEGIS_TEMPORAL_CLIENT_KEY_PATH": private_key_path,
        }[name]
        if value is not None:
            _validate_secret_file(Path(value), label=label)


def _validate_secret_file(path: Path, *, label: str) -> None:
    if not path.is_absolute():
        raise RuntimeError(f"{label} path must be absolute")
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} path must reference a regular file")
    if path.stat().st_size < 1:
        raise RuntimeError(f"{label} path must not be empty")
