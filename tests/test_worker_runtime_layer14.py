from __future__ import annotations

import os
from pathlib import Path
from threading import Thread
from time import sleep

import pytest

from aegis_framework.cli import main
from aegis_framework.worker_runtime import WorkerControl, run_production_worker


class _EntryPoint:
    def __init__(self, loaded: object) -> None:
        self._loaded = loaded

    def load(self) -> object:
        return self._loaded


def _environment() -> dict[str, str]:
    return {
        "AEGIS_DEPLOYMENT_GENERATION": "1",
        "AEGIS_LANGGRAPH_AUTOMATIC_TRACING": "disabled",
        "AEGIS_LANGGRAPH_GRAPH_VERSION": "6.0.0",
        "AEGIS_LEDGER_WRITER_MODE": "single-home-region",
        "AEGIS_POSTGRES_DSN": "postgresql://reference.invalid/aegis",
        "AEGIS_TEMPORAL_ADDRESS": "private.example.invalid:7233",
        "AEGIS_TEMPORAL_NAMESPACE": "aegis-production",
        "AEGIS_TEMPORAL_PAYLOAD_CODEC_KEY": "injected-secret",
        "AEGIS_TEMPORAL_PAYLOAD_ENCRYPTION": "required",
        "AEGIS_TEMPORAL_TASK_QUEUE_PREFIX": "aegis-production",
        "AEGIS_TEMPORAL_TLS_SERVER_NAME": "private.example.invalid",
        "AEGIS_TEMPORAL_API_KEY": "injected-secret",
        "AEGIS_TEMPORAL_WORKER_KIND": "investigation",
        "AEGIS_TEMPORAL_WORKER_VERSIONING": "required",
        "AEGIS_TELEMETRY_ATTRIBUTES": "allowlist-only",
        "AEGIS_WORKER_BUILD_ID": "aegis-0.14.0-build-001",
    }


def test_worker_control_tracks_start_ready_heartbeat_and_drain(tmp_path: Path) -> None:
    control = WorkerControl(tmp_path)
    assert control.healthy("startup") is False
    with pytest.raises(RuntimeError, match="unrequested"):
        control.mark_drained()
    control.mark_started()
    assert control.healthy("startup") is True
    assert control.healthy("live") is True
    control.mark_ready()
    assert control.healthy("ready") is True
    control.request_drain()
    assert control.healthy("ready") is False
    assert control.drain_requested is True
    with pytest.raises(RuntimeError, match="draining"):
        control.mark_ready()
    with pytest.raises(ValueError, match="kind"):
        control.healthy("unknown")


def test_worker_bootstrap_is_exact_and_fail_closed(tmp_path: Path) -> None:
    observed: list[tuple[str, str]] = []

    def bootstrap(
        *,
        profile: str,
        task_queue: str,
        control: WorkerControl,
    ) -> int:
        observed.append((profile, task_queue))
        control.mark_ready()
        return 0

    result = run_production_worker(
        profile="investigation",
        task_queue="aegis-production-investigation-v1",
        runtime_directory=tmp_path,
        environment=_environment(),
        discover=lambda: (_EntryPoint(bootstrap),),  # type: ignore[return-value]
    )
    assert result == 0
    assert observed == [
        ("investigation", "aegis-production-investigation-v1"),
    ]
    assert WorkerControl(tmp_path).healthy("ready") is True

    drained_directory = tmp_path / "drained-worker"

    def draining_bootstrap(
        *,
        profile: str,
        task_queue: str,
        control: WorkerControl,
    ) -> int:
        del profile, task_queue
        control.request_drain()
        return 0

    assert (
        run_production_worker(
            profile="investigation",
            task_queue="aegis-production-investigation-v1",
            runtime_directory=drained_directory,
            environment=_environment(),
            discover=lambda: (_EntryPoint(draining_bootstrap),),  # type: ignore[return-value]
        )
        == 0
    )
    assert WorkerControl(drained_directory).wait_for_drain(timeout_seconds=0)

    with pytest.raises(RuntimeError, match="prerequisites"):
        run_production_worker(
            profile="investigation",
            task_queue="aegis-production-investigation-v1",
            runtime_directory=tmp_path,
            environment={},
            discover=lambda: (),
        )
    with pytest.raises(RuntimeError, match="namespace"):
        run_production_worker(
            profile="investigation",
            task_queue="aegis-production-investigation-v1",
            runtime_directory=tmp_path,
            environment={**_environment(), "AEGIS_TEMPORAL_NAMESPACE": "default"},
            discover=lambda: (),
        )
    with pytest.raises(RuntimeError, match="exactly one"):
        run_production_worker(
            profile="investigation",
            task_queue="aegis-production-investigation-v1",
            runtime_directory=tmp_path,
            environment=_environment(),
            discover=lambda: (),
        )
    with pytest.raises(RuntimeError, match="enforcement"):
        run_production_worker(
            profile="investigation",
            task_queue="aegis-production-investigation-v1",
            runtime_directory=tmp_path,
            environment={
                **_environment(),
                "AEGIS_TEMPORAL_PAYLOAD_ENCRYPTION": "optional",
            },
            discover=lambda: (),
        )
    with pytest.raises(RuntimeError, match="task queue"):
        run_production_worker(
            profile="investigation",
            task_queue="other-investigation-v1",
            runtime_directory=tmp_path,
            environment=_environment(),
            discover=lambda: (),
        )
    with pytest.raises(RuntimeError, match="generation"):
        run_production_worker(
            profile="investigation",
            task_queue="aegis-production-investigation-v1",
            runtime_directory=tmp_path,
            environment={**_environment(), "AEGIS_DEPLOYMENT_GENERATION": "zero"},
            discover=lambda: (),
        )
    certificate_path = tmp_path / "temporal-client.pem"
    private_key_path = tmp_path / "temporal-client.key"
    certificate_path.write_text("certificate", encoding="utf-8")
    private_key_path.write_text("private-key", encoding="utf-8")
    observed.clear()
    assert (
        run_production_worker(
            profile="investigation",
            task_queue="aegis-production-investigation-v1",
            runtime_directory=tmp_path / "mtls-path",
            environment={
                **_environment(),
                "AEGIS_TEMPORAL_API_KEY": "",
                "AEGIS_TEMPORAL_CLIENT_CERTIFICATE_PATH": os.fspath(certificate_path),
                "AEGIS_TEMPORAL_CLIENT_KEY_PATH": os.fspath(private_key_path),
            },
            discover=lambda: (_EntryPoint(bootstrap),),  # type: ignore[return-value]
        )
        == 0
    )
    with pytest.raises(RuntimeError, match="absolute"):
        run_production_worker(
            profile="investigation",
            task_queue="aegis-production-investigation-v1",
            runtime_directory=tmp_path,
            environment={
                **_environment(),
                "AEGIS_TEMPORAL_API_KEY": "",
                "AEGIS_TEMPORAL_CLIENT_CERTIFICATE_PATH": "relative-cert.pem",
                "AEGIS_TEMPORAL_CLIENT_KEY_PATH": os.fspath(private_key_path),
            },
            discover=lambda: (),
        )
    with pytest.raises(RuntimeError, match="server name"):
        run_production_worker(
            profile="investigation",
            task_queue="aegis-production-investigation-v1",
            runtime_directory=tmp_path,
            environment={
                **_environment(),
                "AEGIS_TEMPORAL_TLS_SERVER_NAME": "https://private.example.invalid",
            },
            discover=lambda: (),
        )


def test_worker_probe_and_drain_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_WORKER_RUNTIME_DIR", os.fspath(tmp_path))
    control = WorkerControl(tmp_path)
    control.mark_started()
    control.mark_ready()
    assert main(["worker-health", "--kind", "ready"]) == 0

    def complete_drain() -> None:
        while not control.drain_requested:
            sleep(0.01)
        control.mark_drained()

    thread = Thread(target=complete_drain)
    thread.start()
    assert main(["worker-drain", "--timeout-seconds", "1"]) == 0
    thread.join()
    assert main(["worker-health", "--kind", "ready"]) == 1
    assert main(["worker-drain", "--timeout-seconds", "0"]) == 2
    monkeypatch.setattr(
        "aegis_framework.worker_runtime.run_production_worker",
        lambda **_: (_ for _ in ()).throw(RuntimeError("unavailable")),
    )
    assert (
        main(
            [
                "worker",
                "--profile",
                "evidence",
                "--task-queue",
                "aegis-production-evidence-v1",
            ]
        )
        == 78
    )
