"""Strict production-foundation contracts and deterministic recovery evidence."""

from __future__ import annotations

import json
from collections import defaultdict
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from aegis_framework.domain import Identifier, Sha256Digest, StrictModel
from aegis_framework.errors import IntegrityFailure, PolicyDenied

SecretReference = Annotated[
    str,
    Field(
        min_length=3,
        max_length=253,
        pattern=r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$",
    ),
]
AwsRegion = Annotated[
    str,
    Field(pattern=r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$"),
]


class ProductionComponent(StrEnum):
    API = "api"
    OPERATOR = "operator"
    OUTBOX = "outbox"
    RECONCILER = "reconciler"
    INVESTIGATION = "investigation"
    COGNITIVE = "cognitive"
    EVIDENCE = "evidence"
    REMEDIATION = "remediation"
    MEMORY = "memory"
    SANDBOX = "sandbox"
    PROTOCOL = "protocol"
    PROTOCOL_GATEWAY = "protocol-gateway"


class WorkerCapacity(StrictModel):
    component: ProductionComponent
    task_queue: Identifier
    build_id: Identifier
    replicas: int = Field(ge=2, le=100)
    database_pool_per_replica: int = Field(ge=1, le=50)
    maximum_concurrent_activities: int = Field(ge=1, le=500)
    maximum_concurrent_workflow_tasks: int = Field(ge=1, le=500)
    task_queue_rate_per_second: int = Field(ge=1, le=10_000)


class CapacityPlan(StrictModel):
    database_max_connections: int = Field(ge=100, le=20_000)
    reserved_connections: int = Field(ge=10, le=1_000)
    headroom_percent: int = Field(ge=20, le=70)
    api_replicas: int = Field(ge=2, le=100)
    api_pool_per_replica: int = Field(ge=1, le=50)
    operator_replicas: int = Field(ge=2, le=100)
    operator_pool_per_replica: int = Field(ge=1, le=50)
    workers: tuple[WorkerCapacity, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_capacity(self) -> Self:
        queues = [worker.task_queue for worker in self.workers]
        components = [worker.component for worker in self.workers]
        if len(queues) != len(set(queues)):
            raise ValueError(
                "Temporal task queues must be unique per worker deployment"
            )
        if len(components) != len(set(components)):
            raise ValueError("worker components must be unique")
        used = (
            self.api_replicas * self.api_pool_per_replica
            + self.operator_replicas * self.operator_pool_per_replica
            + sum(
                worker.replicas * worker.database_pool_per_replica
                for worker in self.workers
            )
            + self.reserved_connections
        )
        usable = self.database_max_connections * (100 - self.headroom_percent) // 100
        if used > usable:
            raise ValueError(
                f"database pool budget {used} exceeds guarded capacity {usable}"
            )
        return self

    @property
    def planned_database_connections(self) -> int:
        return (
            self.api_replicas * self.api_pool_per_replica
            + self.operator_replicas * self.operator_pool_per_replica
            + sum(
                worker.replicas * worker.database_pool_per_replica
                for worker in self.workers
            )
            + self.reserved_connections
        )


class TemporalBoundary(StrictModel):
    mode: Literal["temporal-cloud", "self-hosted"]
    address: str = Field(min_length=5, max_length=512)
    namespace: Identifier
    server_name: str = Field(min_length=3, max_length=253)
    client_certificate_secret: SecretReference | None = None
    client_key_secret: SecretReference | None = None
    api_key_secret: SecretReference | None = None
    payload_codec_key_secret: SecretReference
    visibility_retention_days: int = Field(ge=7, le=90)
    schedule_to_start_alert_seconds: int = Field(ge=5, le=300)
    worker_versioning_required: Literal[True]
    encrypted_payloads_required: Literal[True]
    custom_search_attributes: tuple[()] = ()

    @model_validator(mode="after")
    def validate_temporal_boundary(self) -> Self:
        if self.namespace == "default":
            raise ValueError("production Temporal namespace must not be default")
        if (self.client_certificate_secret is None) != (self.client_key_secret is None):
            raise ValueError("Temporal mTLS secret references must be paired")
        if (
            self.mode == "temporal-cloud"
            and self.api_key_secret is None
            and self.client_certificate_secret is None
        ):
            raise ValueError(
                "Temporal Cloud requires API-key or mTLS secret references"
            )
        if any(
            value.startswith(("http://", "https://"))
            for value in (self.address, self.server_name)
        ):
            raise ValueError(
                "Temporal endpoints must be host:port and TLS server names"
            )
        return self


class RetentionPlan(StrictModel):
    application_ledger: Literal["policy-bound-archive-no-framework-deletion"]
    projection_days: int = Field(ge=7, le=365)
    temporal_visibility_days: int = Field(ge=7, le=90)
    langgraph_checkpoint_days: int = Field(ge=1, le=30)
    telemetry_days: int = Field(ge=1, le=90)
    backup_days: int = Field(ge=35, le=365)
    legal_hold_blocks_deletion: Literal[True]


class RegionTopology(StrictModel):
    home_region: AwsRegion
    writer_region: AwsRegion
    standby_regions: tuple[AwsRegion, ...] = Field(min_length=1, max_length=3)
    generation: int = Field(ge=1)
    ledger_mode: Literal["single-writer-home-region"]
    temporal_namespace_strategy: Literal["one-namespace-per-region"]
    regional_edges_stateless: Literal[True]

    @model_validator(mode="after")
    def validate_regions(self) -> Self:
        if self.writer_region != self.home_region:
            raise ValueError("normal topology writer must be the declared home region")
        if self.home_region in self.standby_regions:
            raise ValueError("home region cannot also be a standby")
        if len(self.standby_regions) != len(set(self.standby_regions)):
            raise ValueError("standby regions must be unique")
        return self


class FailoverAuthorization(StrictModel):
    source_region: AwsRegion
    target_region: AwsRegion
    expected_generation: int = Field(ge=1)
    next_generation: int = Field(ge=2)
    approval_ref: Identifier
    fence_digest: Sha256Digest
    source_writer_fenced: Literal[True]
    database_restore_verified: Literal[True]
    ledger_hashes_verified: Literal[True]
    temporal_operations_reconciled: Literal[True]

    @model_validator(mode="after")
    def validate_generation(self) -> Self:
        if self.next_generation != self.expected_generation + 1:
            raise ValueError("failover generation must advance exactly once")
        if self.source_region == self.target_region:
            raise ValueError("failover target must differ from source")
        return self


class ActiveRegion(StrictModel):
    region: AwsRegion
    generation: int = Field(ge=1)
    previous_home_region: AwsRegion
    writer_enabled: Literal[True]
    failback_requires_new_generation: Literal[True]


def authorize_failover(
    topology: RegionTopology,
    authorization: FailoverAuthorization,
) -> ActiveRegion:
    """Validate a fenced regional writer transition without performing it."""

    if authorization.expected_generation != topology.generation:
        raise PolicyDenied("failover generation is stale")
    if authorization.source_region != topology.writer_region:
        raise PolicyDenied("failover source is not the current writer")
    if authorization.target_region not in topology.standby_regions:
        raise PolicyDenied("failover target is not an approved standby")
    return ActiveRegion(
        region=authorization.target_region,
        generation=authorization.next_generation,
        previous_home_region=topology.home_region,
        writer_enabled=True,
        failback_requires_new_generation=True,
    )


class RestoreLedgerEvent(StrictModel):
    cursor: int = Field(ge=1)
    aggregate_id: Identifier
    aggregate_sequence: int = Field(ge=1)
    aggregate_previous_hash: Sha256Digest
    tenant_previous_hash: Sha256Digest
    payload_digest: Sha256Digest
    record_hash: Sha256Digest

    def calculated_hash(self) -> str:
        document = self.model_dump(exclude={"record_hash"})
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return sha256(encoded).hexdigest()


class RestoreVerification(StrictModel):
    event_count: int = Field(ge=1)
    aggregate_count: int = Field(ge=1)
    last_cursor: int = Field(ge=1)
    last_tenant_hash: Sha256Digest
    projections_rebuild_required: Literal[True]
    vector_index_rebuild_required: Literal[True]
    langgraph_rebuild_from_ledger_required: Literal[True]
    temporal_reconciliation_required: Literal[True]
    derived_caches_disposable: Literal[True]


def verify_restored_ledger(
    events: tuple[RestoreLedgerEvent, ...],
) -> RestoreVerification:
    """Verify cursor, aggregate sequence, dual chains, and record hashes."""

    if not events:
        raise IntegrityFailure("restore contains no application events")
    aggregate_sequences: dict[str, int] = defaultdict(int)
    aggregate_hashes: dict[str, str] = defaultdict(lambda: "0" * 64)
    tenant_hash = "0" * 64
    for expected_cursor, event in enumerate(events, start=1):
        if event.cursor != expected_cursor:
            raise IntegrityFailure("restored tenant cursor is not contiguous")
        expected_sequence = aggregate_sequences[event.aggregate_id] + 1
        if event.aggregate_sequence != expected_sequence:
            raise IntegrityFailure("restored aggregate sequence is not contiguous")
        if event.aggregate_previous_hash != aggregate_hashes[event.aggregate_id]:
            raise IntegrityFailure("restored aggregate hash chain is invalid")
        if event.tenant_previous_hash != tenant_hash:
            raise IntegrityFailure("restored tenant hash chain is invalid")
        if event.record_hash != event.calculated_hash():
            raise IntegrityFailure("restored event record hash is invalid")
        aggregate_sequences[event.aggregate_id] = event.aggregate_sequence
        aggregate_hashes[event.aggregate_id] = event.record_hash
        tenant_hash = event.record_hash
    return RestoreVerification(
        event_count=len(events),
        aggregate_count=len(aggregate_sequences),
        last_cursor=events[-1].cursor,
        last_tenant_hash=tenant_hash,
        projections_rebuild_required=True,
        vector_index_rebuild_required=True,
        langgraph_rebuild_from_ledger_required=True,
        temporal_reconciliation_required=True,
        derived_caches_disposable=True,
    )
