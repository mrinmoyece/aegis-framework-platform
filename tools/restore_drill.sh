#!/bin/sh
set -eu

POSTGRES_IMAGE='pgvector/pgvector:0.8.6-pg17-bookworm@sha256:cf134a767f474095eeba57e0117be8e568e011a63f33fbf252f14c9b760f8e6f'
CONTAINER="aegis-layer14-restore-$$"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-layer14-restore.XXXXXX")"
REPORT="${AEGIS_RESTORE_REPORT:-build/restore-drill-db.json}"
ADMIN_PASSWORD="$(openssl rand -hex 32)"
RUNTIME_PASSWORD="$(openssl rand -hex 32)"

uv_run() {
  if command -v uv >/dev/null 2>&1; then
    uv run "$@"
  else
    python3 -m uv run "$@"
  fi
}

cleanup() {
  docker rm --force "${CONTAINER}" >/dev/null 2>&1 || true
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$(dirname "${REPORT}")"
docker run --detach --rm \
  --name "${CONTAINER}" \
  --env POSTGRES_DB=aegis \
  --env POSTGRES_USER=aegis_admin \
  --env POSTGRES_PASSWORD="${ADMIN_PASSWORD}" \
  --env AEGIS_POSTGRES_RUNTIME_PASSWORD="${RUNTIME_PASSWORD}" \
  --publish 127.0.0.1::5432 \
  --mount "type=bind,source=${PWD}/migrations,target=/opt/aegis/migrations,readonly" \
  --mount "type=bind,source=${PWD}/tools/postgres-init.sh,target=/docker-entrypoint-initdb.d/010-aegis.sh,readonly" \
  "${POSTGRES_IMAGE}" >/dev/null

ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if docker exec "${CONTAINER}" pg_isready -U aegis_admin -d aegis >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
if [ "${ready}" != "true" ]; then
  docker logs "${CONTAINER}" >&2
  exit 1
fi

PORT="$(docker port "${CONTAINER}" 5432/tcp | sed 's/.*://')"
ADMIN_DSN="postgresql://aegis_admin:${ADMIN_PASSWORD}@127.0.0.1:${PORT}"
AEGIS_MIGRATIONS_DIR="${PWD}/migrations" \
AEGIS_RESTORE_DSN="${ADMIN_DSN}/aegis" \
  uv_run python -c \
  "import os; from aegis_framework.postgres import setup_postgres; setup_postgres(admin_dsn=os.environ['AEGIS_RESTORE_DSN'])"

HASHES="$(
  uv_run python - <<'PY'
from datetime import UTC, datetime
from hashlib import sha256
from aegis_framework.durability import EventDraft, event_material

zero = "0" * 64
first = EventDraft(
    event_id="event:restore:1",
    event_type="investigation.requested",
    occurred_at=datetime(2026, 8, 18, tzinfo=UTC),
    actor_ref="actor:restore",
    correlation_ref="request:restore",
    payload={
        "incident_id": "incident:restore",
        "request_ref": "request:restore",
        "status": "queued",
        "workflow_id": "workflow:restore",
    },
)
first_hash = sha256(event_material(
    tenant_id="restore-tenant",
    aggregate_type="investigation",
    aggregate_id="run:restore",
    aggregate_sequence=1,
    tenant_cursor=1,
    draft=first,
    aggregate_previous_hash=zero,
    tenant_previous_hash=zero,
).encode()).hexdigest()
second = EventDraft(
    event_id="event:restore:2",
    event_type="investigation.completed",
    occurred_at=datetime(2026, 8, 18, 0, 0, 1, tzinfo=UTC),
    actor_ref="actor:restore",
    correlation_ref="request:restore",
    causation_ref="event:restore:1",
    payload={
        "incident_id": "incident:restore",
        "request_ref": "request:restore",
        "status": "completed",
        "workflow_id": "workflow:restore",
    },
)
second_hash = sha256(event_material(
    tenant_id="restore-tenant",
    aggregate_type="investigation",
    aggregate_id="run:restore",
    aggregate_sequence=2,
    tenant_cursor=2,
    draft=second,
    aggregate_previous_hash=first_hash,
    tenant_previous_hash=first_hash,
).encode()).hexdigest()
print(first_hash, second_hash)
PY
)"
set -- ${HASHES}
HASH_ONE="$1"
HASH_TWO="$2"

docker exec --interactive "${CONTAINER}" \
  psql --set=ON_ERROR_STOP=1 --username aegis_admin --dbname aegis >/dev/null <<SQL
INSERT INTO aegis.tenants (tenant_id, display_name, status)
VALUES ('restore-tenant', 'Restore drill', 'active');
INSERT INTO aegis.ledger_aggregate_heads (
  tenant_id, aggregate_type, aggregate_id, last_sequence, last_hash
) VALUES (
  'restore-tenant', 'investigation', 'run:restore', 2, '${HASH_TWO}'
);
INSERT INTO aegis.ledger_tenant_cursors (tenant_id, last_cursor, last_hash)
VALUES ('restore-tenant', 2, '${HASH_TWO}');
INSERT INTO aegis.application_events (
  tenant_id, aggregate_type, aggregate_id, aggregate_sequence, tenant_cursor,
  event_id, event_type, occurred_at, actor_ref, correlation_ref, causation_ref,
  schema_version, payload, aggregate_previous_hash, tenant_previous_hash, record_hash
) VALUES
(
  'restore-tenant', 'investigation', 'run:restore', 1, 1,
  'event:restore:1', 'investigation.requested', '2026-08-18T00:00:00Z',
  'actor:restore', 'request:restore', NULL, 1,
  '{"incident_id":"incident:restore","request_ref":"request:restore","status":"queued","workflow_id":"workflow:restore"}',
  repeat('0', 64), repeat('0', 64), '${HASH_ONE}'
),
(
  'restore-tenant', 'investigation', 'run:restore', 2, 2,
  'event:restore:2', 'investigation.completed', '2026-08-18T00:00:01Z',
  'actor:restore', 'request:restore', 'event:restore:1', 1,
  '{"incident_id":"incident:restore","request_ref":"request:restore","status":"completed","workflow_id":"workflow:restore"}',
  '${HASH_ONE}', '${HASH_ONE}', '${HASH_TWO}'
);
INSERT INTO aegis.investigation_runs (
  tenant_id, run_id, incident_id, request_ref, workflow_id, status,
  version, last_cursor, created_at, updated_at
) VALUES (
  'restore-tenant', 'run:restore', 'incident:restore', 'request:restore',
  'workflow:restore', 'completed', 2, 2,
  '2026-08-18T00:00:00Z', '2026-08-18T00:00:01Z'
);
INSERT INTO aegis.investigation_timeline (
  tenant_id, run_id, tenant_cursor, event_type, status, occurred_at
) VALUES
  ('restore-tenant', 'run:restore', 1, 'investigation.requested', 'queued', '2026-08-18T00:00:00Z'),
  ('restore-tenant', 'run:restore', 2, 'investigation.completed', 'completed', '2026-08-18T00:00:01Z');
INSERT INTO aegis.outbox_messages (
  tenant_id, message_id, destination, message_type, payload, available_at
) VALUES (
  'restore-tenant', 'outbox:restore', 'temporal',
  'investigation.start', '{"workflow_id":"workflow:restore"}',
  '2026-08-18T00:00:00Z'
);
SQL

docker exec "${CONTAINER}" pg_dump \
  --format=custom --no-owner --no-privileges \
  --username aegis_admin --dbname aegis > "${WORK_DIR}/aegis.dump"
docker exec "${CONTAINER}" createdb --username aegis_admin aegis_restored
docker exec --interactive "${CONTAINER}" pg_restore \
  --exit-on-error --no-owner --no-privileges \
  --username aegis_admin --dbname aegis_restored < "${WORK_DIR}/aegis.dump"

AEGIS_RESTORE_DSN="${ADMIN_DSN}/aegis" \
uv_run python tools/restore_db_verify.py \
  --output "${WORK_DIR}/source.json"
AEGIS_RESTORE_DSN="${ADMIN_DSN}/aegis_restored" \
uv_run python tools/restore_db_verify.py \
  --output "${WORK_DIR}/restored.json" \
  --rebuild

python3 - "${WORK_DIR}/source.json" "${WORK_DIR}/restored.json" \
  "${WORK_DIR}/aegis.dump" "${REPORT}" <<'PY'
import json
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_text())
restored = json.loads(Path(sys.argv[2]).read_text())
for field in ("event_count", "last_cursor", "last_hash", "migration_count", "migration_digest"):
    if source[field] != restored[field]:
        raise SystemExit(f"restore mismatch: {field}")
report = {
    **restored,
    "application_ledger_authoritative": True,
    "backup_sha256": __import__("hashlib").sha256(
        Path(sys.argv[3]).read_bytes()
    ).hexdigest(),
    "cloud_apply_performed": False,
    "drill_kind": "isolated-container-logical-restore",
    "langgraph_checkpoints_disposable": True,
    "live_managed_failover_performed": False,
    "objective_rpo_seconds": 300,
    "objective_rto_seconds": 3600,
    "temporal_reconciliation_required": True,
    "status": "passed",
}
Path(sys.argv[4]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY
