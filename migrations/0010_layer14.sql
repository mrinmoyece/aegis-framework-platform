BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('aegis-layer14-schema', 0));

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_operations') THEN
        CREATE ROLE aegis_operations NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
END
$$;
ALTER ROLE aegis_operations NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA aegis TO aegis_operations;
GRANT EXECUTE ON FUNCTION aegis.current_tenant_id() TO aegis_operations;

CREATE TABLE IF NOT EXISTS aegis.deployment_generations (
    environment text NOT NULL CHECK (
        environment IN ('development', 'test', 'staging', 'production')
    ),
    generation bigint NOT NULL CHECK (generation >= 1),
    home_region text NOT NULL,
    active_region text NOT NULL,
    previous_region text,
    writer_enabled boolean NOT NULL,
    fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
    approval_ref text NOT NULL,
    source_backup_ref text NOT NULL,
    source_ledger_hash char(64) NOT NULL CHECK (
        source_ledger_hash ~ '^[a-f0-9]{64}$'
    ),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (environment, generation),
    CHECK (writer_enabled OR active_region = home_region)
);

CREATE TABLE IF NOT EXISTS aegis.deployment_region_state (
    environment text PRIMARY KEY CHECK (
        environment IN ('development', 'test', 'staging', 'production')
    ),
    generation bigint NOT NULL CHECK (generation >= 1),
    active_region text NOT NULL,
    writer_enabled boolean NOT NULL,
    fence_digest char(64) NOT NULL CHECK (fence_digest ~ '^[a-f0-9]{64}$'),
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (environment, generation)
        REFERENCES aegis.deployment_generations (environment, generation)
);

CREATE TABLE IF NOT EXISTS aegis.restore_drill_records (
    drill_id text PRIMARY KEY,
    environment text NOT NULL CHECK (
        environment IN ('development', 'test', 'staging', 'production')
    ),
    isolated_target text NOT NULL,
    backup_ref text NOT NULL,
    backup_manifest_digest char(64) NOT NULL CHECK (
        backup_manifest_digest ~ '^[a-f0-9]{64}$'
    ),
    event_count bigint NOT NULL CHECK (event_count >= 0),
    last_tenant_cursor bigint NOT NULL CHECK (last_tenant_cursor >= 0),
    last_tenant_hash char(64) NOT NULL CHECK (
        last_tenant_hash ~ '^[a-f0-9]{64}$'
    ),
    sequence_verified boolean NOT NULL,
    dual_hash_verified boolean NOT NULL,
    projections_rebuilt boolean NOT NULL,
    vector_indexes_rebuilt boolean NOT NULL,
    checkpoints_rebuilt boolean NOT NULL,
    temporal_reconciled boolean NOT NULL,
    outbox_reconciled boolean NOT NULL,
    effects_reconciled boolean NOT NULL,
    objective_rpo_seconds bigint NOT NULL CHECK (objective_rpo_seconds >= 0),
    objective_rto_seconds bigint NOT NULL CHECK (objective_rto_seconds >= 0),
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    CHECK (
        completed_at IS NULL OR (
            sequence_verified
            AND dual_hash_verified
            AND projections_rebuilt
            AND vector_indexes_rebuilt
            AND checkpoints_rebuilt
            AND temporal_reconciled
            AND outbox_reconciled
            AND effects_reconciled
        )
    )
);

CREATE TABLE IF NOT EXISTS aegis.retention_executions (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    execution_id text NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision >= 1),
    data_class text NOT NULL CHECK (
        data_class IN (
            'projection', 'checkpoint', 'visibility', 'telemetry', 'backup',
            'derived-cache'
        )
    ),
    cutoff_at timestamptz NOT NULL,
    legal_hold_checked boolean NOT NULL,
    candidate_count bigint NOT NULL CHECK (candidate_count >= 0),
    deleted_count bigint NOT NULL CHECK (deleted_count >= 0),
    manifest_digest char(64) NOT NULL CHECK (
        manifest_digest ~ '^[a-f0-9]{64}$'
    ),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, execution_id),
    CHECK (deleted_count <= candidate_count),
    CHECK (legal_hold_checked OR deleted_count = 0)
);

ALTER TABLE aegis.retention_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis.retention_executions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS retention_executions_tenant_isolation
    ON aegis.retention_executions;
CREATE POLICY retention_executions_tenant_isolation
ON aegis.retention_executions
USING (tenant_id = aegis.current_tenant_id())
WITH CHECK (tenant_id = aegis.current_tenant_id());

DROP TRIGGER IF EXISTS deployment_generations_immutable
    ON aegis.deployment_generations;
CREATE TRIGGER deployment_generations_immutable
BEFORE UPDATE OR DELETE ON aegis.deployment_generations
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS restore_drill_records_immutable
    ON aegis.restore_drill_records;
CREATE TRIGGER restore_drill_records_immutable
BEFORE UPDATE OR DELETE ON aegis.restore_drill_records
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS retention_executions_immutable
    ON aegis.retention_executions;
CREATE TRIGGER retention_executions_immutable
BEFORE UPDATE OR DELETE ON aegis.retention_executions
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

REVOKE ALL ON aegis.deployment_generations,
    aegis.deployment_region_state,
    aegis.restore_drill_records,
    aegis.retention_executions FROM PUBLIC, aegis_runtime;
GRANT SELECT, INSERT ON aegis.deployment_generations,
    aegis.restore_drill_records TO aegis_operations;
GRANT SELECT, INSERT, UPDATE ON aegis.deployment_region_state
    TO aegis_operations;
GRANT SELECT, INSERT ON aegis.retention_executions TO aegis_operations;

COMMIT;
