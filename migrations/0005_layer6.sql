BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('aegis-layer6-schema', 0));

CREATE TABLE IF NOT EXISTS aegis.orchestration_runs (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    run_id text NOT NULL,
    incident_id text NOT NULL,
    thread_ref text NOT NULL,
    graph_version text NOT NULL,
    input_digest char(64) NOT NULL CHECK (input_digest ~ '^[a-f0-9]{64}$'),
    fence_token text NOT NULL,
    status text NOT NULL CHECK (
        status IN (
            'running', 'complete', 'abstained', 'escalated', 'failed', 'cancelled'
        )
    ),
    cancelled boolean NOT NULL DEFAULT false,
    artifact_count integer NOT NULL DEFAULT 0 CHECK (
        artifact_count BETWEEN 0 AND 64
    ),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    UNIQUE (tenant_id, thread_ref)
);

CREATE TABLE IF NOT EXISTS aegis.orchestration_facts (
    tenant_id text NOT NULL,
    fact_id text NOT NULL,
    run_id text NOT NULL,
    task_id text,
    fact_type text NOT NULL CHECK (
        fact_type IN (
            'run.intent', 'task.dispatch', 'task.result', 'artifact.recorded',
            'decision.recorded', 'run.cancelled', 'projection.rebuilt'
        )
    ),
    schema_version integer NOT NULL CHECK (schema_version BETWEEN 1 AND 1000),
    document jsonb NOT NULL CHECK (
        jsonb_typeof(document) = 'object'
        AND pg_column_size(document) <= 65536
    ),
    canonical_digest char(64) NOT NULL CHECK (
        canonical_digest ~ '^[a-f0-9]{64}$'
    ),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, fact_id),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES aegis.orchestration_runs (tenant_id, run_id)
);
CREATE INDEX IF NOT EXISTS orchestration_facts_run_idx
    ON aegis.orchestration_facts (tenant_id, run_id, recorded_at, fact_id);

CREATE TABLE IF NOT EXISTS aegis.orchestration_tasks (
    tenant_id text NOT NULL,
    run_id text NOT NULL,
    task_id text NOT NULL,
    role text NOT NULL CHECK (
        role IN (
            'telemetry_specialist', 'change_specialist',
            'runtime_specialist', 'knowledge_specialist'
        )
    ),
    input_digest char(64) NOT NULL CHECK (input_digest ~ '^[a-f0-9]{64}$'),
    fence_token text NOT NULL,
    attempt integer NOT NULL DEFAULT 1 CHECK (attempt BETWEEN 1 AND 16),
    status text NOT NULL CHECK (
        status IN ('started', 'completed', 'reconciliation_required', 'cancelled')
    ),
    result_document jsonb CHECK (
        result_document IS NULL OR (
            jsonb_typeof(result_document) = 'object'
            AND pg_column_size(result_document) <= 32768
        )
    ),
    result_digest char(64) CHECK (
        result_digest IS NULL OR result_digest ~ '^[a-f0-9]{64}$'
    ),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id, task_id),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES aegis.orchestration_runs (tenant_id, run_id)
);

CREATE TABLE IF NOT EXISTS aegis.orchestration_artifacts (
    tenant_id text NOT NULL,
    run_id text NOT NULL,
    artifact_id text NOT NULL,
    task_id text,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 1 AND 1000),
    artifact_kind text NOT NULL,
    producer_role text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version BETWEEN 1 AND 1000),
    artifact_document jsonb NOT NULL CHECK (
        jsonb_typeof(artifact_document) = 'object'
        AND pg_column_size(artifact_document) <= 65536
    ),
    canonical_digest char(64) NOT NULL CHECK (
        canonical_digest ~ '^[a-f0-9]{64}$'
    ),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id, artifact_id),
    UNIQUE (tenant_id, run_id, ordinal),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES aegis.orchestration_runs (tenant_id, run_id)
);
CREATE INDEX IF NOT EXISTS orchestration_artifacts_cursor_idx
    ON aegis.orchestration_artifacts (tenant_id, run_id, ordinal, artifact_id);

CREATE TABLE IF NOT EXISTS aegis.orchestration_projection_rebuilds (
    tenant_id text NOT NULL,
    run_id text NOT NULL,
    rebuild_id text NOT NULL,
    artifact_count integer NOT NULL CHECK (artifact_count BETWEEN 0 AND 64),
    decision text CHECK (
        decision IS NULL OR decision IN (
            'complete', 'abstained', 'escalated', 'failed', 'cancelled'
        )
    ),
    source_digest char(64) NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
    rebuilt_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, rebuild_id),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES aegis.orchestration_runs (tenant_id, run_id)
);

DROP TRIGGER IF EXISTS orchestration_facts_immutable
    ON aegis.orchestration_facts;
CREATE TRIGGER orchestration_facts_immutable
BEFORE UPDATE OR DELETE ON aegis.orchestration_facts
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS orchestration_artifacts_immutable
    ON aegis.orchestration_artifacts;
CREATE TRIGGER orchestration_artifacts_immutable
BEFORE UPDATE OR DELETE ON aegis.orchestration_artifacts
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS orchestration_projection_rebuilds_immutable
    ON aegis.orchestration_projection_rebuilds;
CREATE TRIGGER orchestration_projection_rebuilds_immutable
BEFORE UPDATE OR DELETE ON aegis.orchestration_projection_rebuilds
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'orchestration_runs',
        'orchestration_facts',
        'orchestration_tasks',
        'orchestration_artifacts',
        'orchestration_projection_rebuilds'
    ]
    LOOP
        EXECUTE format('ALTER TABLE aegis.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE aegis.%I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'DROP POLICY IF EXISTS %I ON aegis.%I',
            table_name || '_tenant_isolation',
            table_name
        );
        EXECUTE format(
            'CREATE POLICY %I ON aegis.%I USING '
            || '(tenant_id = aegis.current_tenant_id()) WITH CHECK '
            || '(tenant_id = aegis.current_tenant_id())',
            table_name || '_tenant_isolation',
            table_name
        );
    END LOOP;
END;
$$;

GRANT SELECT, INSERT, UPDATE ON aegis.orchestration_runs,
    aegis.orchestration_tasks TO aegis_runtime;
GRANT SELECT, INSERT ON aegis.orchestration_facts,
    aegis.orchestration_artifacts,
    aegis.orchestration_projection_rebuilds TO aegis_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON aegis.orchestration_facts,
    aegis.orchestration_artifacts,
    aegis.orchestration_projection_rebuilds FROM aegis_runtime;

COMMIT;
