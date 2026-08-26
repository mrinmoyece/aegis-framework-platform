BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('aegis-layer8-schema', 0));

CREATE TABLE IF NOT EXISTS aegis.sandbox_policies (
    tenant_id text PRIMARY KEY REFERENCES aegis.tenants (tenant_id),
    policy_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 1),
    enabled boolean NOT NULL DEFAULT false,
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    policy_document jsonb NOT NULL CHECK (
        jsonb_typeof(policy_document) = 'object'
        AND pg_column_size(policy_document) <= 131072
    ),
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS aegis.sandbox_requests (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    execution_id text NOT NULL,
    run_id text NOT NULL,
    task_id text NOT NULL,
    remediation_plan_id text NOT NULL,
    approval_id text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version = 1),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    spec_digest char(64) NOT NULL CHECK (spec_digest ~ '^[a-f0-9]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    approval_digest char(64) NOT NULL CHECK (approval_digest ~ '^[a-f0-9]{64}$'),
    image_digest char(64) NOT NULL CHECK (image_digest ~ '^[a-f0-9]{64}$'),
    idempotency_key text NOT NULL,
    request_document jsonb NOT NULL CHECK (
        jsonb_typeof(request_document) = 'object'
        AND pg_column_size(request_document) <= 262144
    ),
    requested_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, execution_id),
    UNIQUE (tenant_id, request_digest),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS aegis.sandbox_quotas (
    tenant_id text PRIMARY KEY REFERENCES aegis.tenants (tenant_id),
    concurrency_limit integer NOT NULL CHECK (concurrency_limit BETWEEN 0 AND 100),
    active_count integer NOT NULL DEFAULT 0 CHECK (active_count >= 0),
    period_limit bigint NOT NULL CHECK (period_limit >= 0),
    reserved_count bigint NOT NULL DEFAULT 0 CHECK (reserved_count >= 0),
    settled_count bigint NOT NULL DEFAULT 0 CHECK (settled_count >= 0),
    version bigint NOT NULL CHECK (version >= 1),
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL CHECK (period_end > period_start),
    CHECK (active_count <= concurrency_limit),
    CHECK (reserved_count + settled_count <= period_limit)
);

CREATE TABLE IF NOT EXISTS aegis.sandbox_quota_reservations (
    tenant_id text NOT NULL,
    reservation_id text NOT NULL,
    execution_id text NOT NULL,
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    units bigint NOT NULL CHECK (units > 0),
    status text NOT NULL CHECK (status IN ('reserved', 'settled', 'released')),
    reserved_at timestamptz NOT NULL,
    settled_at timestamptz,
    PRIMARY KEY (tenant_id, reservation_id),
    FOREIGN KEY (tenant_id, execution_id)
        REFERENCES aegis.sandbox_requests (tenant_id, execution_id)
);

CREATE TABLE IF NOT EXISTS aegis.sandbox_attempts (
    tenant_id text NOT NULL,
    execution_id text NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 16),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    fence_token text NOT NULL,
    status text NOT NULL CHECK (
        status IN (
            'requested', 'claimed', 'provisioning', 'running', 'capturing',
            'terminal', 'cleaning', 'cleaned', 'reconciling'
        )
    ),
    claim_token text,
    claim_until timestamptz,
    worker_ref text,
    provider_ref text,
    provider_uid text,
    result_digest char(64) CHECK (
        result_digest IS NULL OR result_digest ~ '^[a-f0-9]{64}$'
    ),
    requested_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, execution_id, attempt),
    FOREIGN KEY (tenant_id, execution_id)
        REFERENCES aegis.sandbox_requests (tenant_id, execution_id),
    CHECK (
        (status = 'claimed' AND claim_token IS NOT NULL AND claim_until IS NOT NULL)
        OR status <> 'claimed'
    )
);
CREATE INDEX IF NOT EXISTS sandbox_attempt_claim_idx
    ON aegis.sandbox_attempts (tenant_id, status, claim_until, requested_at);

CREATE TABLE IF NOT EXISTS aegis.sandbox_facts (
    tenant_id text NOT NULL,
    execution_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence >= 1),
    fact_id text NOT NULL,
    fact_type text NOT NULL CHECK (fact_type LIKE 'sandbox.%'),
    command_id text NOT NULL,
    actor_ref text NOT NULL,
    fact_document jsonb NOT NULL CHECK (
        jsonb_typeof(fact_document) = 'object'
        AND pg_column_size(fact_document) <= 65536
    ),
    previous_digest char(64) NOT NULL CHECK (previous_digest ~ '^[a-f0-9]{64}$'),
    fact_digest char(64) NOT NULL CHECK (fact_digest ~ '^[a-f0-9]{64}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, execution_id, sequence),
    UNIQUE (tenant_id, fact_id),
    UNIQUE (tenant_id, command_id),
    FOREIGN KEY (tenant_id, execution_id)
        REFERENCES aegis.sandbox_requests (tenant_id, execution_id)
);

CREATE TABLE IF NOT EXISTS aegis.sandbox_artifacts (
    tenant_id text NOT NULL,
    artifact_id text NOT NULL,
    run_id text NOT NULL,
    task_id text NOT NULL,
    execution_id text NOT NULL,
    logical_path text NOT NULL,
    media_type text NOT NULL,
    content_hash char(64) NOT NULL CHECK (content_hash ~ '^[a-f0-9]{64}$'),
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 0 AND 16777216),
    disposition text NOT NULL CHECK (
        disposition IN ('accepted', 'redacted', 'quarantined')
    ),
    artifact_digest char(64) NOT NULL CHECK (artifact_digest ~ '^[a-f0-9]{64}$'),
    artifact_document jsonb NOT NULL CHECK (
        jsonb_typeof(artifact_document) = 'object'
        AND pg_column_size(artifact_document) <= 65536
    ),
    retention_expires_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, artifact_id),
    UNIQUE (tenant_id, execution_id, logical_path),
    FOREIGN KEY (tenant_id, execution_id)
        REFERENCES aegis.sandbox_requests (tenant_id, execution_id)
);
CREATE INDEX IF NOT EXISTS sandbox_artifact_retention_idx
    ON aegis.sandbox_artifacts (tenant_id, retention_expires_at, disposition);

CREATE TABLE IF NOT EXISTS aegis.sandbox_manifests (
    tenant_id text NOT NULL,
    execution_id text NOT NULL,
    manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
    manifest_document jsonb NOT NULL CHECK (
        jsonb_typeof(manifest_document) = 'object'
        AND pg_column_size(manifest_document) <= 262144
    ),
    generated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, execution_id, manifest_digest),
    FOREIGN KEY (tenant_id, execution_id)
        REFERENCES aegis.sandbox_requests (tenant_id, execution_id)
);

CREATE TABLE IF NOT EXISTS aegis.sandbox_attestations (
    tenant_id text NOT NULL,
    execution_id text NOT NULL,
    attestation_digest char(64) NOT NULL CHECK (
        attestation_digest ~ '^[a-f0-9]{64}$'
    ),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    result_digest char(64) NOT NULL CHECK (result_digest ~ '^[a-f0-9]{64}$'),
    provider_uid text NOT NULL,
    attestation_document jsonb NOT NULL CHECK (
        jsonb_typeof(attestation_document) = 'object'
        AND pg_column_size(attestation_document) <= 65536
    ),
    attested_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, execution_id, attestation_digest),
    FOREIGN KEY (tenant_id, execution_id)
        REFERENCES aegis.sandbox_requests (tenant_id, execution_id)
);

CREATE TABLE IF NOT EXISTS aegis.sandbox_cleanup_claims (
    tenant_id text NOT NULL,
    cleanup_id text NOT NULL,
    execution_id text NOT NULL,
    provider_uid text NOT NULL,
    claim_token text NOT NULL,
    claim_until timestamptz NOT NULL,
    worker_ref text NOT NULL,
    status text NOT NULL CHECK (
        status IN ('claimed', 'deleted', 'absent', 'ambiguous', 'quarantined')
    ),
    claimed_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, cleanup_id),
    UNIQUE (tenant_id, execution_id, provider_uid),
    FOREIGN KEY (tenant_id, execution_id)
        REFERENCES aegis.sandbox_requests (tenant_id, execution_id)
);
CREATE INDEX IF NOT EXISTS sandbox_cleanup_redrive_idx
    ON aegis.sandbox_cleanup_claims (tenant_id, status, claim_until);

CREATE TABLE IF NOT EXISTS aegis.sandbox_projections (
    tenant_id text NOT NULL,
    execution_id text NOT NULL,
    run_id text NOT NULL,
    task_id text NOT NULL,
    status text NOT NULL,
    version bigint NOT NULL CHECK (version >= 1),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    spec_digest char(64) NOT NULL CHECK (spec_digest ~ '^[a-f0-9]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    approval_digest char(64) NOT NULL CHECK (approval_digest ~ '^[a-f0-9]{64}$'),
    fence_token text NOT NULL,
    provider_uid text,
    result_digest char(64),
    manifest_digest char(64),
    attestation_digest char(64),
    cleanup_complete boolean NOT NULL DEFAULT false,
    last_fact_digest char(64) NOT NULL CHECK (
        last_fact_digest ~ '^[a-f0-9]{64}$'
    ),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, execution_id),
    FOREIGN KEY (tenant_id, execution_id)
        REFERENCES aegis.sandbox_requests (tenant_id, execution_id)
);

CREATE TABLE IF NOT EXISTS aegis.sandbox_projection_rebuilds (
    tenant_id text NOT NULL,
    rebuild_id text NOT NULL,
    execution_id text NOT NULL,
    source_fact_count bigint NOT NULL CHECK (source_fact_count >= 1),
    source_digest char(64) NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
    projection_digest char(64) NOT NULL CHECK (
        projection_digest ~ '^[a-f0-9]{64}$'
    ),
    rebuilt_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, rebuild_id),
    FOREIGN KEY (tenant_id, execution_id)
        REFERENCES aegis.sandbox_requests (tenant_id, execution_id)
);

DROP TRIGGER IF EXISTS sandbox_requests_immutable ON aegis.sandbox_requests;
CREATE TRIGGER sandbox_requests_immutable
BEFORE UPDATE OR DELETE ON aegis.sandbox_requests
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS sandbox_quota_reservations_immutable
    ON aegis.sandbox_quota_reservations;
CREATE TRIGGER sandbox_quota_reservations_immutable
BEFORE UPDATE OR DELETE ON aegis.sandbox_quota_reservations
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS sandbox_facts_immutable ON aegis.sandbox_facts;
CREATE TRIGGER sandbox_facts_immutable
BEFORE UPDATE OR DELETE ON aegis.sandbox_facts
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS sandbox_artifacts_immutable ON aegis.sandbox_artifacts;
CREATE TRIGGER sandbox_artifacts_immutable
BEFORE UPDATE OR DELETE ON aegis.sandbox_artifacts
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS sandbox_manifests_immutable ON aegis.sandbox_manifests;
CREATE TRIGGER sandbox_manifests_immutable
BEFORE UPDATE OR DELETE ON aegis.sandbox_manifests
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS sandbox_attestations_immutable ON aegis.sandbox_attestations;
CREATE TRIGGER sandbox_attestations_immutable
BEFORE UPDATE OR DELETE ON aegis.sandbox_attestations
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS sandbox_projection_rebuilds_immutable
    ON aegis.sandbox_projection_rebuilds;
CREATE TRIGGER sandbox_projection_rebuilds_immutable
BEFORE UPDATE OR DELETE ON aegis.sandbox_projection_rebuilds
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'sandbox_policies',
        'sandbox_requests',
        'sandbox_quotas',
        'sandbox_quota_reservations',
        'sandbox_attempts',
        'sandbox_facts',
        'sandbox_artifacts',
        'sandbox_manifests',
        'sandbox_attestations',
        'sandbox_cleanup_claims',
        'sandbox_projections',
        'sandbox_projection_rebuilds'
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

GRANT SELECT, INSERT ON aegis.sandbox_requests,
    aegis.sandbox_quota_reservations,
    aegis.sandbox_facts,
    aegis.sandbox_artifacts,
    aegis.sandbox_manifests,
    aegis.sandbox_attestations,
    aegis.sandbox_projection_rebuilds TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.sandbox_policies,
    aegis.sandbox_quotas,
    aegis.sandbox_attempts,
    aegis.sandbox_cleanup_claims,
    aegis.sandbox_projections TO aegis_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON aegis.sandbox_requests,
    aegis.sandbox_quota_reservations,
    aegis.sandbox_facts,
    aegis.sandbox_artifacts,
    aegis.sandbox_manifests,
    aegis.sandbox_attestations,
    aegis.sandbox_projection_rebuilds FROM aegis_runtime;

COMMIT;
