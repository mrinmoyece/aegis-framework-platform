BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('aegis-layer13-schema', 0));

CREATE TABLE IF NOT EXISTS aegis.interop_trust_registry (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    peer_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 1),
    protocol text NOT NULL CHECK (protocol IN ('mcp', 'a2a')),
    owner_ref text NOT NULL,
    environment text NOT NULL CHECK (
        environment IN ('development', 'test', 'staging', 'production')
    ),
    trust_tier text NOT NULL CHECK (
        trust_tier IN ('internal', 'partner', 'restricted')
    ),
    status text NOT NULL CHECK (
        status IN (
            'pending-review', 'active', 'quarantined', 'revoked',
            'expired', 'emergency-disabled'
        )
    ),
    card_digest char(64) CHECK (
        card_digest IS NULL OR card_digest ~ '^[a-f0-9]{64}$'
    ),
    schema_digest char(64) NOT NULL CHECK (schema_digest ~ '^[a-f0-9]{64}$'),
    certificate_digest char(64) CHECK (
        certificate_digest IS NULL OR certificate_digest ~ '^[a-f0-9]{64}$'
    ),
    key_digest char(64) CHECK (
        key_digest IS NULL OR key_digest ~ '^[a-f0-9]{64}$'
    ),
    change_digest char(64) NOT NULL CHECK (change_digest ~ '^[a-f0-9]{64}$'),
    trust_document jsonb NOT NULL CHECK (
        jsonb_typeof(trust_document) = 'object'
        AND pg_column_size(trust_document) <= 65536
        AND NOT (trust_document ?| ARRAY[
            'credential', 'secret', 'token', 'raw', 'prompt', 'completion'
        ])
    ),
    expires_at timestamptz NOT NULL,
    review_after timestamptz NOT NULL CHECK (review_after < expires_at),
    reviewed_at timestamptz,
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, peer_id, revision),
    UNIQUE (tenant_id, peer_id, change_digest)
);
CREATE INDEX IF NOT EXISTS interop_trust_current_idx
    ON aegis.interop_trust_registry (tenant_id, peer_id, revision DESC);
CREATE INDEX IF NOT EXISTS interop_trust_review_idx
    ON aegis.interop_trust_registry (
        tenant_id, status, review_after, expires_at
    );

CREATE TABLE IF NOT EXISTS aegis.interop_invocations (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    operation_id text NOT NULL,
    peer_id text NOT NULL,
    protocol text NOT NULL CHECK (protocol IN ('mcp', 'a2a')),
    capability_id text NOT NULL,
    risk text NOT NULL CHECK (risk IN ('low', 'medium', 'high')),
    trust_revision bigint NOT NULL CHECK (trust_revision >= 1),
    state text NOT NULL CHECK (
        state IN (
            'requested', 'claimed', 'succeeded', 'failed', 'ambiguous',
            'cancelled', 'reconciled', 'quarantined'
        )
    ),
    version bigint NOT NULL CHECK (version >= 1),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    trust_digest char(64) NOT NULL CHECK (trust_digest ~ '^[a-f0-9]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    idempotency_key_digest char(64) NOT NULL CHECK (
        idempotency_key_digest ~ '^[a-f0-9]{64}$'
    ),
    fence_token text NOT NULL,
    result_digest char(64) CHECK (
        result_digest IS NULL OR result_digest ~ '^[a-f0-9]{64}$'
    ),
    cursor_digest char(64) CHECK (
        cursor_digest IS NULL OR cursor_digest ~ '^[a-f0-9]{64}$'
    ),
    error_code text,
    ambiguous boolean NOT NULL DEFAULT false,
    cancellation_requested boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    UNIQUE (tenant_id, idempotency_key_digest),
    CHECK ((state = 'ambiguous') = ambiguous OR NOT ambiguous)
);
CREATE INDEX IF NOT EXISTS interop_invocations_state_idx
    ON aegis.interop_invocations (
        tenant_id, state, protocol, updated_at, operation_id
    );

CREATE TABLE IF NOT EXISTS aegis.interop_tasks (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    task_id text NOT NULL,
    operation_id text NOT NULL,
    peer_task_ref_digest char(64) CHECK (
        peer_task_ref_digest IS NULL OR peer_task_ref_digest ~ '^[a-f0-9]{64}$'
    ),
    state text NOT NULL CHECK (
        state IN (
            'submitted', 'working', 'input-required', 'completed', 'failed',
            'cancelled', 'reconciliation-required', 'quarantined'
        )
    ),
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 3),
    claim_token text,
    claim_until timestamptz,
    fence_token text NOT NULL,
    status_digest char(64) CHECK (
        status_digest IS NULL OR status_digest ~ '^[a-f0-9]{64}$'
    ),
    result_digest char(64) CHECK (
        result_digest IS NULL OR result_digest ~ '^[a-f0-9]{64}$'
    ),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, task_id),
    UNIQUE (tenant_id, operation_id),
    FOREIGN KEY (tenant_id, operation_id)
        REFERENCES aegis.interop_invocations (tenant_id, operation_id)
);
CREATE INDEX IF NOT EXISTS interop_tasks_claim_idx
    ON aegis.interop_tasks (tenant_id, state, claim_until, updated_at);

CREATE TABLE IF NOT EXISTS aegis.interop_facts (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    operation_id text NOT NULL,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 128),
    fact_id text NOT NULL,
    fact_type text NOT NULL CHECK (fact_type LIKE 'interop.%'),
    command_ref text NOT NULL,
    actor_ref text NOT NULL,
    peer_id text NOT NULL,
    payload_document jsonb NOT NULL CHECK (
        jsonb_typeof(payload_document) = 'object'
        AND pg_column_size(payload_document) <= 32768
        AND NOT (payload_document ?| ARRAY[
            'actor_id', 'completion', 'content', 'credential',
            'evidence_locator', 'message', 'prompt', 'raw', 'request_id',
            'secret', 'subject_id', 'tenant_id', 'text', 'token', 'url'
        ])
    ),
    previous_digest char(64) NOT NULL CHECK (previous_digest ~ '^[a-f0-9]{64}$'),
    fact_digest char(64) NOT NULL CHECK (fact_digest ~ '^[a-f0-9]{64}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, operation_id, sequence),
    UNIQUE (tenant_id, fact_id),
    UNIQUE (tenant_id, command_ref),
    UNIQUE (tenant_id, fact_digest),
    FOREIGN KEY (tenant_id, operation_id)
        REFERENCES aegis.interop_invocations (tenant_id, operation_id)
);

CREATE TABLE IF NOT EXISTS aegis.interop_cursors (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    cursor_ref text NOT NULL,
    operation_id text NOT NULL,
    peer_id text NOT NULL,
    protocol text NOT NULL CHECK (protocol IN ('mcp', 'a2a')),
    direction text NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    position bigint NOT NULL CHECK (position >= 0),
    page_size integer NOT NULL CHECK (page_size BETWEEN 1 AND 100),
    query_digest char(64) NOT NULL CHECK (query_digest ~ '^[a-f0-9]{64}$'),
    cursor_digest char(64) NOT NULL CHECK (cursor_digest ~ '^[a-f0-9]{64}$'),
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, cursor_ref),
    UNIQUE (tenant_id, operation_id, cursor_digest),
    FOREIGN KEY (tenant_id, operation_id)
        REFERENCES aegis.interop_invocations (tenant_id, operation_id)
);
CREATE INDEX IF NOT EXISTS interop_cursors_expiry_idx
    ON aegis.interop_cursors (tenant_id, expires_at, operation_id);

CREATE TABLE IF NOT EXISTS aegis.interop_quotas (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    peer_id text NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL CHECK (period_end > period_start),
    request_limit bigint NOT NULL CHECK (request_limit >= 0),
    requests_reserved bigint NOT NULL DEFAULT 0 CHECK (requests_reserved >= 0),
    cost_limit bigint NOT NULL CHECK (cost_limit >= 0),
    cost_reserved bigint NOT NULL DEFAULT 0 CHECK (cost_reserved >= 0),
    byte_limit bigint NOT NULL CHECK (byte_limit >= 0),
    bytes_settled bigint NOT NULL DEFAULT 0 CHECK (bytes_settled >= 0),
    policy_revision bigint NOT NULL CHECK (policy_revision >= 1),
    PRIMARY KEY (tenant_id, peer_id, period_start),
    CHECK (requests_reserved <= request_limit),
    CHECK (cost_reserved <= cost_limit),
    CHECK (bytes_settled <= byte_limit)
);

CREATE TABLE IF NOT EXISTS aegis.interop_artifact_projections (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    artifact_id text NOT NULL,
    operation_id text NOT NULL,
    peer_id text NOT NULL,
    artifact_kind text NOT NULL,
    media_types text[] NOT NULL CHECK (cardinality(media_types) BETWEEN 1 AND 32),
    citation_count integer NOT NULL CHECK (citation_count BETWEEN 0 AND 64),
    content_digest char(64) NOT NULL CHECK (content_digest ~ '^[a-f0-9]{64}$'),
    provenance_digest char(64) NOT NULL CHECK (
        provenance_digest ~ '^[a-f0-9]{64}$'
    ),
    card_digest char(64) NOT NULL CHECK (card_digest ~ '^[a-f0-9]{64}$'),
    classification text NOT NULL CHECK (
        classification IN ('public', 'internal', 'confidential', 'restricted')
    ),
    disposition text NOT NULL CHECK (
        disposition IN ('accepted', 'redacted', 'quarantined')
    ),
    size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 0 AND 262144),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, artifact_id),
    FOREIGN KEY (tenant_id, operation_id)
        REFERENCES aegis.interop_invocations (tenant_id, operation_id)
);
CREATE INDEX IF NOT EXISTS interop_artifacts_operation_idx
    ON aegis.interop_artifact_projections (
        tenant_id, operation_id, disposition, recorded_at, artifact_id
    );

CREATE TABLE IF NOT EXISTS aegis.interop_rebuilds (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    rebuild_id text NOT NULL,
    source_fact_count bigint NOT NULL CHECK (source_fact_count >= 1),
    source_digest char(64) NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
    projection_digest char(64) NOT NULL CHECK (
        projection_digest ~ '^[a-f0-9]{64}$'
    ),
    rebuilt_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, rebuild_id)
);

DROP TRIGGER IF EXISTS interop_trust_immutable
    ON aegis.interop_trust_registry;
CREATE TRIGGER interop_trust_immutable
BEFORE UPDATE OR DELETE ON aegis.interop_trust_registry
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS interop_facts_immutable ON aegis.interop_facts;
CREATE TRIGGER interop_facts_immutable
BEFORE UPDATE OR DELETE ON aegis.interop_facts
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS interop_artifacts_immutable
    ON aegis.interop_artifact_projections;
CREATE TRIGGER interop_artifacts_immutable
BEFORE UPDATE OR DELETE ON aegis.interop_artifact_projections
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS interop_rebuilds_immutable ON aegis.interop_rebuilds;
CREATE TRIGGER interop_rebuilds_immutable
BEFORE UPDATE OR DELETE ON aegis.interop_rebuilds
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'interop_trust_registry',
        'interop_invocations',
        'interop_tasks',
        'interop_facts',
        'interop_cursors',
        'interop_quotas',
        'interop_artifact_projections',
        'interop_rebuilds'
    ]
    LOOP
        EXECUTE format(
            'ALTER TABLE aegis.%I ENABLE ROW LEVEL SECURITY',
            table_name
        );
        EXECUTE format(
            'ALTER TABLE aegis.%I FORCE ROW LEVEL SECURITY',
            table_name
        );
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

GRANT SELECT, INSERT ON aegis.interop_trust_registry,
    aegis.interop_facts,
    aegis.interop_artifact_projections,
    aegis.interop_rebuilds TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.interop_invocations,
    aegis.interop_tasks,
    aegis.interop_cursors,
    aegis.interop_quotas TO aegis_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON aegis.interop_trust_registry,
    aegis.interop_facts,
    aegis.interop_artifact_projections,
    aegis.interop_rebuilds FROM aegis_runtime;

COMMIT;
