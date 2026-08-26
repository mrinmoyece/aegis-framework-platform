BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('aegis-layer9-schema', 0));

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS aegis.memory_records (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    memory_id text NOT NULL,
    incident_id text NOT NULL,
    run_id text NOT NULL,
    tier text NOT NULL CHECK (tier IN ('working', 'episodic', 'semantic')),
    status text NOT NULL CHECK (
        status IN (
            'candidate', 'accepted', 'rejected', 'active',
            'superseded', 'tombstoned', 'erased'
        )
    ),
    schema_version integer NOT NULL CHECK (schema_version = 1),
    record_digest char(64) NOT NULL CHECK (record_digest ~ '^[a-f0-9]{64}$'),
    content_digest char(64) NOT NULL CHECK (content_digest ~ '^[a-f0-9]{64}$'),
    source_id text NOT NULL,
    evidence_id text NOT NULL,
    classification text NOT NULL CHECK (
        classification IN ('public', 'internal', 'confidential', 'restricted')
    ),
    trust text NOT NULL CHECK (
        trust IN ('external_untrusted', 'platform_control_plane', 'operator_approved')
    ),
    acl_document jsonb NOT NULL CHECK (
        jsonb_typeof(acl_document) = 'object'
        AND pg_column_size(acl_document) <= 16384
    ),
    provenance_document jsonb NOT NULL CHECK (
        jsonb_typeof(provenance_document) = 'object'
        AND pg_column_size(provenance_document) <= 32768
    ),
    retention_document jsonb NOT NULL CHECK (
        jsonb_typeof(retention_document) = 'object'
        AND pg_column_size(retention_document) <= 16384
    ),
    blob_document jsonb NOT NULL CHECK (
        jsonb_typeof(blob_document) = 'object'
        AND pg_column_size(blob_document) <= 16384
    ),
    record_document jsonb NOT NULL CHECK (
        jsonb_typeof(record_document) = 'object'
        AND pg_column_size(record_document) <= 131072
    ),
    expires_at timestamptz NOT NULL,
    legal_hold_count integer NOT NULL CHECK (legal_hold_count BETWEEN 0 AND 16),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, memory_id),
    UNIQUE (tenant_id, record_digest)
);
CREATE INDEX IF NOT EXISTS memory_records_incident_idx
    ON aegis.memory_records (tenant_id, incident_id, tier, status, created_at);
CREATE INDEX IF NOT EXISTS memory_records_retention_idx
    ON aegis.memory_records (tenant_id, expires_at, legal_hold_count, status);

CREATE TABLE IF NOT EXISTS aegis.memory_facts (
    tenant_id text NOT NULL,
    memory_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence >= 1),
    fact_id text NOT NULL,
    fact_type text NOT NULL CHECK (fact_type LIKE 'memory.%'),
    command_id text NOT NULL,
    actor_ref text NOT NULL,
    fact_document jsonb NOT NULL CHECK (
        jsonb_typeof(fact_document) = 'object'
        AND pg_column_size(fact_document) <= 32768
    ),
    previous_digest char(64) NOT NULL CHECK (previous_digest ~ '^[a-f0-9]{64}$'),
    fact_digest char(64) NOT NULL CHECK (fact_digest ~ '^[a-f0-9]{64}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, memory_id, sequence),
    UNIQUE (tenant_id, fact_id),
    UNIQUE (tenant_id, command_id),
    FOREIGN KEY (tenant_id, memory_id)
        REFERENCES aegis.memory_records (tenant_id, memory_id)
);

CREATE TABLE IF NOT EXISTS aegis.memory_projections (
    tenant_id text NOT NULL,
    memory_id text NOT NULL,
    tier text NOT NULL CHECK (tier IN ('working', 'episodic', 'semantic')),
    status text NOT NULL,
    version bigint NOT NULL CHECK (version >= 1),
    record_digest char(64) NOT NULL CHECK (record_digest ~ '^[a-f0-9]{64}$'),
    last_fact_digest char(64) NOT NULL CHECK (last_fact_digest ~ '^[a-f0-9]{64}$'),
    chunk_count integer NOT NULL CHECK (chunk_count BETWEEN 0 AND 10000),
    indexed boolean NOT NULL,
    tombstoned boolean NOT NULL,
    legal_hold_count integer NOT NULL CHECK (legal_hold_count BETWEEN 0 AND 16),
    derived_purged boolean NOT NULL,
    blob_erased boolean NOT NULL,
    projection_document jsonb NOT NULL CHECK (
        jsonb_typeof(projection_document) = 'object'
        AND pg_column_size(projection_document) <= 32768
    ),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, memory_id),
    FOREIGN KEY (tenant_id, memory_id)
        REFERENCES aegis.memory_records (tenant_id, memory_id)
);
CREATE INDEX IF NOT EXISTS memory_projection_status_idx
    ON aegis.memory_projections (tenant_id, status, tier, updated_at);

CREATE TABLE IF NOT EXISTS aegis.memory_chunks (
    tenant_id text NOT NULL,
    chunk_id text NOT NULL,
    memory_id text NOT NULL,
    incident_id text NOT NULL,
    run_id text NOT NULL,
    tier text NOT NULL CHECK (tier IN ('working', 'episodic', 'semantic')),
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 10000),
    chunk_text text NOT NULL CHECK (
        octet_length(chunk_text) BETWEEN 1 AND 262144
    ),
    lexical tsvector GENERATED ALWAYS AS (
        to_tsvector('simple', chunk_text)
    ) STORED,
    content_digest char(64) NOT NULL CHECK (content_digest ~ '^[a-f0-9]{64}$'),
    citation_document jsonb NOT NULL CHECK (
        jsonb_typeof(citation_document) = 'object'
        AND pg_column_size(citation_document) <= 16384
    ),
    acl_document jsonb NOT NULL CHECK (
        jsonb_typeof(acl_document) = 'object'
        AND pg_column_size(acl_document) <= 16384
    ),
    classification text NOT NULL,
    trust text NOT NULL,
    quality double precision NOT NULL CHECK (quality BETWEEN 0 AND 1),
    confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    accepted_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    embedder_model text NOT NULL,
    embedder_version text NOT NULL,
    embedding_dimensions integer NOT NULL CHECK (embedding_dimensions = 64),
    embedding vector(64) NOT NULL,
    indexed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, chunk_id),
    UNIQUE (tenant_id, memory_id, ordinal),
    FOREIGN KEY (tenant_id, memory_id)
        REFERENCES aegis.memory_records (tenant_id, memory_id),
    CHECK (vector_dims(embedding) = embedding_dimensions),
    CHECK (embedding::text !~ '(NaN|Infinity)'),
    CHECK ((embedding <#> embedding) BETWEEN -1.000001 AND -0.999999)
);
CREATE INDEX IF NOT EXISTS memory_chunks_filter_idx
    ON aegis.memory_chunks (
        tenant_id, incident_id, classification, tier, accepted_at, expires_at
    );
CREATE INDEX IF NOT EXISTS memory_chunks_lexical_idx
    ON aegis.memory_chunks USING gin (lexical);
CREATE INDEX IF NOT EXISTS memory_chunks_vector_idx
    ON aegis.memory_chunks USING hnsw (embedding vector_cosine_ops);

CREATE TABLE IF NOT EXISTS aegis.memory_jobs (
    tenant_id text NOT NULL,
    job_id text NOT NULL,
    memory_id text NOT NULL,
    job_type text NOT NULL CHECK (
        job_type IN ('scan', 'chunk', 'embed', 'index', 'compact', 'purge', 'rebuild')
    ),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    result_digest char(64) CHECK (
        result_digest IS NULL OR result_digest ~ '^[a-f0-9]{64}$'
    ),
    reservation_id text NOT NULL,
    fence_token text NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 3),
    status text NOT NULL CHECK (
        status IN ('requested', 'claimed', 'completed', 'failed', 'ambiguous')
    ),
    claim_token text,
    claim_until timestamptz,
    requested_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, job_id),
    UNIQUE (tenant_id, request_digest),
    FOREIGN KEY (tenant_id, memory_id)
        REFERENCES aegis.memory_records (tenant_id, memory_id)
);
CREATE INDEX IF NOT EXISTS memory_jobs_claim_idx
    ON aegis.memory_jobs (tenant_id, status, claim_until, requested_at);

CREATE TABLE IF NOT EXISTS aegis.memory_quotas (
    tenant_id text PRIMARY KEY REFERENCES aegis.tenants (tenant_id),
    policy_revision bigint NOT NULL CHECK (policy_revision >= 1),
    embedding_token_limit bigint NOT NULL CHECK (embedding_token_limit >= 0),
    embedding_tokens_reserved bigint NOT NULL DEFAULT 0 CHECK (
        embedding_tokens_reserved >= 0
    ),
    embedding_tokens_settled bigint NOT NULL DEFAULT 0 CHECK (
        embedding_tokens_settled >= 0
    ),
    storage_byte_limit bigint NOT NULL CHECK (storage_byte_limit >= 0),
    storage_bytes bigint NOT NULL DEFAULT 0 CHECK (storage_bytes >= 0),
    retrieval_limit bigint NOT NULL CHECK (retrieval_limit >= 0),
    retrieval_count bigint NOT NULL DEFAULT 0 CHECK (retrieval_count >= 0),
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL CHECK (period_end > period_start),
    CHECK (
        embedding_tokens_reserved + embedding_tokens_settled
        <= embedding_token_limit
    ),
    CHECK (storage_bytes <= storage_byte_limit),
    CHECK (retrieval_count <= retrieval_limit)
);

CREATE TABLE IF NOT EXISTS aegis.memory_cache (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    cache_key char(64) NOT NULL CHECK (cache_key ~ '^[a-f0-9]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    query_digest char(64) NOT NULL CHECK (query_digest ~ '^[a-f0-9]{64}$'),
    result_digest char(64) NOT NULL CHECK (result_digest ~ '^[a-f0-9]{64}$'),
    result_document jsonb NOT NULL CHECK (
        jsonb_typeof(result_document) = 'object'
        AND pg_column_size(result_document) <= 262144
    ),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, cache_key)
);
CREATE INDEX IF NOT EXISTS memory_cache_expiry_idx
    ON aegis.memory_cache (tenant_id, expires_at);

CREATE TABLE IF NOT EXISTS aegis.memory_operation_facts (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    operation_id text NOT NULL,
    run_id text NOT NULL,
    incident_id text NOT NULL,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 16),
    fact_type text NOT NULL CHECK (
        fact_type IN (
            'memory.retrieve_requested',
            'memory.retrieve_completed',
            'memory.context_built',
            'memory.compact_requested',
            'memory.compact_completed',
            'memory.summary_accepted',
            'memory.summary_rejected',
            'memory.feedback_recorded'
        )
    ),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    query_digest char(64) CHECK (
        query_digest IS NULL OR query_digest ~ '^[a-f0-9]{64}$'
    ),
    result_digest char(64) CHECK (
        result_digest IS NULL OR result_digest ~ '^[a-f0-9]{64}$'
    ),
    fact_digest char(64) NOT NULL CHECK (fact_digest ~ '^[a-f0-9]{64}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, operation_id, sequence),
    UNIQUE (tenant_id, fact_digest)
);
CREATE INDEX IF NOT EXISTS memory_operation_run_idx
    ON aegis.memory_operation_facts (
        tenant_id, run_id, incident_id, fact_type, recorded_at
    );

CREATE TABLE IF NOT EXISTS aegis.memory_checkpoints (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    checkpoint_id text NOT NULL,
    operation_type text NOT NULL,
    last_memory_id text,
    source_digest char(64) NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
    item_count bigint NOT NULL CHECK (item_count >= 0),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, checkpoint_id)
);

CREATE TABLE IF NOT EXISTS aegis.memory_rebuilds (
    tenant_id text NOT NULL,
    rebuild_id text NOT NULL,
    memory_id text NOT NULL,
    source_fact_count bigint NOT NULL CHECK (source_fact_count >= 1),
    source_digest char(64) NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
    projection_digest char(64) NOT NULL CHECK (
        projection_digest ~ '^[a-f0-9]{64}$'
    ),
    rebuilt_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, rebuild_id),
    FOREIGN KEY (tenant_id, memory_id)
        REFERENCES aegis.memory_records (tenant_id, memory_id)
);

DROP TRIGGER IF EXISTS memory_records_immutable ON aegis.memory_records;
CREATE TRIGGER memory_records_immutable
BEFORE UPDATE OR DELETE ON aegis.memory_records
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS memory_facts_immutable ON aegis.memory_facts;
CREATE TRIGGER memory_facts_immutable
BEFORE UPDATE OR DELETE ON aegis.memory_facts
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS memory_rebuilds_immutable ON aegis.memory_rebuilds;
CREATE TRIGGER memory_rebuilds_immutable
BEFORE UPDATE OR DELETE ON aegis.memory_rebuilds
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS memory_operation_facts_immutable
    ON aegis.memory_operation_facts;
CREATE TRIGGER memory_operation_facts_immutable
BEFORE UPDATE OR DELETE ON aegis.memory_operation_facts
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'memory_records',
        'memory_facts',
        'memory_projections',
        'memory_chunks',
        'memory_jobs',
        'memory_quotas',
        'memory_cache',
        'memory_operation_facts',
        'memory_checkpoints',
        'memory_rebuilds'
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

GRANT SELECT, INSERT ON aegis.memory_records,
    aegis.memory_facts,
    aegis.memory_operation_facts,
    aegis.memory_rebuilds TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON aegis.memory_chunks,
    aegis.memory_cache TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.memory_projections,
    aegis.memory_jobs,
    aegis.memory_quotas,
    aegis.memory_checkpoints TO aegis_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON aegis.memory_records,
    aegis.memory_facts,
    aegis.memory_operation_facts,
    aegis.memory_rebuilds FROM aegis_runtime;

COMMIT;
