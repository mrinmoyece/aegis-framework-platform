BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('aegis-layer5-schema', 0));

CREATE TABLE IF NOT EXISTS aegis.evidence_sources (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    source_id text NOT NULL,
    source_kind text NOT NULL CHECK (
        source_kind IN ('dynatrace', 'github', 'kubernetes', 'runbook')
    ),
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    source_digest char(64) NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
    document jsonb NOT NULL CHECK (
        jsonb_typeof(document) = 'object' AND pg_column_size(document) <= 32768
    ),
    enabled boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, source_id)
);

CREATE TABLE IF NOT EXISTS aegis.evidence_tenant_quotas (
    tenant_id text PRIMARY KEY REFERENCES aegis.tenants (tenant_id),
    maximum_active_queries integer NOT NULL CHECK (
        maximum_active_queries BETWEEN 1 AND 1000
    ),
    maximum_daily_bytes bigint NOT NULL CHECK (maximum_daily_bytes >= 0),
    reserved_daily_bytes bigint NOT NULL DEFAULT 0 CHECK (
        reserved_daily_bytes BETWEEN 0 AND maximum_daily_bytes
    ),
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK (period_end > period_start)
);

CREATE TABLE IF NOT EXISTS aegis.evidence_queries (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    query_id text NOT NULL,
    incident_id text NOT NULL,
    run_id text NOT NULL,
    source_id text NOT NULL,
    source_kind text NOT NULL,
    query_digest char(64) NOT NULL CHECK (query_digest ~ '^[a-f0-9]{64}$'),
    query_document jsonb NOT NULL CHECK (
        jsonb_typeof(query_document) = 'object'
        AND pg_column_size(query_document) <= 32768
    ),
    status text NOT NULL CHECK (
        status IN (
            'requested', 'running', 'completed', 'failed', 'cancelled',
            'reconciliation_required', 'stale'
        )
    ),
    page_count integer NOT NULL DEFAULT 0 CHECK (page_count BETWEEN 0 AND 100),
    record_count integer NOT NULL DEFAULT 0 CHECK (
        record_count BETWEEN 0 AND 10000
    ),
    accepted_count integer NOT NULL DEFAULT 0 CHECK (
        accepted_count BETWEEN 0 AND 10000
    ),
    quarantined_count integer NOT NULL DEFAULT 0 CHECK (
        quarantined_count BETWEEN 0 AND 10000
    ),
    failure_code text,
    cursor_available boolean NOT NULL DEFAULT false,
    reconciliation_required boolean NOT NULL DEFAULT false,
    last_application_event_id text NOT NULL,
    last_tenant_cursor bigint NOT NULL CHECK (last_tenant_cursor > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, query_id),
    FOREIGN KEY (tenant_id, source_id)
        REFERENCES aegis.evidence_sources (tenant_id, source_id),
    FOREIGN KEY (tenant_id, last_application_event_id)
        REFERENCES aegis.application_events (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS evidence_queries_status_idx
    ON aegis.evidence_queries (tenant_id, status, updated_at DESC, query_id);
CREATE INDEX IF NOT EXISTS evidence_queries_incident_idx
    ON aegis.evidence_queries (tenant_id, incident_id, updated_at, query_id);

CREATE TABLE IF NOT EXISTS aegis.evidence_cursors (
    tenant_id text NOT NULL,
    query_id text NOT NULL,
    cursor_ref text NOT NULL,
    page_number integer NOT NULL CHECK (page_number BETWEEN 1 AND 100),
    cursor_digest char(64) NOT NULL CHECK (cursor_digest ~ '^[a-f0-9]{64}$'),
    encrypted_cursor bytea NOT NULL CHECK (
        octet_length(encrypted_cursor) BETWEEN 29 AND 4128
    ),
    expires_at timestamptz NOT NULL,
    application_event_id text NOT NULL,
    PRIMARY KEY (tenant_id, query_id),
    UNIQUE (tenant_id, cursor_ref),
    FOREIGN KEY (tenant_id, query_id)
        REFERENCES aegis.evidence_queries (tenant_id, query_id),
    FOREIGN KEY (tenant_id, application_event_id)
        REFERENCES aegis.application_events (tenant_id, event_id)
);

CREATE TABLE IF NOT EXISTS aegis.evidence_metadata (
    tenant_id text NOT NULL,
    evidence_id text NOT NULL,
    incident_id text NOT NULL,
    run_id text NOT NULL,
    query_id text NOT NULL,
    source_id text NOT NULL,
    source_kind text NOT NULL,
    page_number integer NOT NULL CHECK (page_number BETWEEN 1 AND 100),
    content_hash char(64) NOT NULL CHECK (content_hash ~ '^[a-f0-9]{64}$'),
    raw_content_hash char(64) NOT NULL CHECK (
        raw_content_hash ~ '^[a-f0-9]{64}$'
    ),
    provenance_digest char(64) NOT NULL CHECK (
        provenance_digest ~ '^[a-f0-9]{64}$'
    ),
    classification text NOT NULL CHECK (
        classification IN ('public', 'internal', 'confidential', 'restricted')
    ),
    disposition text NOT NULL CHECK (
        disposition IN ('accepted', 'redacted', 'duplicate')
    ),
    retention_ref text NOT NULL,
    redaction_count integer NOT NULL DEFAULT 0 CHECK (redaction_count >= 0),
    duplicate_of text,
    observed_at timestamptz NOT NULL,
    retrieved_at timestamptz NOT NULL,
    application_event_id text NOT NULL,
    PRIMARY KEY (tenant_id, evidence_id),
    UNIQUE (tenant_id, incident_id, content_hash),
    FOREIGN KEY (tenant_id, query_id)
        REFERENCES aegis.evidence_queries (tenant_id, query_id),
    FOREIGN KEY (tenant_id, application_event_id)
        REFERENCES aegis.application_events (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS evidence_metadata_query_idx
    ON aegis.evidence_metadata (tenant_id, query_id, page_number, evidence_id);
CREATE INDEX IF NOT EXISTS evidence_metadata_incident_time_idx
    ON aegis.evidence_metadata (tenant_id, incident_id, observed_at, evidence_id);

CREATE TABLE IF NOT EXISTS aegis.evidence_quarantine (
    tenant_id text NOT NULL,
    evidence_id text NOT NULL,
    incident_id text NOT NULL,
    query_id text NOT NULL,
    source_id text NOT NULL,
    reason text NOT NULL,
    raw_content_hash char(64) NOT NULL CHECK (
        raw_content_hash ~ '^[a-f0-9]{64}$'
    ),
    scanner_summary jsonb NOT NULL CHECK (
        jsonb_typeof(scanner_summary) = 'object'
        AND pg_column_size(scanner_summary) <= 16384
    ),
    retention_ref text NOT NULL,
    quarantined_at timestamptz NOT NULL,
    application_event_id text NOT NULL,
    PRIMARY KEY (tenant_id, evidence_id),
    FOREIGN KEY (tenant_id, query_id)
        REFERENCES aegis.evidence_queries (tenant_id, query_id),
    FOREIGN KEY (tenant_id, application_event_id)
        REFERENCES aegis.application_events (tenant_id, event_id)
);

CREATE TABLE IF NOT EXISTS aegis.evidence_bundles (
    tenant_id text NOT NULL,
    bundle_id text NOT NULL,
    incident_id text NOT NULL,
    run_id text NOT NULL,
    bundle_digest char(64) NOT NULL CHECK (bundle_digest ~ '^[a-f0-9]{64}$'),
    query_count integer NOT NULL CHECK (query_count BETWEEN 1 AND 64),
    evidence_count integer NOT NULL CHECK (evidence_count BETWEEN 0 AND 10000),
    created_at timestamptz NOT NULL,
    application_event_id text NOT NULL,
    PRIMARY KEY (tenant_id, bundle_id),
    UNIQUE (tenant_id, incident_id, bundle_digest),
    FOREIGN KEY (tenant_id, application_event_id)
        REFERENCES aegis.application_events (tenant_id, event_id)
);

CREATE TABLE IF NOT EXISTS aegis.evidence_bundle_members (
    tenant_id text NOT NULL,
    bundle_id text NOT NULL,
    evidence_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 1 AND 10000),
    citation jsonb NOT NULL CHECK (
        jsonb_typeof(citation) = 'object' AND pg_column_size(citation) <= 4096
    ),
    PRIMARY KEY (tenant_id, bundle_id, evidence_id),
    UNIQUE (tenant_id, bundle_id, ordinal),
    FOREIGN KEY (tenant_id, bundle_id)
        REFERENCES aegis.evidence_bundles (tenant_id, bundle_id),
    FOREIGN KEY (tenant_id, evidence_id)
        REFERENCES aegis.evidence_metadata (tenant_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS aegis.evidence_projection_rebuilds (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    rebuild_id text NOT NULL,
    projection_name text NOT NULL,
    through_tenant_cursor bigint NOT NULL CHECK (through_tenant_cursor >= 0),
    last_event_hash char(64) NOT NULL CHECK (
        last_event_hash ~ '^[a-f0-9]{64}$'
    ),
    rebuilt_at timestamptz NOT NULL,
    application_event_id text NOT NULL,
    PRIMARY KEY (tenant_id, rebuild_id),
    FOREIGN KEY (tenant_id, application_event_id)
        REFERENCES aegis.application_events (tenant_id, event_id)
);

DROP TRIGGER IF EXISTS evidence_metadata_immutable ON aegis.evidence_metadata;
CREATE TRIGGER evidence_metadata_immutable
BEFORE UPDATE OR DELETE ON aegis.evidence_metadata
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS evidence_quarantine_immutable ON aegis.evidence_quarantine;
CREATE TRIGGER evidence_quarantine_immutable
BEFORE UPDATE OR DELETE ON aegis.evidence_quarantine
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS evidence_bundles_immutable ON aegis.evidence_bundles;
CREATE TRIGGER evidence_bundles_immutable
BEFORE UPDATE OR DELETE ON aegis.evidence_bundles
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS evidence_bundle_members_immutable
    ON aegis.evidence_bundle_members;
CREATE TRIGGER evidence_bundle_members_immutable
BEFORE UPDATE OR DELETE ON aegis.evidence_bundle_members
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS evidence_projection_rebuilds_immutable
    ON aegis.evidence_projection_rebuilds;
CREATE TRIGGER evidence_projection_rebuilds_immutable
BEFORE UPDATE OR DELETE ON aegis.evidence_projection_rebuilds
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'evidence_sources',
        'evidence_tenant_quotas',
        'evidence_queries',
        'evidence_cursors',
        'evidence_metadata',
        'evidence_quarantine',
        'evidence_bundles',
        'evidence_bundle_members',
        'evidence_projection_rebuilds'
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

GRANT SELECT ON aegis.evidence_sources TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.evidence_tenant_quotas,
    aegis.evidence_queries, aegis.evidence_cursors
    TO aegis_runtime;
GRANT DELETE ON aegis.evidence_cursors TO aegis_runtime;
GRANT SELECT, INSERT ON aegis.evidence_metadata, aegis.evidence_quarantine,
    aegis.evidence_bundles, aegis.evidence_bundle_members,
    aegis.evidence_projection_rebuilds
    TO aegis_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON aegis.evidence_metadata,
    aegis.evidence_quarantine, aegis.evidence_bundles,
    aegis.evidence_bundle_members, aegis.evidence_projection_rebuilds
    FROM aegis_runtime;

COMMIT;
