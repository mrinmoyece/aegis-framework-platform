BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('aegis-layer2-schema', 0));

CREATE SCHEMA IF NOT EXISTS aegis;
REVOKE ALL ON SCHEMA aegis FROM PUBLIC;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_runtime') THEN
        CREATE ROLE aegis_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
END
$$;

ALTER ROLE aegis_runtime NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA aegis TO aegis_runtime;

CREATE TABLE IF NOT EXISTS aegis.schema_migrations (
    version integer PRIMARY KEY,
    filename text NOT NULL UNIQUE,
    checksum char(64) NOT NULL CHECK (checksum ~ '^[a-f0-9]{64}$'),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON aegis.schema_migrations FROM PUBLIC, aegis_runtime;

CREATE OR REPLACE FUNCTION aegis.current_tenant_id()
RETURNS text
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT NULLIF(current_setting('aegis.tenant_id', true), '')
$$;
REVOKE ALL ON FUNCTION aegis.current_tenant_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegis.current_tenant_id() TO aegis_runtime;

CREATE TABLE IF NOT EXISTS aegis.tenants (
    tenant_id text PRIMARY KEY CHECK (tenant_id ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    status text NOT NULL CHECK (status IN ('active', 'suspended')),
    version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS aegis.principals (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 8 AND 512),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 255),
    principal_kind text NOT NULL CHECK (principal_kind IN ('human', 'workload')),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    grant_version bigint NOT NULL DEFAULT 1 CHECK (grant_version >= 1),
    version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, issuer, subject_id),
    UNIQUE (issuer, subject_id)
);
CREATE INDEX IF NOT EXISTS principals_tenant_status_idx
    ON aegis.principals (tenant_id, status, issuer, subject_id);

CREATE TABLE IF NOT EXISTS aegis.grants (
    tenant_id text NOT NULL,
    grant_id text NOT NULL CHECK (grant_id ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    issuer text NOT NULL,
    subject_id text NOT NULL,
    role text NOT NULL CHECK (role ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    purpose text NOT NULL CHECK (purpose ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    risk_ceiling text NOT NULL CHECK (risk_ceiling IN ('low', 'medium', 'high')),
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, grant_id),
    FOREIGN KEY (tenant_id, issuer, subject_id)
        REFERENCES aegis.principals (tenant_id, issuer, subject_id),
    CHECK (
        (status = 'active' AND revoked_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS grants_tenant_principal_active_idx
    ON aegis.grants (tenant_id, issuer, subject_id, status, expires_at);
CREATE INDEX IF NOT EXISTS grants_tenant_purpose_role_idx
    ON aegis.grants (tenant_id, purpose, role, status);

CREATE TABLE IF NOT EXISTS aegis.policies (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    policy_id text NOT NULL CHECK (policy_id ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    revision bigint NOT NULL CHECK (revision >= 1),
    allowed_actions text[] NOT NULL CHECK (cardinality(allowed_actions) > 0),
    allowed_purposes text[] NOT NULL CHECK (cardinality(allowed_purposes) > 0),
    max_risk text NOT NULL CHECK (max_risk IN ('low', 'medium', 'high')),
    version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, policy_id),
    UNIQUE (tenant_id, revision)
);
CREATE INDEX IF NOT EXISTS policies_tenant_revision_idx
    ON aegis.policies (tenant_id, revision DESC);

CREATE TABLE IF NOT EXISTS aegis.quotas (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    quota_key text NOT NULL CHECK (quota_key ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    limit_units bigint NOT NULL CHECK (limit_units >= 0),
    used_units bigint NOT NULL DEFAULT 0 CHECK (
        used_units >= 0 AND used_units <= limit_units
    ),
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, quota_key),
    CHECK (period_end > period_start)
);
CREATE INDEX IF NOT EXISTS quotas_tenant_period_idx
    ON aegis.quotas (tenant_id, period_end, quota_key);

CREATE TABLE IF NOT EXISTS aegis.quota_reservations (
    tenant_id text NOT NULL,
    quota_key text NOT NULL,
    reservation_id text NOT NULL CHECK (
        reservation_id ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    requested_units bigint NOT NULL CHECK (requested_units > 0),
    allowed boolean NOT NULL,
    remaining_units bigint NOT NULL CHECK (remaining_units >= 0),
    reason text NOT NULL CHECK (reason IN ('reserved', 'tenant_budget_exhausted')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, quota_key, reservation_id),
    FOREIGN KEY (tenant_id, quota_key)
        REFERENCES aegis.quotas (tenant_id, quota_key)
);
CREATE INDEX IF NOT EXISTS quota_reservations_tenant_created_idx
    ON aegis.quota_reservations (tenant_id, created_at, reservation_id);

CREATE TABLE IF NOT EXISTS aegis.secret_references (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    name text NOT NULL CHECK (name ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    provider text NOT NULL CHECK (provider ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    reference text NOT NULL CHECK (length(reference) BETWEEN 3 AND 512),
    version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS aegis.audit_heads (
    tenant_id text PRIMARY KEY REFERENCES aegis.tenants (tenant_id),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_hash char(64) NOT NULL DEFAULT repeat('0', 64)
        CHECK (last_hash ~ '^[a-f0-9]{64}$')
);

CREATE TABLE IF NOT EXISTS aegis.audit_events (
    tenant_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence >= 1),
    event_id text NOT NULL CHECK (event_id ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    event_type text NOT NULL CHECK (event_type ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    actor_ref text NOT NULL CHECK (actor_ref ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    principal_kind text NOT NULL CHECK (principal_kind IN ('human', 'workload')),
    recorded_at timestamptz NOT NULL,
    attributes jsonb NOT NULL CHECK (
        jsonb_typeof(attributes) = 'object'
        AND pg_column_size(attributes) <= 8192
    ),
    previous_hash char(64) NOT NULL CHECK (previous_hash ~ '^[a-f0-9]{64}$'),
    record_hash char(64) NOT NULL CHECK (record_hash ~ '^[a-f0-9]{64}$'),
    PRIMARY KEY (tenant_id, sequence),
    UNIQUE (tenant_id, event_id),
    FOREIGN KEY (tenant_id) REFERENCES aegis.audit_heads (tenant_id)
);
CREATE INDEX IF NOT EXISTS audit_events_tenant_recorded_idx
    ON aegis.audit_events (tenant_id, recorded_at DESC, sequence DESC);

CREATE OR REPLACE FUNCTION aegis.reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit events are immutable' USING ERRCODE = '55000';
END
$$;
REVOKE ALL ON FUNCTION aegis.reject_audit_mutation() FROM PUBLIC;

DROP TRIGGER IF EXISTS audit_events_immutable ON aegis.audit_events;
CREATE TRIGGER audit_events_immutable
BEFORE UPDATE OR DELETE ON aegis.audit_events
FOR EACH ROW EXECUTE FUNCTION aegis.reject_audit_mutation();

CREATE TABLE IF NOT EXISTS aegis.checkpoint_threads (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    thread_ref text NOT NULL CHECK (thread_ref ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, thread_ref),
    UNIQUE (thread_ref)
);
CREATE INDEX IF NOT EXISTS checkpoint_threads_tenant_created_idx
    ON aegis.checkpoint_threads (tenant_id, created_at, thread_ref);

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'tenants',
        'principals',
        'grants',
        'policies',
        'quotas',
        'quota_reservations',
        'secret_references',
        'audit_heads',
        'audit_events',
        'checkpoint_threads'
    ]
    LOOP
        EXECUTE format('ALTER TABLE aegis.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE aegis.%I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON aegis.%I', table_name);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON aegis.%I '
            'USING (tenant_id = aegis.current_tenant_id()) '
            'WITH CHECK (tenant_id = aegis.current_tenant_id())',
            table_name
        );
    END LOOP;
END
$$;

GRANT SELECT, INSERT, UPDATE ON aegis.tenants TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.principals TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.grants TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.policies TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.quotas TO aegis_runtime;
GRANT SELECT, INSERT ON aegis.quota_reservations TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.secret_references TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.audit_heads TO aegis_runtime;
GRANT SELECT, INSERT ON aegis.audit_events TO aegis_runtime;
GRANT SELECT, INSERT ON aegis.checkpoint_threads TO aegis_runtime;

REVOKE ALL ON ALL TABLES IN SCHEMA aegis FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON aegis.audit_events FROM aegis_runtime;
REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA aegis FROM aegis_runtime;

COMMIT;
