BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('aegis-layer3-schema', 0));

CREATE TABLE IF NOT EXISTS aegis.ledger_aggregate_heads (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    aggregate_type text NOT NULL CHECK (
        aggregate_type ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    aggregate_id text NOT NULL CHECK (
        aggregate_id ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_hash char(64) NOT NULL DEFAULT repeat('0', 64)
        CHECK (last_hash ~ '^[a-f0-9]{64}$'),
    PRIMARY KEY (tenant_id, aggregate_type, aggregate_id)
);

CREATE TABLE IF NOT EXISTS aegis.ledger_tenant_cursors (
    tenant_id text PRIMARY KEY REFERENCES aegis.tenants (tenant_id),
    last_cursor bigint NOT NULL DEFAULT 0 CHECK (last_cursor >= 0),
    last_hash char(64) NOT NULL DEFAULT repeat('0', 64)
        CHECK (last_hash ~ '^[a-f0-9]{64}$')
);

CREATE TABLE IF NOT EXISTS aegis.application_events (
    tenant_id text NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id text NOT NULL,
    aggregate_sequence bigint NOT NULL CHECK (aggregate_sequence >= 1),
    tenant_cursor bigint NOT NULL CHECK (tenant_cursor >= 1),
    event_id text NOT NULL CHECK (event_id ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    event_type text NOT NULL CHECK (event_type ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    occurred_at timestamptz NOT NULL,
    actor_ref text NOT NULL CHECK (actor_ref ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    correlation_ref text NOT NULL CHECK (
        correlation_ref ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    causation_ref text CHECK (
        causation_ref IS NULL
        OR causation_ref ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    schema_version integer NOT NULL CHECK (schema_version BETWEEN 1 AND 1000),
    payload jsonb NOT NULL CHECK (
        jsonb_typeof(payload) = 'object'
        AND pg_column_size(payload) <= 32768
    ),
    aggregate_previous_hash char(64) NOT NULL CHECK (
        aggregate_previous_hash ~ '^[a-f0-9]{64}$'
    ),
    tenant_previous_hash char(64) NOT NULL CHECK (
        tenant_previous_hash ~ '^[a-f0-9]{64}$'
    ),
    record_hash char(64) NOT NULL CHECK (record_hash ~ '^[a-f0-9]{64}$'),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (
        tenant_id,
        aggregate_type,
        aggregate_id,
        aggregate_sequence
    ),
    UNIQUE (tenant_id, tenant_cursor),
    UNIQUE (tenant_id, event_id),
    FOREIGN KEY (tenant_id, aggregate_type, aggregate_id)
        REFERENCES aegis.ledger_aggregate_heads (
            tenant_id,
            aggregate_type,
            aggregate_id
        ),
    FOREIGN KEY (tenant_id) REFERENCES aegis.ledger_tenant_cursors (tenant_id)
);
CREATE INDEX IF NOT EXISTS application_events_tenant_cursor_idx
    ON aegis.application_events (tenant_id, tenant_cursor);
CREATE INDEX IF NOT EXISTS application_events_aggregate_idx
    ON aegis.application_events (
        tenant_id,
        aggregate_type,
        aggregate_id,
        aggregate_sequence
    );
CREATE INDEX IF NOT EXISTS application_events_type_idx
    ON aegis.application_events (tenant_id, event_type, tenant_cursor);

CREATE TABLE IF NOT EXISTS aegis.durable_idempotency (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    request_id text NOT NULL CHECK (
        request_id ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    fingerprint char(64) NOT NULL CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
    aggregate_type text NOT NULL,
    aggregate_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, request_id),
    FOREIGN KEY (tenant_id, aggregate_type, aggregate_id)
        REFERENCES aegis.ledger_aggregate_heads (
            tenant_id,
            aggregate_type,
            aggregate_id
        )
);

CREATE TABLE IF NOT EXISTS aegis.durable_actor_bindings (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    actor_ref text NOT NULL CHECK (
        actor_ref ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 8 AND 512),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 255),
    principal_kind text NOT NULL CHECK (
        principal_kind IN ('human', 'workload')
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, actor_ref),
    FOREIGN KEY (tenant_id, issuer, subject_id)
        REFERENCES aegis.principals (tenant_id, issuer, subject_id)
);

CREATE TABLE IF NOT EXISTS aegis.inbox_messages (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    message_id text NOT NULL CHECK (
        message_id ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    source text NOT NULL CHECK (source ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    message_type text NOT NULL CHECK (
        message_type ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    payload_hash char(64) NOT NULL CHECK (payload_hash ~ '^[a-f0-9]{64}$'),
    payload jsonb NOT NULL CHECK (
        jsonb_typeof(payload) = 'object'
        AND pg_column_size(payload) <= 8192
    ),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, message_id)
);

CREATE TABLE IF NOT EXISTS aegis.outbox_messages (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    message_id text NOT NULL CHECK (
        message_id ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    destination text NOT NULL CHECK (
        destination ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    message_type text NOT NULL CHECK (
        message_type ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    payload jsonb NOT NULL CHECK (
        jsonb_typeof(payload) = 'object'
        AND pg_column_size(payload) <= 8192
    ),
    status text NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'claimed', 'delivered', 'dead_letter')
    ),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    available_at timestamptz NOT NULL,
    claim_token text CHECK (
        claim_token IS NULL
        OR claim_token ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    claim_until timestamptz,
    last_error_code text CHECK (
        last_error_code IS NULL
        OR last_error_code ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    delivered_at timestamptz,
    PRIMARY KEY (tenant_id, message_id),
    CHECK (
        (status = 'claimed' AND claim_token IS NOT NULL AND claim_until IS NOT NULL)
        OR (status <> 'claimed' AND claim_token IS NULL AND claim_until IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS outbox_claim_idx
    ON aegis.outbox_messages (status, available_at, tenant_id, message_id)
    WHERE status IN ('pending', 'claimed');

CREATE TABLE IF NOT EXISTS aegis.projection_checkpoints (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    projection_name text NOT NULL CHECK (
        projection_name ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    last_cursor bigint NOT NULL CHECK (last_cursor >= 0),
    last_event_hash char(64) NOT NULL CHECK (
        last_event_hash ~ '^[a-f0-9]{64}$'
    ),
    version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
    rebuilt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, projection_name)
);

CREATE TABLE IF NOT EXISTS aegis.investigation_runs (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    run_id text NOT NULL CHECK (run_id ~ '^[a-zA-Z0-9._:-]{1,128}$'),
    incident_id text NOT NULL CHECK (
        incident_id ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    request_ref text NOT NULL CHECK (
        request_ref ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    workflow_id text NOT NULL CHECK (
        workflow_id ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    status text NOT NULL CHECK (
        status IN (
            'queued',
            'running',
            'waiting',
            'completed',
            'failed',
            'cancel_requested',
            'cancelled',
            'timed_out'
        )
    ),
    failure_code text CHECK (
        failure_code IS NULL
        OR failure_code ~ '^[a-zA-Z0-9._:-]{1,128}$'
    ),
    version bigint NOT NULL CHECK (version >= 1),
    last_cursor bigint NOT NULL CHECK (last_cursor >= 1),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    UNIQUE (tenant_id, workflow_id)
);
CREATE INDEX IF NOT EXISTS investigation_runs_status_idx
    ON aegis.investigation_runs (tenant_id, status, updated_at DESC, run_id);

CREATE TABLE IF NOT EXISTS aegis.investigation_timeline (
    tenant_id text NOT NULL,
    run_id text NOT NULL,
    tenant_cursor bigint NOT NULL,
    event_type text NOT NULL,
    status text NOT NULL,
    failure_code text,
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id, tenant_cursor),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES aegis.investigation_runs (tenant_id, run_id)
        ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION aegis.reject_immutable_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'application facts are immutable' USING ERRCODE = '55000';
END
$$;
REVOKE ALL ON FUNCTION aegis.reject_immutable_fact() FROM PUBLIC;

DROP TRIGGER IF EXISTS application_events_immutable ON aegis.application_events;
CREATE TRIGGER application_events_immutable
BEFORE UPDATE OR DELETE ON aegis.application_events
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS durable_idempotency_immutable ON aegis.durable_idempotency;
CREATE TRIGGER durable_idempotency_immutable
BEFORE UPDATE OR DELETE ON aegis.durable_idempotency
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS inbox_messages_immutable ON aegis.inbox_messages;
CREATE TRIGGER inbox_messages_immutable
BEFORE UPDATE OR DELETE ON aegis.inbox_messages
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS durable_actor_bindings_immutable
    ON aegis.durable_actor_bindings;
CREATE TRIGGER durable_actor_bindings_immutable
BEFORE UPDATE OR DELETE ON aegis.durable_actor_bindings
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'ledger_aggregate_heads',
        'ledger_tenant_cursors',
        'application_events',
        'durable_idempotency',
        'durable_actor_bindings',
        'inbox_messages',
        'outbox_messages',
        'projection_checkpoints',
        'investigation_runs',
        'investigation_timeline'
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

GRANT SELECT, INSERT, UPDATE ON aegis.ledger_aggregate_heads TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.ledger_tenant_cursors TO aegis_runtime;
GRANT SELECT, INSERT ON aegis.application_events TO aegis_runtime;
GRANT SELECT, INSERT ON aegis.durable_idempotency TO aegis_runtime;
GRANT SELECT, INSERT ON aegis.durable_actor_bindings TO aegis_runtime;
GRANT SELECT, INSERT ON aegis.inbox_messages TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.outbox_messages TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.projection_checkpoints TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.investigation_runs TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.investigation_timeline TO aegis_runtime;

REVOKE ALL ON ALL TABLES IN SCHEMA aegis FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON aegis.application_events FROM aegis_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON aegis.durable_idempotency FROM aegis_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON aegis.durable_actor_bindings FROM aegis_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON aegis.inbox_messages FROM aegis_runtime;
REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA aegis FROM aegis_runtime;

COMMIT;
