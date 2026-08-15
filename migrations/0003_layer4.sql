BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('aegis-layer4-schema', 0));

CREATE TABLE IF NOT EXISTS aegis.model_policies (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    policy_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    document jsonb NOT NULL,
    active boolean NOT NULL DEFAULT true,
    PRIMARY KEY (tenant_id, policy_id, revision)
);

CREATE UNIQUE INDEX IF NOT EXISTS model_policies_one_active_idx
    ON aegis.model_policies (tenant_id)
    WHERE active;

CREATE TABLE IF NOT EXISTS aegis.model_catalog (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    provider text NOT NULL,
    model text NOT NULL,
    region text NOT NULL,
    document jsonb NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY (tenant_id, provider, model, region)
);

CREATE TABLE IF NOT EXISTS aegis.model_budgets (
    tenant_id text PRIMARY KEY REFERENCES aegis.tenants (tenant_id),
    limit_microunits bigint NOT NULL CHECK (limit_microunits >= 0),
    reserved_microunits bigint NOT NULL DEFAULT 0
        CHECK (reserved_microunits >= 0),
    reconciled_microunits bigint NOT NULL DEFAULT 0
        CHECK (reconciled_microunits >= 0),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0)
);

CREATE TABLE IF NOT EXISTS aegis.model_reservations (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    run_id text NOT NULL,
    reservation_id text NOT NULL,
    requested_input_tokens bigint NOT NULL CHECK (requested_input_tokens >= 0),
    requested_output_tokens bigint NOT NULL CHECK (requested_output_tokens > 0),
    reserved_cost_microunits bigint NOT NULL
        CHECK (reserved_cost_microunits >= 0),
    policy_id text NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    policy_digest text NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, reservation_id)
);

CREATE INDEX IF NOT EXISTS model_reservations_tenant_run_idx
    ON aegis.model_reservations (tenant_id, run_id);

CREATE TABLE IF NOT EXISTS aegis.model_reservation_settlements (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    reservation_id text NOT NULL,
    ambiguous_billing boolean NOT NULL,
    billed_cost_microunits bigint NOT NULL CHECK (billed_cost_microunits >= 0),
    settled_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, reservation_id),
    FOREIGN KEY (tenant_id, reservation_id)
        REFERENCES aegis.model_reservations (tenant_id, reservation_id)
);

CREATE TABLE IF NOT EXISTS aegis.model_call_events (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    run_id text NOT NULL,
    call_id text NOT NULL,
    attempt_id text NOT NULL,
    event_type text NOT NULL
        CHECK (event_type IN ('requested', 'settled', 'corrected')),
    occurred_at timestamptz NOT NULL,
    record jsonb NOT NULL,
    PRIMARY KEY (tenant_id, attempt_id, event_type)
);

CREATE INDEX IF NOT EXISTS model_call_events_tenant_run_idx
    ON aegis.model_call_events (tenant_id, run_id, occurred_at, attempt_id);

CREATE TABLE IF NOT EXISTS aegis.model_usage_projection (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    run_id text NOT NULL,
    reconciled_cost_microunits bigint NOT NULL DEFAULT 0
        CHECK (reconciled_cost_microunits >= 0),
    ambiguous_cost_microunits bigint NOT NULL DEFAULT 0
        CHECK (ambiguous_cost_microunits >= 0),
    input_tokens bigint NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens bigint NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    call_count bigint NOT NULL DEFAULT 0 CHECK (call_count >= 0),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    PRIMARY KEY (tenant_id, run_id)
);

CREATE TABLE IF NOT EXISTS aegis.provider_health_projection (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    provider text NOT NULL,
    model text NOT NULL,
    region text NOT NULL,
    observed_calls bigint NOT NULL DEFAULT 0 CHECK (observed_calls >= 0),
    failure_count bigint NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, provider, model, region)
);

CREATE OR REPLACE FUNCTION aegis.reject_model_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'model ledger facts are immutable';
END;
$$;

DROP TRIGGER IF EXISTS model_reservations_immutable
    ON aegis.model_reservations;
CREATE TRIGGER model_reservations_immutable
BEFORE UPDATE OR DELETE ON aegis.model_reservations
FOR EACH ROW EXECUTE FUNCTION aegis.reject_model_fact_mutation();

DROP TRIGGER IF EXISTS model_call_events_immutable
    ON aegis.model_call_events;
CREATE TRIGGER model_call_events_immutable
BEFORE UPDATE OR DELETE ON aegis.model_call_events
FOR EACH ROW EXECUTE FUNCTION aegis.reject_model_fact_mutation();

DROP TRIGGER IF EXISTS model_reservation_settlements_immutable
    ON aegis.model_reservation_settlements;
CREATE TRIGGER model_reservation_settlements_immutable
BEFORE UPDATE OR DELETE ON aegis.model_reservation_settlements
FOR EACH ROW EXECUTE FUNCTION aegis.reject_model_fact_mutation();

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'model_policies',
        'model_catalog',
        'model_budgets',
        'model_reservations',
        'model_reservation_settlements',
        'model_call_events',
        'model_usage_projection',
        'provider_health_projection'
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

GRANT SELECT ON aegis.model_policies, aegis.model_catalog
    TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.model_budgets TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON aegis.model_usage_projection,
    aegis.provider_health_projection
    TO aegis_runtime;
GRANT SELECT, INSERT ON aegis.model_reservations,
    aegis.model_reservation_settlements, aegis.model_call_events
    TO aegis_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON aegis.model_reservations,
    aegis.model_reservation_settlements, aegis.model_call_events
    FROM aegis_runtime;

COMMIT;
