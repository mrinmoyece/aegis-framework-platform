BEGIN;

SELECT pg_advisory_xact_lock(hashtextextended('aegis-layer7-schema', 0));

CREATE TABLE IF NOT EXISTS aegis.remediation_plans (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    plan_id text NOT NULL,
    run_id text NOT NULL,
    incident_id text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version BETWEEN 1 AND 1000),
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    target_fingerprint char(64) NOT NULL CHECK (
        target_fingerprint ~ '^[a-f0-9]{64}$'
    ),
    risk text NOT NULL CHECK (risk IN ('low', 'medium', 'high')),
    blast_radius text NOT NULL CHECK (
        blast_radius IN ('one-replica-set', 'one-service', 'multi-service')
    ),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    plan_document jsonb NOT NULL CHECK (
        jsonb_typeof(plan_document) = 'object'
        AND pg_column_size(plan_document) <= 131072
    ),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    PRIMARY KEY (tenant_id, plan_id),
    UNIQUE (tenant_id, plan_digest)
);

CREATE TABLE IF NOT EXISTS aegis.action_policies (
    tenant_id text PRIMARY KEY REFERENCES aegis.tenants (tenant_id),
    policy_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 1),
    role_revision bigint NOT NULL CHECK (role_revision >= 1),
    quota_revision bigint NOT NULL CHECK (quota_revision >= 1),
    enabled boolean NOT NULL DEFAULT false,
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    policy_document jsonb NOT NULL CHECK (
        jsonb_typeof(policy_document) = 'object'
        AND pg_column_size(policy_document) <= 65536
    ),
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS aegis.effect_quotas (
    tenant_id text NOT NULL REFERENCES aegis.tenants (tenant_id),
    quota_key text NOT NULL,
    limit_count bigint NOT NULL CHECK (limit_count >= 0),
    reserved_count bigint NOT NULL DEFAULT 0 CHECK (reserved_count >= 0),
    settled_count bigint NOT NULL DEFAULT 0 CHECK (settled_count >= 0),
    version bigint NOT NULL CHECK (version >= 1),
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL CHECK (period_end > period_start),
    PRIMARY KEY (tenant_id, quota_key),
    CHECK (reserved_count + settled_count <= limit_count)
);

CREATE TABLE IF NOT EXISTS aegis.effect_quota_reservations (
    tenant_id text NOT NULL,
    reservation_id text NOT NULL,
    quota_key text NOT NULL,
    plan_id text NOT NULL,
    amount bigint NOT NULL CHECK (amount > 0),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    status text NOT NULL CHECK (status IN ('reserved', 'settled', 'released')),
    reserved_at timestamptz NOT NULL,
    settled_at timestamptz,
    PRIMARY KEY (tenant_id, reservation_id),
    FOREIGN KEY (tenant_id, quota_key)
        REFERENCES aegis.effect_quotas (tenant_id, quota_key),
    FOREIGN KEY (tenant_id, plan_id)
        REFERENCES aegis.remediation_plans (tenant_id, plan_id)
);

CREATE TABLE IF NOT EXISTS aegis.action_approvals (
    tenant_id text NOT NULL,
    approval_id text NOT NULL,
    plan_id text NOT NULL,
    approval_digest char(64) NOT NULL CHECK (approval_digest ~ '^[a-f0-9]{64}$'),
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    target_fingerprint char(64) NOT NULL CHECK (
        target_fingerprint ~ '^[a-f0-9]{64}$'
    ),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    quorum integer NOT NULL CHECK (quorum BETWEEN 1 AND 5),
    requested_by_ref text NOT NULL,
    approval_document jsonb NOT NULL CHECK (
        jsonb_typeof(approval_document) = 'object'
        AND pg_column_size(approval_document) <= 65536
    ),
    requested_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > requested_at),
    PRIMARY KEY (tenant_id, approval_id),
    UNIQUE (tenant_id, plan_id),
    FOREIGN KEY (tenant_id, plan_id)
        REFERENCES aegis.remediation_plans (tenant_id, plan_id)
);

CREATE TABLE IF NOT EXISTS aegis.approval_decisions (
    tenant_id text NOT NULL,
    decision_id text NOT NULL,
    command_id text NOT NULL,
    approval_id text NOT NULL,
    approver_ref text NOT NULL,
    approver_role text NOT NULL,
    disposition text NOT NULL CHECK (disposition IN ('grant', 'deny')),
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    approval_digest char(64) NOT NULL CHECK (approval_digest ~ '^[a-f0-9]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    role_revision bigint NOT NULL CHECK (role_revision >= 1),
    rationale text NOT NULL CHECK (length(rationale) BETWEEN 1 AND 2000),
    decision_digest char(64) NOT NULL CHECK (decision_digest ~ '^[a-f0-9]{64}$'),
    decision_document jsonb NOT NULL CHECK (
        jsonb_typeof(decision_document) = 'object'
        AND pg_column_size(decision_document) <= 32768
    ),
    decided_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, decision_id),
    UNIQUE (tenant_id, command_id),
    UNIQUE (tenant_id, approval_id, approver_ref),
    FOREIGN KEY (tenant_id, approval_id)
        REFERENCES aegis.action_approvals (tenant_id, approval_id)
);

CREATE TABLE IF NOT EXISTS aegis.remediation_facts (
    tenant_id text NOT NULL,
    plan_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence >= 1),
    fact_id text NOT NULL,
    fact_type text NOT NULL CHECK (fact_type LIKE 'remediation.%'),
    command_id text NOT NULL,
    actor_ref text NOT NULL,
    fact_document jsonb NOT NULL CHECK (
        jsonb_typeof(fact_document) = 'object'
        AND pg_column_size(fact_document) <= 65536
    ),
    previous_digest char(64) NOT NULL CHECK (previous_digest ~ '^[a-f0-9]{64}$'),
    fact_digest char(64) NOT NULL CHECK (fact_digest ~ '^[a-f0-9]{64}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, plan_id, sequence),
    UNIQUE (tenant_id, fact_id),
    UNIQUE (tenant_id, command_id),
    FOREIGN KEY (tenant_id, plan_id)
        REFERENCES aegis.remediation_plans (tenant_id, plan_id)
);

CREATE TABLE IF NOT EXISTS aegis.effect_attempts (
    tenant_id text NOT NULL,
    plan_id text NOT NULL,
    action_id text NOT NULL,
    operation_id text NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 16),
    idempotency_key text NOT NULL,
    action_digest char(64) NOT NULL CHECK (action_digest ~ '^[a-f0-9]{64}$'),
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    approval_digest char(64) NOT NULL CHECK (approval_digest ~ '^[a-f0-9]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    target_fingerprint char(64) NOT NULL CHECK (
        target_fingerprint ~ '^[a-f0-9]{64}$'
    ),
    fence_token text NOT NULL,
    status text NOT NULL CHECK (
        status IN (
            'requested', 'claimed', 'started', 'succeeded', 'failed',
            'ambiguous', 'reconciling', 'compensated', 'cancelled', 'escalated'
        )
    ),
    claim_token text,
    claim_until timestamptz,
    worker_ref text,
    receipt_digest char(64) CHECK (
        receipt_digest IS NULL OR receipt_digest ~ '^[a-f0-9]{64}$'
    ),
    receipt_document jsonb CHECK (
        receipt_document IS NULL OR (
            jsonb_typeof(receipt_document) = 'object'
            AND pg_column_size(receipt_document) <= 65536
        )
    ),
    requested_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, plan_id, action_id, attempt),
    UNIQUE (tenant_id, idempotency_key),
    FOREIGN KEY (tenant_id, plan_id)
        REFERENCES aegis.remediation_plans (tenant_id, plan_id),
    CHECK (
        (status = 'claimed' AND claim_token IS NOT NULL AND claim_until IS NOT NULL)
        OR status <> 'claimed'
    )
);
CREATE INDEX IF NOT EXISTS effect_attempt_claim_idx
    ON aegis.effect_attempts (tenant_id, status, claim_until, requested_at);

CREATE TABLE IF NOT EXISTS aegis.effect_receipts (
    tenant_id text NOT NULL,
    plan_id text NOT NULL,
    action_id text NOT NULL,
    operation_id text NOT NULL,
    receipt_digest char(64) NOT NULL CHECK (receipt_digest ~ '^[a-f0-9]{64}$'),
    outcome text NOT NULL,
    receipt_document jsonb NOT NULL CHECK (
        jsonb_typeof(receipt_document) = 'object'
        AND pg_column_size(receipt_document) <= 65536
    ),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, operation_id, receipt_digest),
    FOREIGN KEY (tenant_id, plan_id)
        REFERENCES aegis.remediation_plans (tenant_id, plan_id)
);

CREATE TABLE IF NOT EXISTS aegis.verification_records (
    tenant_id text NOT NULL,
    verification_id text NOT NULL,
    plan_id text NOT NULL,
    action_id text NOT NULL,
    effect_receipt_digest char(64) NOT NULL CHECK (
        effect_receipt_digest ~ '^[a-f0-9]{64}$'
    ),
    verification_digest char(64) NOT NULL CHECK (
        verification_digest ~ '^[a-f0-9]{64}$'
    ),
    postconditions_satisfied boolean NOT NULL,
    verification_document jsonb NOT NULL CHECK (
        jsonb_typeof(verification_document) = 'object'
        AND pg_column_size(verification_document) <= 65536
    ),
    verified_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, verification_id),
    FOREIGN KEY (tenant_id, plan_id)
        REFERENCES aegis.remediation_plans (tenant_id, plan_id)
);

CREATE TABLE IF NOT EXISTS aegis.remediation_projections (
    tenant_id text NOT NULL,
    plan_id text NOT NULL,
    run_id text NOT NULL,
    status text NOT NULL,
    version bigint NOT NULL CHECK (version >= 1),
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    approval_id text,
    approval_digest char(64),
    effect_receipt_digest char(64),
    verification_digest char(64),
    fence_token text NOT NULL,
    last_fact_digest char(64) NOT NULL CHECK (
        last_fact_digest ~ '^[a-f0-9]{64}$'
    ),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, plan_id),
    FOREIGN KEY (tenant_id, plan_id)
        REFERENCES aegis.remediation_plans (tenant_id, plan_id)
);

CREATE TABLE IF NOT EXISTS aegis.remediation_projection_rebuilds (
    tenant_id text NOT NULL,
    rebuild_id text NOT NULL,
    plan_id text NOT NULL,
    source_fact_count bigint NOT NULL CHECK (source_fact_count >= 1),
    source_digest char(64) NOT NULL CHECK (source_digest ~ '^[a-f0-9]{64}$'),
    projection_digest char(64) NOT NULL CHECK (
        projection_digest ~ '^[a-f0-9]{64}$'
    ),
    rebuilt_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, rebuild_id),
    FOREIGN KEY (tenant_id, plan_id)
        REFERENCES aegis.remediation_plans (tenant_id, plan_id)
);

DROP TRIGGER IF EXISTS remediation_plans_immutable ON aegis.remediation_plans;
CREATE TRIGGER remediation_plans_immutable
BEFORE UPDATE OR DELETE ON aegis.remediation_plans
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS effect_quota_reservations_immutable
    ON aegis.effect_quota_reservations;
CREATE TRIGGER effect_quota_reservations_immutable
BEFORE UPDATE OR DELETE ON aegis.effect_quota_reservations
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS action_approvals_immutable ON aegis.action_approvals;
CREATE TRIGGER action_approvals_immutable
BEFORE UPDATE OR DELETE ON aegis.action_approvals
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS approval_decisions_immutable ON aegis.approval_decisions;
CREATE TRIGGER approval_decisions_immutable
BEFORE UPDATE OR DELETE ON aegis.approval_decisions
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS remediation_facts_immutable ON aegis.remediation_facts;
CREATE TRIGGER remediation_facts_immutable
BEFORE UPDATE OR DELETE ON aegis.remediation_facts
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS effect_receipts_immutable ON aegis.effect_receipts;
CREATE TRIGGER effect_receipts_immutable
BEFORE UPDATE OR DELETE ON aegis.effect_receipts
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS verification_records_immutable ON aegis.verification_records;
CREATE TRIGGER verification_records_immutable
BEFORE UPDATE OR DELETE ON aegis.verification_records
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DROP TRIGGER IF EXISTS remediation_projection_rebuilds_immutable
    ON aegis.remediation_projection_rebuilds;
CREATE TRIGGER remediation_projection_rebuilds_immutable
BEFORE UPDATE OR DELETE ON aegis.remediation_projection_rebuilds
FOR EACH ROW EXECUTE FUNCTION aegis.reject_immutable_fact();

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'remediation_plans',
        'action_policies',
        'effect_quotas',
        'effect_quota_reservations',
        'action_approvals',
        'approval_decisions',
        'remediation_facts',
        'effect_attempts',
        'effect_receipts',
        'verification_records',
        'remediation_projections',
        'remediation_projection_rebuilds'
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

GRANT SELECT, INSERT ON aegis.remediation_plans,
    aegis.effect_quota_reservations,
    aegis.action_approvals,
    aegis.approval_decisions,
    aegis.remediation_facts,
    aegis.effect_receipts,
    aegis.verification_records,
    aegis.remediation_projection_rebuilds TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON aegis.action_policies,
    aegis.effect_quotas,
    aegis.effect_attempts,
    aegis.remediation_projections TO aegis_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON aegis.remediation_plans,
    aegis.effect_quota_reservations,
    aegis.action_approvals,
    aegis.approval_decisions,
    aegis.remediation_facts,
    aegis.effect_receipts,
    aegis.verification_records,
    aegis.remediation_projection_rebuilds FROM aegis_runtime;

COMMIT;
