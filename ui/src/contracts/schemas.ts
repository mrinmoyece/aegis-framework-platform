import { z } from "zod";

const identifier = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[a-zA-Z0-9._:-]+$/);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const instant = z.iso.datetime({ offset: true });

export const operatorUserSchema = z
  .object({
    actor_ref: identifier,
    display_name: z.string().min(1).max(120),
    principal_kind: z.literal("human"),
    roles: z.array(identifier).max(16),
    permissions: z.array(identifier).max(64),
    grant_version: z.number().int().positive()
  })
  .strict();

export const sessionSchema = z
  .object({
    authenticated: z.literal(true),
    tenant_id: identifier,
    available_tenants: z.array(identifier).max(16),
    user: operatorUserSchema,
    expires_at: instant,
    server_time: instant,
    csrf_token: z.string().min(32).max(128),
    session_generation: identifier,
    session_mode: z.enum(["deterministic-demo", "oidc"])
  })
  .strict();

export const authorizationStartSchema = z
  .object({
    authorization_url: z.string().startsWith("/operator/session/callback?"),
    state: z.string().min(32).max(128),
    nonce: z.string().min(32).max(128),
    code_challenge: z.string().min(43).max(128),
    code_challenge_method: z.literal("S256"),
    code_verifier: z.string().min(43).max(128),
    expires_at: instant
  })
  .strict();

const healthItemSchema = z
  .object({
    component: identifier,
    status: z.enum(["healthy", "degraded", "unavailable"]),
    objective_percent: z.number().positive().max(100),
    budget_status: z.enum(["within", "at-risk", "exhausted"]),
    runbook: z.string().regex(/^docs\/runbooks\/[a-z0-9-]+\.md$/)
  })
  .strict();

const incidentItemSchema = z
  .object({
    incident_id: identifier,
    title: z.string().min(1).max(200),
    severity: z.enum(["sev1", "sev2", "sev3"]),
    status: z.enum(["investigating", "mitigating", "resolved"]),
    updated_at: instant,
    stale_after: instant
  })
  .strict();

const timelineItemSchema = z
  .object({
    event_id: identifier,
    occurred_at: instant,
    event_type: identifier,
    summary: z.string().min(1).max(300),
    evidence_ids: z.array(identifier).max(16)
  })
  .strict();

const evidenceItemSchema = z
  .object({
    evidence_id: identifier,
    source_kind: identifier,
    locator_label: z.string().min(1).max(120),
    content_hash: digest,
    disposition: z.enum(["accepted", "redacted", "quarantined"]),
    summary: z.string().min(1).max(300)
  })
  .strict();

const graphNodeItemSchema = z
  .object({
    role: identifier,
    status: z.enum(["complete", "abstained", "rejected"]),
    artifact_kind: identifier,
    citations: z.number().int().min(0).max(100)
  })
  .strict();

const hypothesisItemSchema = z
  .object({
    hypothesis_id: identifier,
    statement: z.string().min(1).max(300),
    confidence: z.number().min(0).max(1),
    critic: z.enum(["accepted", "abstained", "rejected"]),
    evidence_ids: z.array(identifier).min(1).max(16)
  })
  .strict();

const modelUsageItemSchema = z
  .object({
    provider: identifier,
    model: identifier,
    calls: z.number().int().min(0).max(10_000),
    input_tokens: z.number().int().nonnegative(),
    output_tokens: z.number().int().nonnegative(),
    cost_microunits: z.number().int().nonnegative(),
    ambiguous_cost_microunits: z.number().int().nonnegative()
  })
  .strict();

const approvalItemSchema = z
  .object({
    approval_id: identifier,
    status: z.enum(["pending", "approved", "denied", "expired", "revoked"]),
    risk: z.enum(["low", "medium", "high"]),
    grants: z.number().int().min(0).max(16),
    quorum: z.number().int().min(1).max(16),
    plan_digest: digest,
    approval_digest: digest,
    expires_at: instant,
    created_by_actor_ref: identifier,
    can_decide: z.boolean(),
    denial_reason: z.string().max(200).nullable(),
    target: z.string().min(1).max(200),
    rollback: z.enum(["not-required", "available", "running", "failed"])
  })
  .strict();

const effectItemSchema = z
  .object({
    effect_id: identifier,
    status: z.enum([
      "not-started",
      "executing",
      "ambiguous",
      "reconciled",
      "verified",
      "rollback-required"
    ]),
    target: z.string().min(1).max(200),
    receipt_digest: digest.nullable(),
    verification: z.enum(["not-run", "failed", "passed", "ambiguous"]),
    rollback: z.enum(["not-required", "available", "running", "failed"])
  })
  .strict();

const sandboxItemSchema = z
  .object({
    execution_id: identifier,
    status: z.enum(["complete", "failed", "quarantined"]),
    artifact_count: z.number().int().min(0).max(100),
    quarantined_count: z.number().int().min(0).max(100),
    cleanup_complete: z.boolean()
  })
  .strict();

const memoryItemSchema = z
  .object({
    memory_id: identifier,
    tier: z.enum(["working", "episodic", "semantic"]),
    provenance: z.string().min(1).max(200),
    status: z.enum(["indexed", "held", "tombstoned"]),
    retention_expires_at: instant,
    legal_hold: z.boolean()
  })
  .strict();

const evaluationItemSchema = z
  .object({
    suite_id: identifier,
    passed: z.boolean(),
    regressions: z.number().int().min(0).max(10_000),
    cases: z.number().int().min(0).max(100_000),
    baseline_digest: digest
  })
  .strict();

const auditItemSchema = z
  .object({
    event_id: identifier,
    event_type: identifier,
    actor_ref: identifier,
    recorded_at: instant,
    record_hash: digest
  })
  .strict();

const replayItemSchema = z
  .object({
    report_id: identifier,
    integrity: z.enum(["verified", "failed"]),
    projection_matches: z.boolean(),
    truncated: z.boolean(),
    report_digest: digest
  })
  .strict();

export const snapshotSchema = z
  .object({
    schema_version: z.literal(1),
    tenant_id: identifier,
    session_generation: identifier,
    generated_at: instant,
    stale_after: instant,
    synthetic: z.boolean(),
    health: z.array(healthItemSchema).max(32),
    incidents: z.array(incidentItemSchema).max(100),
    timeline: z.array(timelineItemSchema).max(200),
    evidence: z.array(evidenceItemSchema).max(200),
    graph: z.array(graphNodeItemSchema).max(32),
    hypotheses: z.array(hypothesisItemSchema).max(32),
    model_usage: z.array(modelUsageItemSchema).max(32),
    approvals: z.array(approvalItemSchema).max(100),
    effects: z.array(effectItemSchema).max(100),
    sandboxes: z.array(sandboxItemSchema).max(100),
    memories: z.array(memoryItemSchema).max(100),
    evaluations: z.array(evaluationItemSchema).max(100),
    audit: z.array(auditItemSchema).max(200),
    replay: z.array(replayItemSchema).max(100)
  })
  .strict();

export const mutationReceiptSchema = z
  .object({
    command_id: identifier,
    outcome: z.enum(["denied", "accepted", "conflict", "ambiguous"]),
    message: z.string().min(1).max(300),
    server_time: instant
  })
  .strict();

export type OperatorSession = z.infer<typeof sessionSchema>;
export type OperatorSnapshot = z.infer<typeof snapshotSchema>;
export type ApprovalItem = OperatorSnapshot["approvals"][number];
export type MutationReceipt = z.infer<typeof mutationReceiptSchema>;
