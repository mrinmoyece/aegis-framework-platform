import type { OperatorSession, OperatorSnapshot } from "./contracts/schemas";

const now = "2026-08-17T18:00:00Z";
const later = "2026-08-17T18:30:00Z";
const digest = "a".repeat(64);

export const fixtureSession: OperatorSession = {
  authenticated: true,
  tenant_id: "tenant-acme",
  available_tenants: ["tenant-acme", "tenant-beta"],
  user: {
    actor_ref: "actor-responder",
    display_name: "Incident responder",
    principal_kind: "human",
    roles: ["incident-responder"],
    permissions: ["investigation:read"],
    grant_version: 1
  },
  expires_at: later,
  server_time: now,
  csrf_token: "c".repeat(43),
  session_generation: "session-fixture-1",
  session_mode: "deterministic-demo"
};

export const fixtureSnapshot: OperatorSnapshot = {
  schema_version: 1,
  tenant_id: "tenant-acme",
  session_generation: "session-fixture-1",
  generated_at: now,
  stale_after: later,
  synthetic: true,
  health: [
    {
      component: "api",
      status: "healthy",
      objective_percent: 99.9,
      budget_status: "within",
      runbook: "docs/runbooks/api-availability.md"
    }
  ],
  incidents: [
    {
      incident_id: "incident-1",
      title: "Checkout failures",
      severity: "sev1",
      status: "investigating",
      updated_at: now,
      stale_after: later
    }
  ],
  timeline: [
    {
      event_id: "event-1",
      occurred_at: now,
      event_type: "alert.received",
      summary: "Failure rate increased.",
      evidence_ids: ["evidence-1"]
    }
  ],
  evidence: [
    {
      evidence_id: "evidence-1",
      source_kind: "telemetry",
      locator_label: "redacted locator",
      content_hash: digest,
      disposition: "accepted",
      summary: "<img src=x onerror=alert(1)> must remain text"
    }
  ],
  graph: [
    {
      role: "critic",
      status: "complete",
      artifact_kind: "critique",
      citations: 1
    }
  ],
  hypotheses: [
    {
      hypothesis_id: "hypothesis-1",
      statement: "Deployment is temporally correlated.",
      confidence: 0.8,
      critic: "accepted",
      evidence_ids: ["evidence-1"]
    }
  ],
  model_usage: [
    {
      provider: "fake",
      model: "deterministic",
      calls: 1,
      input_tokens: 100,
      output_tokens: 20,
      cost_microunits: 0,
      ambiguous_cost_microunits: 0
    }
  ],
  approvals: [
    {
      approval_id: "approval-1",
      status: "pending",
      risk: "high",
      grants: 0,
      quorum: 2,
      plan_digest: digest,
      approval_digest: digest,
      expires_at: later,
      created_by_actor_ref: "actor-planner",
      can_decide: false,
      denial_reason: "Current grants do not permit approval.",
      target: "exact target",
      rollback: "available"
    }
  ],
  effects: [
    {
      effect_id: "effect-1",
      status: "ambiguous",
      target: "exact target",
      receipt_digest: null,
      verification: "ambiguous",
      rollback: "available"
    }
  ],
  sandboxes: [
    {
      execution_id: "sandbox-1",
      status: "quarantined",
      artifact_count: 1,
      quarantined_count: 1,
      cleanup_complete: true
    }
  ],
  memories: [
    {
      memory_id: "memory-1",
      tier: "semantic",
      provenance: "accepted evidence",
      status: "held",
      retention_expires_at: later,
      legal_hold: true
    }
  ],
  evaluations: [
    {
      suite_id: "suite-1",
      passed: true,
      regressions: 0,
      cases: 50,
      baseline_digest: digest
    }
  ],
  audit: [
    {
      event_id: "audit-1",
      event_type: "operator.read",
      actor_ref: "actor-responder",
      recorded_at: now,
      record_hash: digest
    }
  ],
  replay: [
    {
      report_id: "replay-1",
      integrity: "verified",
      projection_matches: true,
      truncated: false,
      report_digest: digest
    }
  ],
  protocol_peers: [
    {
      peer_id: "partner-investigator",
      protocol: "a2a",
      owner_ref: "team-response",
      environment: "staging",
      trust_tier: "partner",
      status: "active",
      revision: 3,
      card_digest: digest,
      schema_digest: digest,
      certificate_digest: digest,
      key_digest: digest,
      capabilities: ["investigate-incident"],
      transports: ["json-rpc-http"],
      classifications: ["internal"],
      risks: ["low", "medium"],
      review_after: later,
      expires_at: later,
      production_ready: false,
      can_administer: true
    }
  ]
};
