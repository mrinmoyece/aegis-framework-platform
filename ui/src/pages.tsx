import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { useId, useRef, useState } from "react";

import { operatorApi } from "./api/client";
import { DataTable } from "./components/DataTable";
import { Status, Timestamp } from "./components/Status";
import type { ApprovalItem, OperatorSnapshot } from "./contracts/schemas";
import { useOperator } from "./operator-context";
import { redactError } from "./safety";

type Health = OperatorSnapshot["health"][number];
type Incident = OperatorSnapshot["incidents"][number];
type Timeline = OperatorSnapshot["timeline"][number];
type Evidence = OperatorSnapshot["evidence"][number];
type GraphNode = OperatorSnapshot["graph"][number];
type ModelUsage = OperatorSnapshot["model_usage"][number];
type Effect = OperatorSnapshot["effects"][number];
type Sandbox = OperatorSnapshot["sandboxes"][number];
type Memory = OperatorSnapshot["memories"][number];
type Evaluation = OperatorSnapshot["evaluations"][number];
type Audit = OperatorSnapshot["audit"][number];
type Replay = OperatorSnapshot["replay"][number];

export function OverviewPage() {
  const { snapshot } = useOperator();
  const healthColumns: ColumnDef<Health>[] = [
    { accessorKey: "component", header: "Component" },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ getValue }) => <Status value={String(getValue())} />
    },
    {
      accessorKey: "objective_percent",
      header: "SLO objective",
      cell: ({ getValue }) => `${String(getValue())}%`
    },
    { accessorKey: "budget_status", header: "Error budget" },
    { accessorKey: "runbook", header: "Runbook" }
  ];
  const incidentColumns: ColumnDef<Incident>[] = [
    { accessorKey: "incident_id", header: "Incident" },
    { accessorKey: "title", header: "Title" },
    { accessorKey: "severity", header: "Severity" },
    { accessorKey: "status", header: "Status" },
    {
      accessorKey: "updated_at",
      header: "Updated",
      cell: ({ getValue }) => <Timestamp value={String(getValue())} />
    }
  ];
  return (
    <Page
      title="Health and active incidents"
      description="Derived operational views only."
    >
      <DataTable
        caption="Service health and SLOs"
        columns={healthColumns}
        data={snapshot.health}
      />
      <DataTable
        caption="Authorized incidents"
        columns={incidentColumns}
        data={snapshot.incidents}
      />
    </Page>
  );
}

export function InvestigationPage() {
  const { snapshot } = useOperator();
  const timelineColumns: ColumnDef<Timeline>[] = [
    {
      accessorKey: "occurred_at",
      header: "Occurred",
      cell: ({ getValue }) => <Timestamp value={String(getValue())} />
    },
    { accessorKey: "event_type", header: "Event" },
    { accessorKey: "summary", header: "Summary" },
    {
      accessorKey: "evidence_ids",
      header: "Citations",
      cell: ({ getValue }) => getValue<string[]>().join(", ")
    }
  ];
  const evidenceColumns: ColumnDef<Evidence>[] = [
    { accessorKey: "evidence_id", header: "Evidence ID" },
    { accessorKey: "source_kind", header: "Source" },
    { accessorKey: "locator_label", header: "Locator" },
    { accessorKey: "disposition", header: "Disposition" },
    { accessorKey: "summary", header: "Bounded summary" }
  ];
  const graphColumns: ColumnDef<GraphNode>[] = [
    { accessorKey: "role", header: "Specialist" },
    { accessorKey: "status", header: "Status" },
    { accessorKey: "artifact_kind", header: "Artifact" },
    { accessorKey: "citations", header: "Citations" }
  ];
  return (
    <Page
      title="Cited investigation"
      description="Timeline, evidence, specialist DAG, hypotheses, and critic decisions."
    >
      <DataTable
        caption="Cited incident timeline"
        columns={timelineColumns}
        data={snapshot.timeline}
      />
      <DataTable
        caption="Evidence projections"
        columns={evidenceColumns}
        data={snapshot.evidence}
      />
      <DataTable
        caption="Bounded specialist DAG"
        columns={graphColumns}
        data={snapshot.graph}
      />
      <section aria-labelledby="hypotheses-title" className="panel">
        <h2 id="hypotheses-title">Hypotheses and critic</h2>
        {snapshot.hypotheses.map((item) => (
          <article key={item.hypothesis_id}>
            <h3>{item.hypothesis_id}</h3>
            <p>{item.statement}</p>
            <p>
              Confidence {(item.confidence * 100).toFixed(0)}%; critic{" "}
              <Status value={item.critic} />
            </p>
            <p>Cites: {item.evidence_ids.join(", ")}</p>
          </article>
        ))}
      </section>
    </Page>
  );
}

export function ModelsPage() {
  const { snapshot } = useOperator();
  const columns: ColumnDef<ModelUsage>[] = [
    { accessorKey: "provider", header: "Provider" },
    { accessorKey: "model", header: "Model" },
    { accessorKey: "calls", header: "Calls" },
    { accessorKey: "input_tokens", header: "Input tokens" },
    { accessorKey: "output_tokens", header: "Output tokens" },
    { accessorKey: "cost_microunits", header: "Reconciled cost (µ)" },
    { accessorKey: "ambiguous_cost_microunits", header: "Ambiguous cost (µ)" }
  ];
  return (
    <Page title="Model usage" description="Settled and ambiguous usage remain distinct.">
      <div
        className="bar-chart"
        role="img"
        aria-label="Input and output token comparison; exact values are in the following table."
      >
        {snapshot.model_usage.map((item) => (
          <div key={item.model} className="bar-row">
            <span>{item.model}</span>
            <span
              className="bar"
              style={{ width: `${Math.min(100, item.input_tokens / 50)}%` }}
            />
          </div>
        ))}
      </div>
      <DataTable
        caption="Model usage ledger projection"
        columns={columns}
        data={snapshot.model_usage}
      />
    </Page>
  );
}

export function ApprovalsPage() {
  const { snapshot } = useOperator();
  return (
    <Page
      title="Exact-scope approvals"
      description="The UI exposes scope, quorum, separation of duties, and server denial."
    >
      {snapshot.approvals.map((approval) => (
        <ApprovalCard key={approval.approval_id} approval={approval} />
      ))}
    </Page>
  );
}

function ApprovalCard({ approval }: { approval: ApprovalItem }) {
  const { session, serverNow } = useOperator();
  const queryClient = useQueryClient();
  const [confirmation, setConfirmation] = useState("");
  const [rationale, setRationale] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const confirmationId = useId();
  const rationaleId = useId();
  // Stable command_id: generated once per component mount so that a timeout or
  // lost-response retry reuses the same idempotency key and the server can
  // de-duplicate the approval decision.
  const commandIdRef = useRef(crypto.randomUUID());
  const mutation = useMutation({
    mutationFn: () =>
      operatorApi.decideApproval(
        approval,
        {
          command_id: commandIdRef.current,
          disposition: "grant",
          rationale,
          expected_status: "pending",
          plan_digest: approval.plan_digest,
          approval_digest: approval.approval_digest,
          typed_confirmation: confirmation
        },
        session.csrf_token
      ),
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: ["operator", session.tenant_id] });
    }
  });
  const expired = Date.parse(approval.expires_at) <= Date.parse(serverNow);
  const canSubmit =
    reviewed &&
    approval.can_decide &&
    !expired &&
    confirmation === "APPROVE CHECKOUT-API" &&
    rationale.trim().length >= 12 &&
    !mutation.isPending;
  return (
    <article className="panel approval-card">
      <h2>{approval.approval_id}</h2>
      <p>
        <Status value={approval.status} /> · risk {approval.risk} · quorum{" "}
        {approval.grants}/{approval.quorum}
      </p>
      <p>
        Expires from server time: <Timestamp value={approval.expires_at} />
      </p>
      <dl className="digests">
        <dt>Plan digest</dt>
        <dd>
          <code>{approval.plan_digest}</code>
        </dd>
        <dt>Approval digest</dt>
        <dd>
          <code>{approval.approval_digest}</code>
        </dd>
      </dl>
      <dl className="digests">
        <dt>Target</dt>
        <dd>
          <code>{approval.target}</code>
        </dd>
        <dt>Rollback</dt>
        <dd>
          <code>{approval.rollback}</code>
        </dd>
      </dl>
      <p>
        Request creator: {approval.created_by_actor_ref}; current actor:{" "}
        {session.user.actor_ref}. Agents and request creators cannot self-approve.
      </p>
      {approval.denial_reason === null ? null : (
        <p className="notice" role="status">
          {approval.denial_reason}
        </p>
      )}
      <label className="check-row">
        <input
          type="checkbox"
          checked={reviewed}
          onChange={(event) => setReviewed(event.target.checked)}
        />
        I reviewed the exact target, digests, quorum, expiry, and rollback.
      </label>
      <label htmlFor={rationaleId}>Independent rationale</label>
      <textarea
        id={rationaleId}
        value={rationale}
        maxLength={2000}
        onChange={(event) => setRationale(event.target.value)}
      />
      <label htmlFor={confirmationId}>
        Type <code>APPROVE CHECKOUT-API</code>
      </label>
      <input
        id={confirmationId}
        value={confirmation}
        autoComplete="off"
        onChange={(event) => setConfirmation(event.target.value)}
      />
      <button type="button" disabled={!canSubmit} onClick={() => mutation.mutate()}>
        {mutation.isPending ? "Submitting once…" : "Submit exact-scope approval"}
      </button>
      <div aria-live="assertive" role="status">
        {mutation.data === undefined
          ? null
          : `${mutation.data.outcome}: ${mutation.data.message}`}
        {mutation.error != null ? redactError(mutation.error) : null}
      </div>
    </article>
  );
}

export function EffectsPage() {
  const { snapshot } = useOperator();
  const columns: ColumnDef<Effect>[] = [
    { accessorKey: "effect_id", header: "Effect" },
    {
      accessorKey: "status",
      header: "Outcome",
      cell: ({ getValue }) => (
        <Status value={String(getValue())} urgent={getValue() === "ambiguous"} />
      )
    },
    { accessorKey: "target", header: "Exact target" },
    { accessorKey: "verification", header: "Verification" },
    { accessorKey: "rollback", header: "Rollback" }
  ];
  return (
    <Page
      title="Effects, reconciliation, and rollback"
      description="Ambiguity is never rendered as success."
    >
      <DataTable
        caption="Effect ledger projection"
        columns={columns}
        data={snapshot.effects}
      />
    </Page>
  );
}

export function SandboxesPage() {
  const { snapshot } = useOperator();
  const columns: ColumnDef<Sandbox>[] = [
    { accessorKey: "execution_id", header: "Execution" },
    { accessorKey: "status", header: "Status" },
    { accessorKey: "artifact_count", header: "Artifacts" },
    { accessorKey: "quarantined_count", header: "Quarantined" },
    {
      accessorKey: "cleanup_complete",
      header: "Cleanup",
      cell: ({ getValue }) => (getValue() ? "Complete" : "Incomplete")
    }
  ];
  return (
    <Page
      title="Sandbox and artifacts"
      description="Quarantine and cleanup remain explicit."
    >
      <DataTable
        caption="Sandbox executions"
        columns={columns}
        data={snapshot.sandboxes}
      />
    </Page>
  );
}

export function MemoryPage() {
  const { snapshot } = useOperator();
  const columns: ColumnDef<Memory>[] = [
    { accessorKey: "memory_id", header: "Memory" },
    { accessorKey: "tier", header: "Tier" },
    { accessorKey: "provenance", header: "Provenance" },
    { accessorKey: "status", header: "Status" },
    {
      accessorKey: "retention_expires_at",
      header: "Retention",
      cell: ({ getValue }) => <Timestamp value={String(getValue())} />
    },
    {
      accessorKey: "legal_hold",
      header: "Legal hold",
      cell: ({ getValue }) => (getValue() ? "Active" : "None")
    }
  ];
  return (
    <Page
      title="Memory provenance and retention"
      description="Retrieved memory is untrusted data."
    >
      <DataTable
        caption="Memory projections"
        columns={columns}
        data={snapshot.memories}
      />
    </Page>
  );
}

export function EvaluationsPage() {
  const { snapshot } = useOperator();
  const columns: ColumnDef<Evaluation>[] = [
    { accessorKey: "suite_id", header: "Suite" },
    {
      accessorKey: "passed",
      header: "Result",
      cell: ({ getValue }) => <Status value={getValue() ? "passed" : "failed"} />
    },
    { accessorKey: "regressions", header: "Regressions" },
    { accessorKey: "cases", header: "Cases" },
    { accessorKey: "baseline_digest", header: "Baseline digest" }
  ];
  return (
    <Page
      title="Evaluation regressions"
      description="Release evidence, never runtime authority."
    >
      <DataTable
        caption="Governed evaluation reports"
        columns={columns}
        data={snapshot.evaluations}
      />
    </Page>
  );
}

export function AuditPage() {
  const { snapshot } = useOperator();
  const columns: ColumnDef<Audit>[] = [
    { accessorKey: "event_id", header: "Event ID" },
    { accessorKey: "event_type", header: "Event type" },
    { accessorKey: "actor_ref", header: "Actor reference" },
    {
      accessorKey: "recorded_at",
      header: "Recorded",
      cell: ({ getValue }) => <Timestamp value={String(getValue())} />
    },
    { accessorKey: "record_hash", header: "Record hash" }
  ];
  return (
    <Page title="Audit" description="Privileged reads are server-authorized and audited.">
      <DataTable
        caption="Bounded audit records"
        columns={columns}
        data={snapshot.audit}
      />
    </Page>
  );
}

export function ReplayPage() {
  const { snapshot } = useOperator();
  const columns: ColumnDef<Replay>[] = [
    { accessorKey: "report_id", header: "Report" },
    { accessorKey: "integrity", header: "Integrity" },
    {
      accessorKey: "projection_matches",
      header: "Projection",
      cell: ({ getValue }) => (getValue() ? "Matches" : "Diverged")
    },
    {
      accessorKey: "truncated",
      header: "Completeness",
      cell: ({ getValue }) => (getValue() ? "Truncated" : "Complete")
    },
    { accessorKey: "report_digest", header: "Digest" }
  ];
  return (
    <Page
      title="Replay and support"
      description="Replay never invokes a model, tool, or effect."
    >
      <DataTable
        caption="Support replay reports"
        columns={columns}
        data={snapshot.replay}
      />
    </Page>
  );
}

function Page({
  title,
  description,
  children
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <>
      <header className="page-header">
        <h1>{title}</h1>
        <p>{description}</p>
      </header>
      {children}
    </>
  );
}
