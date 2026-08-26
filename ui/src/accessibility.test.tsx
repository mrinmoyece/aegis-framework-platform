import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import type { ReactElement } from "react";

import { operatorApi } from "./api/client";
import { OperatorContext } from "./operator-context";
import {
  ApprovalsPage,
  AuditPage,
  EffectsPage,
  EvaluationsPage,
  InvestigationPage,
  MemoryPage,
  ModelsPage,
  OverviewPage,
  ProtocolPeersPage,
  ReplayPage,
  SandboxesPage
} from "./pages";
import { fixtureSession, fixtureSnapshot } from "./test-fixtures";

const pages: [string, ReactElement][] = [
  ["overview", <OverviewPage />],
  ["investigation", <InvestigationPage />],
  ["models", <ModelsPage />],
  ["approvals", <ApprovalsPage />],
  ["effects", <EffectsPage />],
  ["sandboxes", <SandboxesPage />],
  ["memory", <MemoryPage />],
  ["evaluations", <EvaluationsPage />],
  ["audit", <AuditPage />],
  ["replay", <ReplayPage />],
  ["protocol peers", <ProtocolPeersPage />]
];

function renderPage(page: ReactElement, snapshot = fixtureSnapshot) {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <OperatorContext.Provider
        value={{
          session: fixtureSession,
          snapshot,
          isFetching: false,
          pollingStatus: null,
          serverNow: fixtureSession.server_time,
          switchTenant: () => Promise.resolve()
        }}
      >
        <main>{page}</main>
      </OperatorContext.Provider>
    </QueryClientProvider>
  );
}

describe("WCAG automated baseline", () => {
  it.each(pages)("%s has no axe violations", async (_name, page) => {
    const { container, unmount } = renderPage(page);
    const result = await axe.run(container, {
      rules: {
        "color-contrast": { enabled: false },
        region: { enabled: false }
      }
    });
    expect(result.violations).toEqual([]);
    unmount();
  });

  it("renders hostile evidence as inert text and ambiguity as non-success", () => {
    const { container } = renderPage(<InvestigationPage />);
    expect(container.querySelector("img")).toBeNull();
    expect(
      screen.getByText("<img src=x onerror=alert(1)> must remain text")
    ).toBeVisible();
    const effects = renderPage(<EffectsPage />);
    expect(screen.getAllByText("ambiguous")).toHaveLength(2);
    expect(effects.container.querySelector(".status-success")).toBeNull();
  });

  it("keeps approval submission disabled when server grants deny authority", () => {
    renderPage(<ApprovalsPage />);
    expect(
      screen.getByRole("button", { name: "Submit exact-scope approval" })
    ).toBeDisabled();
    expect(screen.getByText(/Current grants do not permit approval/)).toBeVisible();
  });

  it("submits a reviewed decision once and preserves server denial", async () => {
    const user = userEvent.setup();
    const approval = fixtureSnapshot.approvals[0];
    if (approval === undefined) throw new Error("approval fixture is unavailable");
    const decide = vi.spyOn(operatorApi, "decideApproval").mockResolvedValue({
      command_id: "command-1",
      outcome: "denied",
      message: "Server authority denied the request.",
      server_time: fixtureSession.server_time
    });
    renderPage(<ApprovalsPage />, {
      ...fixtureSnapshot,
      approvals: [
        {
          ...approval,
          can_decide: true,
          denial_reason: null
        }
      ]
    });
    await user.click(screen.getByRole("checkbox"));
    await user.type(
      screen.getByLabelText("Independent rationale"),
      "Independent exact-scope review."
    );
    await user.type(
      screen.getByLabelText(/Type APPROVE CHECKOUT-API/),
      "APPROVE CHECKOUT-API"
    );
    await user.click(screen.getByRole("button", { name: "Submit exact-scope approval" }));
    expect(decide).toHaveBeenCalledOnce();
    expect(await screen.findByText(/denied: Server authority denied/)).toBeVisible();
  });

  it("requires exact protocol trust review before one mutation", async () => {
    const user = userEvent.setup();
    const mutate = vi.spyOn(operatorApi, "mutateProtocolTrust").mockResolvedValue({
      command_id: "trust-command-1",
      outcome: "accepted",
      message: "Protocol peer trust changed to revoked.",
      server_time: fixtureSession.server_time
    });
    renderPage(<ProtocolPeersPage />);
    expect(screen.getByText(/production ready no \(fail closed\)/)).toBeVisible();
    const button = screen.getByRole("button", {
      name: "Apply exact trust transition"
    });
    expect(button).toBeDisabled();
    await user.selectOptions(screen.getByLabelText("Trust action"), "revoke");
    await user.click(screen.getByRole("checkbox"));
    await user.type(
      screen.getByLabelText("Independent rationale"),
      "Verified card and schema drift requires revocation."
    );
    await user.type(
      screen.getByLabelText(/Type REVOKE partner-investigator/),
      "REVOKE partner-investigator"
    );
    await user.click(button);
    expect(mutate).toHaveBeenCalledOnce();
    expect(await screen.findByText(/accepted: Protocol peer trust/)).toBeVisible();
  });

  it("disables mutation for terminal protocol trust", () => {
    const peer = fixtureSnapshot.protocol_peers[0];
    if (peer === undefined) throw new Error("protocol peer fixture is unavailable");
    renderPage(<ProtocolPeersPage />, {
      ...fixtureSnapshot,
      protocol_peers: [{ ...peer, status: "revoked" }]
    });
    expect(
      screen.getByRole("button", { name: "Apply exact trust transition" })
    ).toBeDisabled();
    expect(screen.getByLabelText("Trust action")).toBeDisabled();
  });

  it("shows redacted error when protocol trust mutation fails", async () => {
    const user = userEvent.setup();
    vi.spyOn(operatorApi, "mutateProtocolTrust").mockRejectedValue(
      new Error("network failure")
    );
    renderPage(<ProtocolPeersPage />);
    const button = screen.getByRole("button", { name: "Apply exact trust transition" });
    await user.selectOptions(screen.getByLabelText("Trust action"), "revoke");
    await user.click(screen.getByRole("checkbox"));
    await user.type(
      screen.getByLabelText("Independent rationale"),
      "Verified card and schema drift requires revocation."
    );
    await user.type(
      screen.getByLabelText(/Type REVOKE partner-investigator/),
      "REVOKE partner-investigator"
    );
    await user.click(button);
    expect(await screen.findByText(/operator workspace failed safely/)).toBeVisible();
  });
});
