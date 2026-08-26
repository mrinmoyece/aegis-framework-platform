import { createContext, useContext } from "react";

import type { OperatorSession, OperatorSnapshot } from "./contracts/schemas";

export interface OperatorContextValue {
  session: OperatorSession;
  snapshot: OperatorSnapshot;
  isFetching: boolean;
  pollingStatus: string | null;
  serverNow: string;
  switchTenant: (tenantId: string) => Promise<void>;
}

export const OperatorContext = createContext<OperatorContextValue | null>(null);

export function useOperator(): OperatorContextValue {
  const value = useContext(OperatorContext);
  if (value === null) throw new Error("operator context is unavailable");
  return value;
}
