import { readFileSync } from "node:fs";

const manifest = JSON.parse(
  readFileSync(new URL("../src/contracts/backend-contract.json", import.meta.url), "utf8")
);
const source = readFileSync(
  new URL("../src/contracts/schemas.ts", import.meta.url),
  "utf8"
);

const expectedRoutes = [
  "/operator/api/approvals/{approval_id}/decisions",
  "/operator/api/protocol-peers/{peer_id}/trust",
  "/operator/api/snapshot",
  "/operator/readyz",
  "/operator/session",
  "/operator/session/authorization",
  "/operator/session/callback",
  "/operator/session/logout",
  "/operator/session/tenant"
];
if (manifest.schema_version !== 1 || manifest.api_version !== "0.16.0") {
  throw new Error("operator contract version drift");
}
for (const route of expectedRoutes) {
  if (!manifest.routes.includes(route)) throw new Error(`missing BFF route: ${route}`);
}
for (const field of manifest.models.OperatorSnapshot) {
  if (!source.includes(`${field}:`)) throw new Error(`snapshot schema drift: ${field}`);
}
for (const field of manifest.models.OperatorSessionView) {
  if (!source.includes(`${field}:`)) throw new Error(`session schema drift: ${field}`);
}
console.log(
  `contracts: ${manifest.routes.length} routes and ${Object.keys(manifest.models).length} runtime models match`
);
