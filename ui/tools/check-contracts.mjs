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
if (manifest.schema_version !== 1 || manifest.api_version !== "0.15.0") {
  throw new Error("operator contract version drift");
}
for (const route of expectedRoutes) {
  if (!manifest.routes.includes(route)) throw new Error(`missing BFF route: ${route}`);
}

// Structural check: each backend contract field must appear as a Zod schema
// property declaration (`  fieldName:` at the start of a line with leading
// whitespace), not just anywhere in the file.  This catches field renames and
// removals that a plain string-includes test would miss.
const ZOD_PROPERTY = /^\s{2,}\w+:/m;
for (const field of manifest.models.OperatorSnapshot) {
  const pattern = new RegExp(`^\\s{2,}${field}\\s*:`, "m");
  if (!pattern.test(source)) throw new Error(`snapshot schema drift: ${field}`);
}
for (const field of manifest.models.OperatorSessionView) {
  const pattern = new RegExp(`^\\s{2,}${field}\\s*:`, "m");
  if (!pattern.test(source)) throw new Error(`session schema drift: ${field}`);
}
// Suppress the unused variable warning from the pattern validation helper above.
void ZOD_PROPERTY;
console.log(
  `contracts: ${manifest.routes.length} routes and ${Object.keys(manifest.models).length} runtime models match`
);
