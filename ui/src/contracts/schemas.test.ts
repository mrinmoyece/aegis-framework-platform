import { sessionSchema, snapshotSchema } from "./schemas";
import { fixtureSession, fixtureSnapshot } from "../test-fixtures";

describe("runtime contracts", () => {
  it("accepts the reviewed bounded contract", () => {
    expect(sessionSchema.parse(fixtureSession).tenant_id).toBe("tenant-acme");
    expect(snapshotSchema.parse(fixtureSnapshot).incidents).toHaveLength(1);
  });

  it("rejects unknown fields and unbounded collections", () => {
    expect(
      sessionSchema.safeParse({ ...fixtureSession, bearer_token: "forbidden" }).success
    ).toBe(false);
    expect(
      snapshotSchema.safeParse({
        ...fixtureSnapshot,
        timeline: Array.from({ length: 201 }, () => fixtureSnapshot.timeline[0])
      }).success
    ).toBe(false);
  });

  it("rejects malformed digests and ambiguous success labels", () => {
    expect(
      snapshotSchema.safeParse({
        ...fixtureSnapshot,
        evidence: [{ ...fixtureSnapshot.evidence[0], content_hash: "not-a-digest" }]
      }).success
    ).toBe(false);
    expect(
      snapshotSchema.safeParse({
        ...fixtureSnapshot,
        effects: [{ ...fixtureSnapshot.effects[0], status: "success" }]
      }).success
    ).toBe(false);
  });
});
