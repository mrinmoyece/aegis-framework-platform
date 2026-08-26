# Deployment promotion runbook

1. Require green source, protocol, eval, frontend, deployment, Terraform, restore,
   container, and security gates.
2. Record the multi-platform digest, SPDX digest, provenance, keyless identity, scan
   result, change reference, migration set, Temporal deployment/build IDs, and rollback
   digest. Never record secrets or payloads.
3. Verify Sigstore identity/rekor and GitHub attestation, then create a digest-only
   GitOps change. A tag is not deployable identity.
4. Approve staging, run additive migration, deploy compatible workers, canary API and
   reconcile. Hold on safety/SLO/queue/DB/migration signals.
5. Approve production for the same digest. Use maxUnavailable zero and watch drain.
6. Roll back only to a previously verified replay-compatible digest. Keep expanded
   schema, reconcile all ambiguity, and open a new incident/change record.

