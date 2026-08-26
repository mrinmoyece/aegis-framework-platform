# Compliance-ready evidence mapping

This mapping organizes evidence; it is not certification, legal advice, control
operation, or proof of effectiveness.

| Objective | Repository evidence | External evidence still required |
|---|---|---|
| Change/release control | exact pins, PR gates, promotion environments, digest/signature/provenance checks | protected branch/environment configuration, reviewer records, signing identity operations |
| Least privilege | explicit service accounts, narrow sandbox Role, Pod Identity roles, runtime DB role/RLS | cloud IAM policy review, access logs, break-glass and recertification |
| Network segmentation | default-deny policies and explicit boundary proxies/private endpoints | enforcing CNI/firewall/proxy tests and flow evidence |
| Workload hardening | restricted PSS, CEL admission, digest/non-root/read-only/drop-all/seccomp | policy-controller/CEL enforcement, node/runtime qualification, exception records |
| Data protection | KMS/S3/RDS/Secrets references, TLS boundaries, payload-codec requirement | key policies/rotation, PKI, DPA/residency, erasure and restore operation |
| Audit/integrity | immutable application facts, dual hash chains, RLS, restore verification | external witness/WORM/legal retention and DBA monitoring |
| Availability/recovery | Multi-AZ references, PDB/HPA/spread, backup/vault lock, runbooks | applied cloud config, load/chaos, alert/on-call, measured RPO/RTO |
| Supplier/supply chain | lockfiles, SBOM, vulnerability/license/secret gates, keyless signing/attestation | incident response, waiver review, registry/admission operations |
| Secure development | strict typing/lint/tests/evals/CodeQL/dependency review | independent penetration review, threat review cadence, training records |
| Privacy | telemetry allowlists, automatic tracing disabled, bounded references | DPIA, deletion/legal hold operations, vendor terms, access reviews |

CI artifacts are retained for 30 days and are not a durable audit archive. An external
evidence store must bind source commit, workflow identity, digest, approval, policy
revision, and retention without copying prompts, completions, raw evidence, credentials,
tenant/actor/request IDs, or locators.

