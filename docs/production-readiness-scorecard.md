# Production-readiness scorecard

The source of record is `qualification/readiness-scorecard.json`. There is no
aggregate score: one blocked identity, isolation, recovery, sandbox, supply-chain or
operational gate blocks go-live.

| Status | Meaning |
|---|---|
| Implemented | Code/configuration exists; no verification claim |
| Locally Verified | Deterministic repository evidence passed |
| Environment-Gated | A named local/integration command must run |
| Live Evidence Required | Production-like organizational or environment evidence is absent |
| Deferred | Deliberately outside the current design |

## Hard go-live gates

| Gate | Owner | Evidence | Rollback/denial |
|---|---|---|---|
| Production OIDC, PKI and rotation | identity-platform | live issuer/JWKS/session/rotation exercise | deny production authentication |
| Managed database restore/failover | data-platform | isolated PITR and cross-account restore with ledger verification | fence target and retain source |
| Temporal Cloud upgrade/failover | workflow-platform | version/replay/drain/failover evidence | route no new outbox starts |
| Enforced sandbox isolation | sandbox-platform | Kata/CNI/admission/CSI/proxy escape/resource tests | disable sandbox execution |
| Provider/connector/partner qualification | integrations | exact account/model/source/peer/region tests | keep adapter disabled |
| Production load, chaos, SLO and on-call | sre | representative load curves, error budgets, alert delivery and response | block promotion |
| Independent security/accessibility/privacy/legal | risk-and-compliance | signed review records and remediation closure | no launch or certification claim |

Promotion requires every blocking item to move through an approved evidence record.
Changing JSON status without the named evidence is a release-control failure.
