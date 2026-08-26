# Security policy

This repository is an educational alpha and is not approved for production
remediation. Report vulnerabilities privately through GitHub's security advisory
interface for `mrinmoyece/aegis-framework-platform`; do not include credentials,
customer evidence, or exploit data in public issues.

Supported code is the latest commit on `master`. Layer 5 has production-shaped
OIDC/JWT, forced PostgreSQL RLS, immutable application events, transactional delivery,
Temporal workflow boundaries, and disabled evidence connector adapters. Production
Temporal/PostgreSQL HA, live IdP rotation, connector/provider qualification, DNS/egress,
credential brokering, parser isolation, and deployment remain unproven. It intentionally
has no enabled credentialed connector/model provider, approval mutation endpoint, or
effect.

Never report access tokens, signing keys, database passwords, resolved secrets, raw
tenant evidence, actor IDs, request IDs, or exploit data in a public issue. See the
[threat model](docs/threat-model.md) and [limitations](docs/limitations.md).

Report any path that lets evidence/model content select a URL, source, tenant,
credential, repository, namespace, cursor, policy, approval, or effect; bypasses
DNS/IP/redirect/response bounds; leaks raw evidence/cursors/locators/credentials to
telemetry; or lets quarantined/uncited evidence enter graph/model context.
