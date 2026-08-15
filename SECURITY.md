# Security policy

This repository is an educational alpha and is not approved for production
remediation. Report vulnerabilities privately through GitHub's security advisory
interface for `mrinmoyece/aegis-framework-platform`; do not include credentials,
customer evidence, or exploit data in public issues.

Supported code is the latest commit on `master`. Layer 3 has production-shaped
OIDC/JWT, forced PostgreSQL RLS, immutable application events, transactional delivery,
and Temporal workflow boundaries. Production Temporal/PostgreSQL HA, live IdP
rotation, and deployment remain unproven. It intentionally has no credentialed model
provider, production evidence source, approval mutation endpoint, or effect.

Never report access tokens, signing keys, database passwords, resolved secrets, raw
tenant evidence, actor IDs, request IDs, or exploit data in a public issue. See the
[threat model](docs/threat-model.md) and [limitations](docs/limitations.md).
