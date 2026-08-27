# Versioning and deprecation policy

The repository uses `0.<layer>.0` while it remains an educational alpha. Layer 16
is version `0.16.0`; Python and UI package versions must match and are checked by
`make docs`.

Minor versions may change framework adapters, schemas, and deployment references.
Application events remain additive and legacy-readable. A breaking event,
provider-neutral port, database, protocol, or operator-contract change requires:

1. an ADR and migration/compatibility plan;
2. old/new readers during the documented compatibility window;
3. replay, projection-rebuild, tenant-isolation, and rollback evidence;
4. a changelog entry and explicit removal version;
5. at least one minor release of deprecation notice unless an active vulnerability
   requires immediate fail-closed removal.

Patch versions contain compatible fixes and documentation. Only the current minor
line on `master` receives security fixes. Framework and SDK major upgrades are
rejected until replay, failure, privacy, dependency, and exit tests pass.

This policy does not promise production support, uptime, or certification.
