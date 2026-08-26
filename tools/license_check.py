"""Fail closed on unknown or unreviewed installed Python dependency licenses."""

from __future__ import annotations

import sys
from importlib.metadata import PackageMetadata, distributions

APPROVED = {
    "3-Clause BSD License",
    "Apache 2.0",
    "Apache License 2.0",
    "Apache License Version 2.0",
    "Apache License, Version 2.0",
    "Apache-2.0",
    "Apache-2.0 AND MIT",
    "Apache-2.0 OR BSD-2-Clause",
    "Apache-2.0 OR BSD-3-Clause",
    "Apache-2.0 OR MIT",
    "BSD",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "LGPL-3.0-only",
    "MIT",
    "MIT OR Apache-2.0",
    "MIT-0",
    "Modified BSD License",
    "MPL-2.0",
    "MPL-2.0 AND (Apache-2.0 OR MIT)",
    "MPL-2.0 AND MIT",
    "OSI Approved :: Apache Software License",
    "OSI Approved :: MIT License",
    "OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
    "PSF-2.0",
    "PSFL",
}
NAMED_EXCEPTIONS = {
    ("python-dateutil", "Dual License"),
}


def main() -> int:
    rejected: list[tuple[str, str]] = []
    checked = 0
    for distribution in distributions():
        name = str(distribution.metadata["Name"]).lower()
        license_name = _license(distribution.metadata)
        checked += 1
        if (
            license_name not in APPROVED
            and (name, license_name) not in NAMED_EXCEPTIONS
            and not license_name.startswith(
                "Permission is hereby granted, free of charge"
            )
        ):
            rejected.append((name, license_name[:120]))
    if rejected:
        for name, license_name in sorted(rejected):
            print(f"license-check: rejected {name}: {license_name}", file=sys.stderr)
        return 1
    print(f"license-check: {checked} installed distributions use reviewed licenses")
    return 0


def _license(metadata: PackageMetadata) -> str:
    expression = metadata.get("License-Expression")
    if expression:
        return str(expression).strip()
    license_name = metadata.get("License")
    if license_name:
        return str(license_name).strip()
    for classifier in metadata.get_all("Classifier", []):
        if "License ::" in classifier:
            return str(classifier).split("License ::", 1)[1].strip()
    return "UNKNOWN"


if __name__ == "__main__":
    raise SystemExit(main())
