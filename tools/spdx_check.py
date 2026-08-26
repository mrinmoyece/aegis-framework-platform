"""Fail closed on SPDX documents missing mandatory fields."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", action="append", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = evaluate(sboms=tuple(args.sbom))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"spdx-check: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(f"spdx-check: validated {result['checked_count']} SPDX document(s)")
    return 0


def evaluate(*, sboms: tuple[Path, ...]) -> dict[str, object]:
    if not sboms:
        raise ValueError("at least one SPDX document is required")
    documents: list[str] = []
    for path in sboms:
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise TypeError("SPDX document must be an object")
        _validate_document(document)
        documents.append(path.name)
    return {
        "checked_count": len(documents),
        "documents": tuple(sorted(documents)),
    }


def _validate_document(document: dict[str, Any]) -> None:
    if not _non_empty_string(document.get("spdxVersion")):
        raise ValueError("SPDX document version is missing")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ValueError("SPDX document identifier is invalid")
    if document.get("dataLicense") != "CC0-1.0":
        raise ValueError("SPDX document data license is invalid")
    for field in ("name", "documentNamespace"):
        if not _non_empty_string(document.get(field)):
            raise ValueError(f"SPDX document {field} is missing")
    creation_info = document.get("creationInfo")
    if not isinstance(creation_info, dict):
        raise ValueError("SPDX creationInfo is missing")
    if not _non_empty_string(creation_info.get("created")):
        raise ValueError("SPDX creation timestamp is missing")
    creators = creation_info.get("creators")
    if (
        not isinstance(creators, list)
        or not creators
        or any(not _non_empty_string(creator) for creator in creators)
    ):
        raise ValueError("SPDX creators are missing")
    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("SPDX packages are missing")


def _non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


if __name__ == "__main__":
    raise SystemExit(main())
