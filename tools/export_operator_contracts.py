"""Export a compact drift manifest for the browser-facing Layer 12 contracts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis_framework.api import AppMode, create_app
from aegis_framework.operator_api import (
    AuthorizationStart,
    MutationReceipt,
    OperatorSessionView,
    OperatorSnapshot,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "ui/src/contracts/backend-contract.json"
MODELS = {
    "AuthorizationStart": AuthorizationStart,
    "MutationReceipt": MutationReceipt,
    "OperatorSessionView": OperatorSessionView,
    "OperatorSnapshot": OperatorSnapshot,
}


def manifest() -> dict[str, object]:
    app = create_app(mode=AppMode.DEMO)
    route_paths = {
        path
        for route in app.routes
        for path in _route_paths(route)
        if path.startswith("/operator")
    }
    models = {
        name: sorted(model.model_json_schema()["properties"])
        for name, model in MODELS.items()
    }
    return {
        "schema_version": 1,
        "api_version": app.version,
        "models": models,
        "routes": sorted(route_paths),
    }


def _route_paths(route: object) -> tuple[str, ...]:
    path = getattr(route, "path", None)
    if isinstance(path, str):
        return (path,)
    original_router = getattr(route, "original_router", None)
    nested = (
        getattr(original_router, "routes", ()) if original_router is not None else ()
    )
    return tuple(path for child in nested for path in _route_paths(child))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(manifest(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != rendered:
            print(
                "operator contract drift detected; regenerate the manifest",
                file=sys.stderr,
            )
            return 1
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
