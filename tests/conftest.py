from __future__ import annotations

import pytest

from aegis_framework.fixtures import (
    DemoBundle,
    DemoScenario,
    build_demo_bundle,
)


@pytest.fixture
def success_bundle() -> DemoBundle:
    return build_demo_bundle(DemoScenario.SUCCESS)
