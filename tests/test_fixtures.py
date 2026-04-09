"""HAR fixture tests — port of test/providers.js."""

from __future__ import annotations

import pytest
from conftest import PROVIDER_FIXTURES, load_fixture

from is_antibot import is_antibot


@pytest.mark.parametrize(
    "name,fixture_path",
    [(f["name"], f["path"]) for f in PROVIDER_FIXTURES["failed"]],
    ids=[f["name"] for f in PROVIDER_FIXTURES["failed"]],
)
def test_fixture_detected(name: str, fixture_path: str):
    fixture = load_fixture(fixture_path)
    result = is_antibot(**fixture)
    assert result.detected is True, f"Failed {name}"
    assert result.provider, f"Failed {name}"


@pytest.mark.parametrize(
    "name,fixture_path",
    [(f["name"], f["path"]) for f in PROVIDER_FIXTURES["success"]],
    ids=[f["name"] for f in PROVIDER_FIXTURES["success"]],
)
def test_fixture_not_detected(name: str, fixture_path: str):
    fixture = load_fixture(fixture_path)
    result = is_antibot(**fixture)
    assert result.detected is False, f"Failed {name}"
    assert result.provider is None, f"Failed {name}"
