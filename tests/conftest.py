"""Shared test utilities for is_antibot tests."""

from __future__ import annotations

import json
from pathlib import Path

PROVIDERS_PATH = Path(__file__).resolve().parent.parent / "providers"


def _headers_from_har(response: dict) -> dict[str, str | list[str]]:
    """Convert HAR header format [{name, value}, ...] to a dict.

    Duplicate header names are collected into a list.
    """
    result: dict[str, str | list[str]] = {}
    for header in response["headers"]:
        name = header["name"]
        value = header["value"]
        existing = result.get(name)
        if existing is not None:
            if isinstance(existing, list):
                existing.append(value)
            else:
                result[name] = [existing, value]
        else:
            result[name] = value
    return result


def load_fixture(filepath: str | Path) -> dict:
    """Load a HAR fixture and return a dict suitable for is_antibot()."""
    raw = Path(filepath).read_text(encoding="utf-8")
    data = json.loads(raw)
    response = data["log"]["entries"][0]["response"]
    request = data["log"]["entries"][0].get("request", {})
    return {
        "headers": _headers_from_har(response),
        "status_code": response["status"],
        "html": (response.get("content") or {}).get("text", ""),
        "url": request.get("url", ""),
    }


def _discover_provider_fixtures() -> dict[str, list[dict[str, str]]]:
    """Scan the providers/ directory for failed.json and success.json fixtures."""
    fixtures: dict[str, list[dict[str, str]]] = {"failed": [], "success": []}
    if not PROVIDERS_PATH.is_dir():
        return fixtures
    for child in sorted(PROVIDERS_PATH.iterdir()):
        if not child.is_dir():
            continue
        name = child.name
        failed = child / "failed.json"
        success = child / "success.json"
        if failed.exists():
            fixtures["failed"].append({"name": name, "path": str(failed)})
        if success.exists():
            fixtures["success"].append({"name": name, "path": str(success)})
    return fixtures


PROVIDER_FIXTURES = _discover_provider_fixtures()
