"""Normalize exported evidence and merge repeated observations."""
from __future__ import annotations

import json

from .model import redact, stable_id
from .scope import normalize_host


def sanitized(value):
    """Copy a JSON-shaped value while removing secrets from exported strings."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [sanitized(item) for item in value]
    if isinstance(value, dict):
        return {str(key): sanitized(item) for key, item in value.items()}
    return value


def deduplicate(items: list[dict]) -> list[dict]:
    """Merge identical exported observations while retaining source provenance."""
    result = {}
    for item in items:
        item = sanitized(item)
        if item["kind"] != "package":
            try:
                item["asset"] = normalize_host(item["asset"])
            except ValueError:
                pass
        # IDs are based on exported content, not redacted credential values.
        item["id"] = stable_id(item["kind"], item["asset"], item["data"])
        if item["id"] not in result:
            result[item["id"]] = item
        else:
            result[item["id"]]["evidence"].extend(item["evidence"])
    for item in result.values():
        unique = {json.dumps(e, sort_keys=True): e for e in item["evidence"]}
        item["evidence"] = sorted(unique.values(), key=lambda e: (e["path"], e["line"], e.get("locator", "")))
    return sorted(result.values(), key=lambda o: (o["asset"], o["kind"], o["data"].get("protocol", ""),
                                                  o["data"].get("port", 0), o["data"].get("url", ""), o["id"]))
