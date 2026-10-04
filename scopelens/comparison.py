"""Validate and compare saved ScopeLens evidence snapshots."""
from __future__ import annotations

import json

from .evidence import sanitized
from .model import SCHEMA_VERSION


def validate_report(report: dict) -> dict:
    """Validate the snapshot identities and service fields used by comparison."""
    if not isinstance(report, dict) or type(report.get("schema_version")) is not int or report["schema_version"] != SCHEMA_VERSION:
        raise ValueError("Expected a ScopeLens schema_version 1 report")
    for key in ("observations", "findings"):
        if not isinstance(report.get(key), list):
            raise ValueError(f"Report must contain a {key} array")
        seen = set()
        for item in report[key]:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"] or not isinstance(item.get("asset"), str):
                raise ValueError(f"Malformed {key} entry")
            if item["id"] in seen:
                raise ValueError(f"Duplicate {key} identity")
            seen.add(item["id"])
            if key == "observations" and (not isinstance(item.get("kind"), str) or not isinstance(item.get("data"), dict)):
                raise ValueError("Malformed observation entry")
            if key == "observations" and item["kind"] == "service":
                if (type(item["data"].get("port")) is not int or not 1 <= item["data"]["port"] <= 65535
                        or not isinstance(item["data"].get("protocol"), str)
                        or item["data"]["protocol"] not in {"tcp", "udp", "sctp"}):
                    raise ValueError("Malformed service entry")
    return report


def _services(report: dict) -> dict[tuple[str, str, int], list[dict]]:
    """Group all evidence for a service in a stable, input-independent order."""
    result: dict[tuple[str, str, int], list[dict]] = {}
    for item in report["observations"]:
        if item["kind"] == "service":
            data = item["data"]
            key = (item["asset"], data["protocol"], data["port"])
            result.setdefault(key, []).append(item)
    for group in result.values():
        group.sort(key=lambda item: (json.dumps(item["data"], sort_keys=True), item["id"]))
    return result


def _signature(items: list[dict]) -> set[str]:
    return {json.dumps(item["data"], sort_keys=True) for item in items}


def compare_reports(before: dict, after: dict) -> dict:
    """Compare evidence content, without modifying either supplied snapshot."""
    validate_report(before)
    validate_report(after)
    prior_findings = {finding["id"]: finding for finding in before["findings"]}
    current_findings = {finding["id"]: finding for finding in after["findings"]}
    old, new = _services(before), _services(after)
    return sanitized({
        "added_findings": [current_findings[key] for key in sorted(current_findings.keys() - prior_findings.keys())],
        "removed_findings": [prior_findings[key] for key in sorted(prior_findings.keys() - current_findings.keys())],
        "added_services": [new[key][0] for key in sorted(new.keys() - old.keys())],
        "removed_services": [old[key][0] for key in sorted(old.keys() - new.keys())],
        "changed_services": [
            {"asset": new[key][0]["asset"], "before": old[key], "after": new[key]}
            for key in sorted(old.keys() & new.keys())
            if _signature(old[key]) != _signature(new[key])
        ],
        "note": "Changes describe supplied evidence, not live state. Missing observations do not prove remediation. Compare collection coverage, timestamps, and scope before interpreting differences.",
    })
