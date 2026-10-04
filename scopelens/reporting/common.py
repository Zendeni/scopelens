"""Shared report view helpers; imported evidence remains plain data."""
from __future__ import annotations

import json
from collections import Counter


_SEVERITIES = ("critical", "high", "medium", "low", "info")
_DIFF_LABELS = (("added_findings", "Added findings"), ("removed_findings", "Removed findings"),
                ("added_services", "Added services"), ("removed_services", "Removed services"),
                ("changed_services", "Changed services"))


def _text(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _severity(value: object) -> str:
    value = str(value).lower()
    return value if value in _SEVERITIES else "info"


def _items(report: dict, kind: str) -> list[dict]:
    aliases = {"service": {"service"}, "web": {"web", "http", "web_endpoint"},
               "package": {"package"}}
    return [item for item in report.get("observations", [])
            if item.get("kind") in aliases[kind]]


def _counts(report: dict) -> dict:
    observations = report.get("observations", [])
    findings = report.get("findings", [])
    coverage = report.get("coverage", [])
    values = {
        "assets": len({item.get("asset") for item in observations if item.get("asset")}),
        "services": len(_items(report, "service")),
        "web_endpoints": len(_items(report, "web")),
        "packages": len(_items(report, "package")),
        "findings": len(findings),
        "files_total": len(coverage),
        "files_parsed": sum(item.get("status") == "parsed" for item in coverage),
        "by_severity": dict(Counter(_severity(item.get("severity")) for item in findings)),
    }
    values.update(report.get("summary") or {})
    return values


def _diff_label(entry: object) -> str:
    if not isinstance(entry, dict):
        return _text(entry)
    title = entry.get("title") or entry.get("subject")
    if title:
        return f"{entry.get('asset', '—')} · {title}"
    data = entry.get("data")
    if isinstance(data, dict):
        return f"{entry.get('asset', '—')} · {_text(data)}"
    return _text(entry)
