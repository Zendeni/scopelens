"""Orchestrate offline import, scope selection, findings, and report assembly.

The original engine imports remain available for compatibility; focused modules
also expose scope, evidence, rules, and snapshot comparison independently.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .comparison import compare_reports, validate_report
from .evidence import deduplicate, sanitized
from .inputs import load_input
from .model import SCHEMA_VERSION, redact
from .parsers import parse_documents
from .rules import RULES, build_findings
from .scope import in_scope, normalize_host, validate_scope


def _conflict_warnings(observations: list[dict]) -> list[dict]:
    """Preserve conflicting observations and make their disagreement visible."""
    warnings = []
    service_groups = {}
    for item in observations:
        if item["kind"] == "service":
            key = (item["asset"], item["data"].get("protocol"), item["data"].get("port"))
            service_groups.setdefault(key, []).append(item)
    for (asset, protocol, port), group in service_groups.items():
        conflicts = [field for field in ("state", "service", "product", "version", "tunnel")
                     if len({o["data"].get(field) for o in group if o["data"].get(field)}) > 1]
        if conflicts:
            warnings.append({"code": "conflicting_service_evidence", "path": "",
                             "message": f"{asset} {protocol}/{port} has differing reported {', '.join(conflicts)}; all observations retained"})
    return warnings


def _classify_coverage(coverage: list[dict], observations: list[dict],
                       parser_warnings: list[dict]) -> None:
    """Annotate import coverage using the observations and diagnostics produced."""
    observed_paths = {e["path"] for item in observations for e in item["evidence"]}
    warned_paths = {w.get("path") for w in parser_warnings}
    parser_labels = {}
    for item in observations:
        for evidence in item["evidence"]:
            locator = evidence.get("locator", "")
            label = ("nmap-xml" if locator.startswith("/nmaprun") else
                     "nmap-text" if locator.startswith("Nmap") else
                     "http-headers" if locator == "HTTP response headers" else
                     "httpx" if locator in {"httpx record", "HTTP URL row"} else
                     "ffuf" if locator.startswith("/results/") else
                     "npm-lock" if locator.startswith(("/packages/", "/dependencies/")) else
                     "requirements" if locator == "exact requirement pin" else
                     "target-env" if locator == "target environment" else "structured")
            parser_labels.setdefault(evidence["path"], set()).add(label)
    error_paths = {w.get("path") for w in parser_warnings if any(s in w.get("code", "") for s in ("malformed", "invalid", "error", "unsafe"))}
    for row in coverage:
        if row["status"] == "loaded":
            row["status"] = "parsed" if row["path"] in observed_paths else "error" if row["path"] in error_paths else "unrecognized"
            if row["path"] in parser_labels:
                row["parser"] = ", ".join(sorted(parser_labels[row["path"]]))
            if row["path"] in warned_paths:
                row["reason"] = "Import diagnostics present; inspect warnings"
            if row["status"] == "unrecognized":
                row["reason"] = "No supported observations found; this is not a clean bill of health"


def _summarize(observations: list[dict], findings: list[dict], coverage: list[dict]) -> dict:
    services = {(item["asset"], item["data"].get("protocol"), item["data"].get("port"))
                for item in observations if item["kind"] == "service"}
    assets = {item["asset"] for item in observations
              if item["asset"] != "unattributed" and item["kind"] != "package"}
    endpoints = {item["data"].get("url") for item in observations if item["kind"] == "web"}
    return {
        "assets": len(assets),
        "services": len(services),
        "web_endpoints": len(endpoints),
        "packages": sum(item["kind"] == "package" for item in observations),
        "findings": len(findings),
        "by_severity": dict(Counter(item["severity"] for item in findings)),
        "files_parsed": sum(row["status"] == "parsed" for row in coverage),
        "files_total": len(coverage),
    }


def analyze(source: Path, name: str = "", scope: dict | None = None,
            baseline: dict | None = None, exclude: Path | None = None) -> dict:
    """Build a complete report from local artifacts without writing any files."""
    scope = validate_scope(scope)
    documents, coverage, warnings = load_input(source, exclude=exclude)
    observations, parser_warnings = parse_documents(documents)
    warnings.extend(parser_warnings)
    observations = deduplicate(observations)
    warnings.extend(_conflict_warnings(observations))
    _classify_coverage(coverage, observations, parser_warnings)
    selected = [o for o in observations if o["kind"] == "package" or in_scope(o["asset"], scope)]
    if any(o["kind"] == "package" for o in selected):
        warnings.append({"code": "unattributed_packages", "path": "", "message": "Package inventory is retained independently of host scope because manifests do not establish a host association"})
    outside = len(observations) - len(selected)
    if outside:
        warnings.append({"code": "outside_scope", "path": "", "message": f"{outside} observations excluded by explicit scope; no DNS resolution was performed"})
    if not scope["include"]:
        warnings.append({"code": "scope_unspecified", "path": "", "message": "No include list supplied; all observed assets except explicit exclusions are analyzed"})
    if not selected:
        warnings.append({"code": "no_observations", "path": "", "message": "No supported in-scope observations found; review input format, scope, and coverage"})
    findings = build_findings(selected)
    source_kind = "directory" if source.is_dir() else "zip" if source.suffix.lower() == ".zip" else "file"
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "ScopeLens", "version": __version__},
        "name": redact(name or source.stem),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": {"name": source.name, "kind": source_kind},
        "scope": scope,
        "summary": _summarize(selected, findings, coverage),
        "observations": selected,
        "findings": findings,
        "coverage": coverage,
        "warnings": sanitized(warnings),
        "diff": None,
    }
    if baseline is not None:
        report["diff"] = compare_reports(baseline, report)
    return report
