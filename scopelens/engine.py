"""Deterministic normalization, explicit scope, and defensive review rules."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re

from . import __version__
from .inputs import load_input
from .model import SCHEMA_VERSION, SEVERITIES, redact, stable_id
from .parsers import parse_documents


RULES = [
    {"id": "SL001", "severity": "medium", "title": "Cleartext service observed",
     "description": "A reported FTP, Telnet, POP3, or IMAP service deserves transport-security review; STARTTLS support is not determined."},
    {"id": "SL002", "severity": "low", "title": "Management service observed",
     "description": "Review network access controls for reported management and database services. An open port does not prove public or unauthenticated access."},
    {"id": "SL003", "severity": "low", "title": "HTTP endpoint uses cleartext transport",
     "description": "A captured HTTP response was served without TLS. Redirects to HTTPS and error responses are excluded."},
    {"id": "SL004", "severity": "low", "title": "HSTS absent from captured HTTPS response",
     "description": "Only complete response headers for a successful HTTPS response are evaluated."},
    {"id": "SL005", "severity": "low", "title": "Browser protection header absent",
     "description": "Complete HTML response headers are checked for Content-Security-Policy and X-Content-Type-Options."},
    {"id": "SL006", "severity": "medium", "title": "Cookie transport protection absent",
     "description": "A cookie captured over HTTPS lacks the Secure attribute. Cookie values are not exported."},
    {"id": "SL007", "severity": "info", "title": "Service version disclosed",
     "description": "Record reported product/version for maintenance review. This rule does not infer CVE applicability."},
]


def normalize_host(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        if re.fullmatch(r"[0-9.]+", value) and "." in value:
            raise ValueError(f"Invalid IP address in scope: {value}")
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"Invalid scope entry: {value}") from exc
        if (len(value) > 253 or not value or
                not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split("."))):
            raise ValueError(f"Invalid scope entry: {value}")
        return value


def validate_scope(scope: dict | None) -> dict:
    if scope is None:
        return {"include": [], "exclude": []}
    if not isinstance(scope, dict) or set(scope) - {"include", "exclude"}:
        raise ValueError("Scope must be an object with include and exclude arrays")
    result = {}
    for key in ("include", "exclude"):
        values = scope.get(key, [])
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise ValueError(f"Scope {key} must be an array of hostnames, IPs, or CIDRs")
        result[key] = sorted({normalize_host(value) for value in values})
    return result


def in_scope(asset: str, scope: dict) -> bool:
    try:
        asset = normalize_host(asset)
    except ValueError:
        asset = asset.lower().rstrip(".")
    def matches(entry: str) -> bool:
        try:
            if "/" in entry:
                return ipaddress.ip_address(asset) in ipaddress.ip_network(entry)
        except ValueError:
            return False
        return asset.lower().rstrip(".") == entry
    if any(matches(entry) for entry in scope["exclude"]):
        return False
    return not scope["include"] or any(matches(entry) for entry in scope["include"])


def sanitized(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [sanitized(item) for item in value]
    if isinstance(value, dict):
        return {str(key): sanitized(item) for key, item in value.items()}
    return value


def deduplicate(items: list[dict]) -> list[dict]:
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


def build_findings(observations: list[dict]) -> list[dict]:
    findings: dict[str, dict] = {}
    def add(rule: str, item: dict, subject: str, detail: str, remediation: str, title: str = "") -> None:
        spec = next(r for r in RULES if r["id"] == rule)
        fid = stable_id(rule, item["asset"], subject)
        if fid in findings:
            findings[fid]["evidence"].extend(item["evidence"])
            return
        findings[fid] = {"id": fid, "rule_id": rule, "title": title or spec["title"],
                         "severity": spec["severity"], "confidence": item["confidence"],
                         "asset": item["asset"], "subject": subject, "detail": detail,
                         "remediation": remediation, "evidence": list(item["evidence"])}
    cleartext = {"ftp", "telnet", "pop3", "imap"}
    management = {"ssh", "ms-wbt-server", "rdp", "winrm", "microsoft-ds", "msrpc", "redis", "mysql", "postgresql", "mongodb", "vnc", "docker"}
    for item in observations:
        data = item["data"]
        if item["asset"] == "unattributed":
            continue
        if item["kind"] == "service" and data.get("state") == "open":
            subject = f"{data['protocol']}/{data['port']}"
            name = data.get("service", "").lower()
            if name in cleartext and data.get("tunnel") != "ssl":
                add("SL001", item, subject,
                    f"The artifact reports {name} on {subject}. Encryption upgrades and authentication requirements have not been verified.",
                    "Confirm transport encryption in service configuration. Prefer encrypted alternatives and restrict network access to required clients.")
            if name in management:
                add("SL002", item, subject,
                    f"The artifact reports {name} on {subject}. Reachability is relative to the original collection location.",
                    "Confirm ownership and intended exposure. Restrict management access with network policy and strong authentication.")
            if data.get("version"):
                add("SL007", item, f"{subject} {data.get('product', '')} {data['version']}",
                    f"Reported version: {data.get('product', '')} {data['version']}. Scanner banners may be inaccurate or omit vendor backports.",
                    "Compare against the owner-maintained software inventory and vendor maintenance guidance before deciding whether an update is needed.")
        elif item["kind"] == "web":
            url = data.get("url", "")
            status = data.get("status")
            successful = isinstance(status, int) and 200 <= status < 300
            if url.startswith("http://") and successful:
                add("SL003", item, url, "A successful HTTP response was observed in the supplied artifact; the sensitivity of the content is unknown.",
                    "Serve application traffic over HTTPS and review whether HTTP should redirect to HTTPS.")
            headers = {k.lower(): v for k, v in data.get("headers", {}).items()}
            if data.get("headers_complete") and successful:
                if url.startswith("https://") and "strict-transport-security" not in headers:
                    add("SL004", item, url, "The captured successful HTTPS response does not contain Strict-Transport-Security. Other responses may differ.",
                        "Review HSTS policy after confirming HTTPS works for the intended host and any affected subdomains.")
                if "text/html" in headers.get("content-type", "").lower():
                    for header in ("content-security-policy", "x-content-type-options"):
                        if header not in headers:
                            add("SL005", item, f"{url} {header}", f"The captured HTML response does not include {header}.",
                                "Review browser security headers in the application or reverse proxy. Test policy changes against required application behavior.",
                                f"{header} absent from captured HTML response")
            for cookie in data.get("cookies", []):
                if url.startswith("https://") and cookie.get("secure") is False:
                    add("SL006", item, f"{url} cookie:{cookie.get('name', '(unnamed)')}",
                        "A cookie set by the captured HTTPS response lacks the Secure attribute. Its purpose and sensitivity require owner review.",
                        "Use Secure on cookies that should only travel over HTTPS. Review HttpOnly and SameSite requirements with the application owner.")
    for finding in findings.values():
        unique = {json.dumps(e, sort_keys=True): e for e in finding["evidence"]}
        finding["evidence"] = sorted(unique.values(), key=lambda e: (e["path"], e["line"]))
    return sorted(findings.values(), key=lambda f: (-SEVERITIES[f["severity"]], f["asset"], f["rule_id"], f["id"]))


def validate_report(report: dict) -> dict:
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


def compare_reports(before: dict, after: dict) -> dict:
    validate_report(before)
    validate_report(after)
    prior_findings = {f["id"]: f for f in before["findings"]}
    current_findings = {f["id"]: f for f in after["findings"]}
    def services(report):
        result = {}
        for item in report["observations"]:
            if item["kind"] == "service":
                data = item["data"]
                key = f"{item['asset']}|{data['protocol']}|{data['port']}"
                result.setdefault(key, []).append(item)
        return result
    old, new = services(before), services(after)
    def signature(items):
        return sorted({json.dumps(i["data"], sort_keys=True) for i in items})
    return sanitized({"added_findings": [current_findings[k] for k in sorted(current_findings.keys() - prior_findings.keys())],
            "removed_findings": [prior_findings[k] for k in sorted(prior_findings.keys() - current_findings.keys())],
            "added_services": [new[k][0] for k in sorted(new.keys() - old.keys())],
            "removed_services": [old[k][0] for k in sorted(old.keys() - new.keys())],
            "changed_services": [{"asset": new[k][0]["asset"], "before": old[k], "after": new[k]} for k in sorted(old.keys() & new.keys()) if signature(old[k]) != signature(new[k])],
            "note": "Changes describe supplied evidence, not live state. Missing observations do not prove remediation. Compare collection coverage, timestamps, and scope before interpreting differences."})


def analyze(source: Path, name: str = "", scope: dict | None = None,
            baseline: dict | None = None, exclude: Path | None = None) -> dict:
    scope = validate_scope(scope)
    documents, coverage, warnings = load_input(source, exclude=exclude)
    observations, parser_warnings = parse_documents(documents)
    warnings.extend(parser_warnings)
    observations = deduplicate(observations)
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
    services = {(o["asset"], o["data"].get("protocol"), o["data"].get("port")) for o in selected if o["kind"] == "service"}
    report = {"schema_version": SCHEMA_VERSION, "tool": {"name": "ScopeLens", "version": __version__},
              "name": redact(name or source.stem), "generated_at": datetime.now(timezone.utc).isoformat(),
              "source": {"name": source.name, "kind": "directory" if source.is_dir() else "zip" if source.suffix.lower() == ".zip" else "file"},
              "scope": scope, "summary": {"assets": len({o["asset"] for o in selected if o["asset"] != "unattributed" and o["kind"] != "package"}),
              "services": len(services), "web_endpoints": len({o["data"].get("url") for o in selected if o["kind"] == "web"}),
              "packages": sum(o["kind"] == "package" for o in selected), "findings": len(findings),
              "by_severity": dict(Counter(f["severity"] for f in findings)),
              "files_parsed": sum(row["status"] == "parsed" for row in coverage), "files_total": len(coverage)},
              "observations": selected, "findings": findings, "coverage": coverage,
              "warnings": sanitized(warnings), "diff": None}
    if baseline is not None:
        report["diff"] = compare_reports(baseline, report)
    return report
