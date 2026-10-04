"""Evidence-backed defensive review rules; no live assessment is performed."""
from __future__ import annotations

import json

from .model import SEVERITIES, stable_id


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


def build_findings(observations: list[dict]) -> list[dict]:
    """Apply the rule catalog to supplied observations and retain their evidence."""
    findings: dict[str, dict] = {}
    specifications = {rule["id"]: rule for rule in RULES}

    def add(rule: str, item: dict, subject: str, detail: str, remediation: str, title: str = "") -> None:
        spec = specifications[rule]
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
