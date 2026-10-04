"""The report boundary must treat every imported field as untrusted text."""
from __future__ import annotations

import copy
from html.parser import HTMLParser
import json
import unittest

from scopelens.reports import render_html, render_json, render_markdown


class Page(HTMLParser):
    def __init__(self, source: str):
        super().__init__()
        self.tags = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def report_fixture() -> dict:
    evidence = [{"path": "inputs/host.xml", "sha256": "a" * 64, "line": 14,
                 "locator": "host/ports/port", "excerpt": '<port protocol="tcp" portid="80" />'}]
    service = {"id": "service-1", "kind": "service", "asset": "server.example", "confidence": "high",
               "data": {"port": 80, "protocol": "tcp", "name": "http", "state": "open"}, "evidence": evidence}
    finding = {"id": "finding-1", "rule_id": "web.cleartext", "title": "Cleartext HTTP observed",
               "severity": "medium", "confidence": "high", "asset": "server.example", "subject": "80/tcp",
               "detail": "A response was observed over HTTP.", "remediation": "Review HTTPS deployment.",
               "evidence": evidence}
    return {
        "schema_version": 1, "tool": {"name": "ScopeLens", "version": "0.1.0"}, "name": "Example analysis",
        "generated_at": "2026-10-04T20:00:00Z", "source": {"name": "inputs", "kind": "directory"},
        "scope": {"include": ["server.example"], "exclude": []},
        "summary": {"assets": 1, "services": 1, "web_endpoints": 1, "packages": 1, "findings": 1,
                    "by_severity": {"medium": 1}, "files_parsed": 1, "files_total": 2},
        "observations": [service,
                         {"id": "web-1", "kind": "web", "asset": "server.example", "confidence": "high",
                          "data": {"url": "https://server.example/", "status": 200, "title": "Example"}, "evidence": evidence},
                         {"id": "package-1", "kind": "package", "asset": "dependency:sample", "confidence": "high",
                          "data": {"name": "sample", "version": "1.0.0", "licenses": ["MIT"]}, "evidence": evidence}],
        "findings": [finding],
        "coverage": [{"path": "inputs/host.xml", "status": "parsed", "parser": "nmap-xml", "bytes": 420,
                      "sha256": "a" * 64},
                     {"path": "inputs/notes.bin", "status": "skipped", "bytes": 10, "sha256": "b" * 64,
                      "reason": "Unsupported format"}],
        "warnings": [{"code": "unsupported", "path": "inputs/notes.bin", "message": "Unsupported file was skipped."}],
        "diff": None,
    }


class ReportTests(unittest.TestCase):
    def test_json_round_trips_full_contract_without_mutation(self):
        report = report_fixture()
        original = copy.deepcopy(report)
        self.assertEqual(json.loads(render_json(report)), report)
        render_html(report)
        render_markdown(report)
        self.assertEqual(report, original)

    def test_normal_html_contains_evidence_inventories_and_accessible_filters(self):
        source = render_html(report_fixture())
        page = Page(source)
        ids = {attrs.get("id") for _, attrs in page.tags if attrs.get("id")}
        for expected in ("findings", "service-inventory", "web-inventory", "package-inventory",
                         "baseline", "coverage", "text-filter", "asset-filter", "severity-filter", "filter-status"):
            self.assertIn(expected, ids)
        self.assertIn("Line 14", source)
        self.assertIn("a" * 64, source)
        self.assertIn("Confidence <strong>high</strong>", source)
        self.assertIn('data-severity="medium"', source)
        self.assertIn("Unsupported file was skipped.", source)
        self.assertIn("No baseline supplied.", source)
        self.assertIn('role="status" aria-live="polite"', source)
        labels = {attrs.get("for") for tag, attrs in page.tags if tag == "label"}
        self.assertTrue({"text-filter", "asset-filter", "severity-filter"} <= labels)
        self.assertIn("scope", {attr for _, attrs in page.tags for attr in attrs})

    def test_empty_reports_are_useful(self):
        source = render_html({})
        markdown = render_markdown({})
        self.assertIn("No findings were produced.", source)
        self.assertIn("No source files recorded.", source)
        self.assertIn("No import warnings.", source)
        self.assertIn("No baseline supplied.", source)
        self.assertIn("No observations in this category.", source)
        self.assertIn("No findings were produced.", markdown)
        self.assertIn("No files recorded", markdown)
        self.assertEqual(json.loads(render_json({})), {})

    def test_hostile_strings_cannot_escape_any_html_context(self):
        hostile = '</script><img src="https://attacker.example/pixel" onerror="alert(1)"><script>alert(2)</script>" autofocus onfocus="alert(3)'
        report = report_fixture()
        report["name"] = hostile
        report["generated_at"] = hostile
        report["tool"]["version"] = hostile
        report["source"]["name"] = hostile
        report["scope"] = {"include": [hostile], "exclude": [hostile]}
        for item in report["observations"] + report["findings"]:
            item["asset"] = hostile
            item["confidence"] = hostile
            if "data" in item:
                item["data"] = {hostile: hostile}
            else:
                for key in ("title", "subject", "detail", "remediation", "rule_id", "id", "severity"):
                    item[key] = hostile
            item["evidence"] = [{key: hostile for key in ("path", "sha256", "line", "locator", "excerpt")}]
        report["coverage"] = [{key: hostile for key in ("path", "status", "parser", "bytes", "sha256", "reason")}]
        report["warnings"] = [{key: hostile for key in ("code", "path", "message")}]
        report["diff"] = {"note": hostile, "added_findings": [{"title": hostile, "asset": hostile}]}
        source = render_html(report)
        page = Page(source)
        self.assertNotIn(hostile, source)
        self.assertEqual(sum(tag == "script" for tag, _ in page.tags), 1)
        self.assertEqual(sum(tag == "style" for tag, _ in page.tags), 1)
        self.assertFalse(any(tag in {"img", "iframe", "object", "embed"} for tag, _ in page.tags))
        for _, attrs in page.tags:
            self.assertFalse(any(key.startswith("on") for key in attrs))
            self.assertNotIn("autofocus", attrs)
        self.assertIn("&lt;/script&gt;", source)
        # Escaping preserves searchable values without creating attributes.
        cards = [attrs for _, attrs in page.tags if "data-filterable" in attrs]
        self.assertTrue(cards)
        self.assertTrue(all(item["data-asset"] == hostile for item in cards))

    def test_offline_page_has_no_remote_dependencies_or_unsafe_dom_sinks(self):
        source = render_html(report_fixture())
        page = Page(source)
        for tag, attrs in page.tags:
            self.assertNotIn("src", attrs)
            if "href" in attrs:
                self.assertTrue(attrs["href"].startswith("#"), (tag, attrs))
        self.assertNotIn("@import", source)
        self.assertNotIn("innerHTML", source)
        self.assertNotIn("document.write", source)
        self.assertNotIn("fetch(", source)
        self.assertNotIn("XMLHttpRequest", source)
        self.assertIn("Content-Security-Policy", source)
        self.assertIn("default-src 'none'", source)
        self.assertIn("form-action 'none'", source)

    def test_markdown_escapes_imported_markup_and_preserves_provenance(self):
        report = report_fixture()
        hostile = '\n## Forged heading\n[click](javascript:alert(1)) ![pixel](https://attacker.example/) <img src=x onerror=alert(1)> `code` | extra'
        report["name"] = hostile
        report["findings"][0]["title"] = hostile
        report["findings"][0]["evidence"][0]["excerpt"] = hostile
        source = render_markdown(report)
        self.assertNotIn("\n## Forged heading", source)
        self.assertNotIn("[click](javascript:", source)
        self.assertNotIn("![pixel]", source)
        self.assertNotIn("<img", source)
        self.assertNotIn("`code`", source)
        self.assertIn("\\| extra", source)
        self.assertIn("SHA-256: " + "a" * 64, source)
        self.assertIn("line 14", source)
        self.assertIn("Severity: **medium** · Confidence: **high**", source)

    def test_baseline_handles_finding_service_and_changed_objects(self):
        report = report_fixture()
        service = report["observations"][0]
        report["diff"] = {"note": "A removed item may reflect missing coverage.",
                          "added_findings": [report["findings"][0]], "removed_findings": [],
                          "added_services": [service], "removed_services": ["former-service-id"],
                          "changed_services": [{"before": service, "after": service}]}
        for render in (render_html, render_markdown):
            source = render(report)
            self.assertIn("Added findings", source)
            self.assertIn("Changed services", source)
            self.assertIn("missing coverage", source)
            self.assertIn("former", source)
            self.assertIn("before", source)

    def test_unrecognized_severity_cannot_become_a_css_class(self):
        report = report_fixture()
        report["findings"][0]["severity"] = 'high" onclick="alert(1)'
        source = render_html(report)
        page = Page(source)
        badges = [attrs["class"] for _, attrs in page.tags if attrs.get("class", "").startswith("badge")]
        self.assertEqual(badges, ["badge info"])
        self.assertIn('data-severity="info"', source)


if __name__ == "__main__":
    unittest.main()
