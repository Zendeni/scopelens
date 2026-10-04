"""Behavioral regressions for evidence-driven findings and snapshot comparison."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scopelens.engine import analyze, compare_reports, in_scope, validate_report, validate_scope


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def httpx(self, rows, name="httpx.jsonl"):
        return self.write(name, "\n".join(json.dumps(row) for row in rows) + "\n")

    def nmap(self, text, name="services.txt"):
        return self.write(name, text)

    def report(self, source=None, **kwargs):
        return analyze(source or self.root, **kwargs)

    def sample_report(self):
        path = self.nmap("Nmap scan report for 192.0.2.10\n21/tcp open ftp ExampleFTP 1.0\n")
        return self.report(path)

    def test_scope_exact_hosts_cidrs_and_exclusions(self):
        scope = validate_scope({"include": ["EXAMPLE.TEST.", "192.0.2.25/24", "2001:db8::/64"],
                                "exclude": ["192.0.2.99", "2001:db8::99"]})
        for asset in ("example.test", "192.0.2.10", "2001:db8::10"):
            with self.subTest(asset=asset):
                self.assertTrue(in_scope(asset, scope))
        for asset in ("child.example.test", "notexample.test", "192.0.2.99", "198.51.100.1", "2001:db8::99"):
            with self.subTest(asset=asset):
                self.assertFalse(in_scope(asset, scope))
        self.assertIn("192.0.2.0/24", scope["include"])

    def test_scope_invalid_shapes_and_entries_are_rejected(self):
        for scope in ([], {"include": "example.test"}, {"include": [None]},
                      {"include": ["*.example.test"]}, {"include": ["https://example.test"]},
                      {"include": ["bad..example.test"]}, {"include": ["example.test.."]},
                      {"include": ["192.0.2.10.."]}, {"unknown": []}):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                validate_scope(scope)

    def test_expanded_ipv6_matches_normalized_include_and_exclude(self):
        expanded = "2001:0DB8:0000:0000:0000:0000:0000:0001"
        included = validate_scope({"include": ["2001:db8::1"], "exclude": []})
        excluded = validate_scope({"include": ["2001:db8::/64"], "exclude": ["2001:db8::1"]})
        self.assertTrue(in_scope(expanded, included))
        self.assertFalse(in_scope(expanded, excluded))

    def test_idna_hostname_scope_and_observation_use_same_identity(self):
        self.httpx([{"url": "https://täst.example.test/", "status_code": 200}])
        scope = {"include": ["xn--tst-qla.example.test"], "exclude": []}
        self.assertTrue(in_scope("TÄST.example.test.", validate_scope(scope)))
        report = self.report(scope=scope)
        self.assertEqual({item["asset"] for item in report["observations"]}, {"xn--tst-qla.example.test"})

    def test_scope_filters_observations_without_resolving_dns(self):
        self.httpx([{"url": "https://portal.example.test/", "status_code": 200},
                    {"url": "https://other.example.test/", "status_code": 200}])
        with mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS must stay offline")):
            report = self.report(scope={"include": ["portal.example.test"], "exclude": []})
        self.assertEqual({item["asset"] for item in report["observations"]}, {"portal.example.test"})
        self.assertIn("outside_scope", {item["code"] for item in report["warnings"]})

    def test_unspecified_scope_is_visible(self):
        report = self.sample_report()
        self.assertIn("scope_unspecified", {item["code"] for item in report["warnings"]})

    def test_tcp_udp_and_multiple_hosts_are_separate_services(self):
        self.nmap("Nmap scan report for 192.0.2.10\n53/tcp open domain\n53/udp open domain\n"
                  "Nmap scan report for 192.0.2.20\n53/tcp open domain\n")
        report = self.report()
        services = {(item["asset"], item["data"]["protocol"], item["data"]["port"])
                    for item in report["observations"] if item["kind"] == "service"}
        self.assertEqual(services, {("192.0.2.10", "tcp", 53), ("192.0.2.10", "udp", 53),
                                    ("192.0.2.20", "tcp", 53)})
        self.assertEqual(report["summary"]["services"], 3)

    def test_incomplete_httpx_headers_do_not_imply_missing_controls(self):
        self.httpx([{"url": "https://portal.example.test/", "status_code": 200,
                     "header": {"content-type": "text/html"}}])
        report = self.report()
        self.assertFalse(any(finding["rule_id"] in {"SL004", "SL005"} for finding in report["findings"]))

    def test_complete_header_findings_stay_on_the_affected_host(self):
        self.write("a.headers", "URL: https://portal.example.test/\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n")
        self.write("b.headers", "URL: https://secure.example.test/\nHTTP/1.1 200 OK\nContent-Type: text/html\n"
                   "Strict-Transport-Security: max-age=31536000\nContent-Security-Policy: default-src 'self'\n"
                   "X-Content-Type-Options: nosniff\n\n")
        findings = [finding for finding in self.report()["findings"] if finding["rule_id"] in {"SL004", "SL005"}]
        self.assertEqual(len(findings), 3)
        self.assertEqual({finding["asset"] for finding in findings}, {"portal.example.test"})
        self.assertTrue(all(evidence["path"] == "a.headers" for finding in findings for evidence in finding["evidence"]))

    def test_http_redirects_and_error_responses_are_not_cleartext_findings(self):
        self.httpx([{"url": "http://redirect.example.test/", "status_code": 301},
                    {"url": "http://error.example.test/", "status_code": 404},
                    {"url": "http://content.example.test/", "status_code": 200}])
        findings = [finding for finding in self.report()["findings"] if finding["rule_id"] == "SL003"]
        self.assertEqual([finding["asset"] for finding in findings], ["content.example.test"])

    def test_tls_wrapped_ftp_is_not_called_cleartext(self):
        self.write("services.xml", '<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/>'
                   '<ports><port protocol="tcp" portid="990"><state state="open"/>'
                   '<service name="ftp" tunnel="ssl"/></port></ports></host></nmaprun>')
        self.assertFalse(any(finding["rule_id"] == "SL001" for finding in self.report()["findings"]))

    def test_cookie_attributes_are_reviewed_without_exporting_cookie_values(self):
        self.httpx([{"url": "https://portal.example.test/", "status_code": 200,
                     "header": {"set-cookie": ["session=synthetic-first; Path=/; HttpOnly",
                                                  "preferences=synthetic-second; Path=/; Secure"]}}])
        report = self.report()
        serialized = json.dumps(report)
        self.assertNotIn("synthetic-first", serialized)
        self.assertNotIn("synthetic-second", serialized)
        findings = [finding for finding in report["findings"] if finding["rule_id"] == "SL006"]
        self.assertEqual(len(findings), 1)
        self.assertIn("cookie:session", findings[0]["subject"])

    def test_url_credentials_queries_and_fragments_are_not_exported(self):
        self.httpx([{"url": "https://demo:synthetic-password@portal.example.test/login?token=synthetic-token#synthetic-fragment",
                     "status_code": 200, "title": "password=synthetic-title-secret"}])
        report = self.report()
        serialized = json.dumps(report)
        for value in ("synthetic-password", "synthetic-token", "synthetic-fragment", "synthetic-title-secret"):
            self.assertNotIn(value, serialized)
        self.assertEqual(next(o for o in report["observations"] if o["kind"] == "web")["data"]["url"],
                         "https://portal.example.test/login")

    def test_duplicate_evidence_merges_without_inflating_inventory(self):
        text = "Nmap scan report for 192.0.2.10\n21/tcp open ftp\n"
        self.nmap(text, "first.txt")
        self.nmap(text, "second.txt")
        report = self.report()
        service = next(item for item in report["observations"] if item["kind"] == "service")
        self.assertEqual(report["summary"]["services"], 1)
        self.assertEqual({e["path"] for e in service["evidence"]}, {"first.txt", "second.txt"})
        self.assertEqual(len([f for f in report["findings"] if f["rule_id"] == "SL001"]), 1)

    def test_ids_do_not_change_with_source_path_or_redacted_query_values(self):
        first = self.httpx([{"url": "https://portal.example.test/?token=first-secret", "status_code": 200}], "first/httpx.jsonl")
        second = self.httpx([{"url": "https://portal.example.test/?token=second-secret", "status_code": 200}], "second/httpx.jsonl")
        a, b = self.report(first), self.report(second)
        self.assertEqual([o["id"] for o in a["observations"]], [o["id"] for o in b["observations"]])
        self.assertNotEqual(a["observations"][0]["evidence"][0]["sha256"], b["observations"][0]["evidence"][0]["sha256"])

    def test_unrecognized_and_malformed_artifacts_do_not_report_clean_coverage(self):
        self.write("opaque.txt", "Unrecognized data without supported records.")
        self.write("broken.json", "{")
        report = self.report()
        coverage = {row["path"]: row for row in report["coverage"]}
        self.assertEqual(coverage["opaque.txt"]["status"], "unrecognized")
        self.assertEqual(coverage["broken.json"]["status"], "error")
        self.assertIn("no_observations", {item["code"] for item in report["warnings"]})

    def test_valid_rows_and_parse_errors_both_remain_visible(self):
        self.write("httpx.jsonl", '{"url":"https://portal.example.test/","status_code":200}\n{\n')
        report = self.report()
        self.assertEqual(report["coverage"][0]["status"], "parsed")
        self.assertIn("diagnostics", report["coverage"][0].get("reason", "").lower())
        self.assertTrue(any("malformed" in warning["code"] for warning in report["warnings"]))

    def test_scoped_packages_remain_unassociated_inventory(self):
        self.nmap("Nmap scan report for 192.0.2.10\n53/tcp open domain\n")
        self.write("requirements.txt", "example-component==1.2.3\n")
        report = self.report(scope={"include": ["192.0.2.10"], "exclude": []})
        self.assertEqual(report["summary"]["packages"], 1)
        self.assertEqual(report["summary"]["assets"], 1)
        self.assertIn("unattributed_packages", {item["code"] for item in report["warnings"]})

    def test_conflicting_versions_are_not_silently_merged(self):
        self.nmap("Nmap scan report for 192.0.2.10\n22/tcp open ssh OpenSSH 9.8\n", "old.txt")
        self.nmap("Nmap scan report for 192.0.2.10\n22/tcp open ssh OpenSSH 9.9\n", "new.txt")
        report = self.report()
        findings = [finding for finding in report["findings"] if finding["rule_id"] == "SL007"]
        self.assertEqual(len(findings), 2)
        self.assertTrue(any("9.8" in finding["detail"] for finding in findings))
        self.assertTrue(any("9.9" in finding["detail"] for finding in findings))
        self.assertIn("conflicting_service_evidence", {item["code"] for item in report["warnings"]})

    def test_diff_distinguishes_added_removed_and_changed_services(self):
        before = self.report(self.nmap("Nmap scan report for 192.0.2.10\n21/tcp open ftp\n22/tcp open ssh OpenSSH 9.8\n", "before.txt"))
        after = self.report(self.nmap("Nmap scan report for 192.0.2.10\n22/tcp open ssh OpenSSH 9.9\n53/udp open domain\n"
                                     "Nmap scan report for 192.0.2.20\n443/tcp open https\n", "after.txt"))
        delta = compare_reports(before, after)
        self.assertEqual({(o["asset"], o["data"]["protocol"], o["data"]["port"]) for o in delta["added_services"]},
                         {("192.0.2.10", "udp", 53), ("192.0.2.20", "tcp", 443)})
        self.assertEqual([o["data"]["port"] for o in delta["removed_services"]], [21])
        self.assertEqual(len(delta["changed_services"]), 1)
        self.assertEqual(delta["changed_services"][0]["asset"], "192.0.2.10")
        self.assertTrue(any(f["rule_id"] == "SL001" for f in delta["removed_findings"]))
        self.assertIn("do not prove remediation", delta["note"])

    def test_reordered_snapshot_has_no_changes(self):
        before = self.sample_report()
        after = copy.deepcopy(before)
        after["observations"].reverse()
        after["findings"].reverse()
        delta = compare_reports(before, after)
        for key, value in delta.items():
            if key != "note":
                self.assertEqual(value, [], key)

    def test_diff_with_conflicting_service_evidence_is_independent_of_row_order(self):
        before = self.report(self.nmap(
            "Nmap scan report for 192.0.2.10\n22/tcp open ssh OpenSSH 9.8\n",
            "before.txt"))
        after = self.report(self.nmap(
            "Nmap scan report for 192.0.2.10\n22/tcp open ssh OpenSSH 9.9\n"
            "22/tcp open ssh OpenSSH 9.10\n21/tcp open ftp ExampleFTP 1.0\n"
            "21/tcp open ftp ExampleFTP 2.0\n", "after.txt"))
        reordered = copy.deepcopy(after)
        reordered["observations"].reverse()
        reordered["findings"].reverse()
        original_rows = copy.deepcopy(reordered["observations"])
        self.assertEqual(compare_reports(before, after), compare_reports(before, reordered))
        self.assertEqual(compare_reports(after, before), compare_reports(reordered, before))
        self.assertEqual(reordered["observations"], original_rows)
        changed = compare_reports(before, after)["changed_services"]
        self.assertEqual(len(changed), 1)
        self.assertEqual(len(changed[0]["after"]), 2)

    def test_diff_redacts_baseline_records_without_mutating_the_baseline(self):
        before = self.sample_report()
        before["findings"][0]["detail"] = "Recorded token=EXAMPLE_VALUE"
        service = next(item for item in before["observations"] if item["kind"] == "service")
        service["data"]["product"] = "Recorded token=EXAMPLE_VALUE"
        after = copy.deepcopy(before)
        after["observations"] = []
        after["findings"] = []
        delta = compare_reports(before, after)
        self.assertNotIn("EXAMPLE_VALUE", json.dumps(delta))
        self.assertTrue(delta["removed_services"])
        self.assertTrue(delta["removed_findings"])
        self.assertIn("EXAMPLE_VALUE", before["findings"][0]["detail"])

    def test_baseline_schema_version_is_an_integer_and_supported(self):
        for version in (True, "1", 0, 2, None):
            with self.subTest(version=version):
                report = self.sample_report()
                report["schema_version"] = version
                with self.assertRaises(ValueError):
                    validate_report(report)

    def test_malformed_baseline_lists_are_rejected(self):
        for key in ("observations", "findings"):
            with self.subTest(key=key):
                report = self.sample_report()
                report[key] = {}
                with self.assertRaises(ValueError):
                    compare_reports(report, self.sample_report())

    def test_baseline_protocol_and_port_types_are_validated(self):
        cases = [("protocol", []), ("protocol", "unknown"), ("port", True),
                 ("port", 0), ("port", -1), ("port", 65536), ("port", "21")]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                report = self.sample_report()
                service = next(o for o in report["observations"] if o["kind"] == "service")
                service["data"][key] = value
                with self.assertRaises(ValueError):
                    validate_report(report)

    def test_duplicate_baseline_identities_are_rejected(self):
        for key in ("observations", "findings"):
            with self.subTest(key=key):
                report = self.sample_report()
                report[key].append(copy.deepcopy(report[key][0]))
                with self.assertRaises(ValueError):
                    validate_report(report)


if __name__ == "__main__":
    unittest.main()
