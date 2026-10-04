"""Importer regression tests using synthetic, offline-only evidence."""
import hashlib
import json
import unittest
from unittest.mock import patch
from xml.parsers import expat

from scopelens.model import Document
from scopelens.parsers import parse_documents


def doc(path, text):
    return Document(path, text, hashlib.sha256(text.encode()).hexdigest(), len(text.encode()))


class ParserTests(unittest.TestCase):
    def parse(self, path, text):
        return parse_documents([doc(path, text)])

    def test_nmap_xml_multi_host_and_protocols(self):
        raw = '''<?xml version="1.0"?><!DOCTYPE nmaprun>
<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames><hostname name="portal.example.test"/></hostnames><ports>
<port protocol="tcp" portid="53"><state state="open"/><service name="domain" product="BIND" version="9.18"/></port>
<port protocol="udp" portid="53"><state state="open|filtered"/></port>
</ports></host><host><address addr="192.0.2.20" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host></nmaprun>'''
        observations, warnings = self.parse("scans/services.xml", raw)
        self.assertEqual(warnings, [])
        services = [o for o in observations if o["kind"] == "service"]
        self.assertEqual([(s["asset"], s["data"]["port"], s["data"]["protocol"]) for s in services],
                         [("192.0.2.10", 53, "tcp"), ("192.0.2.10", 53, "udp"), ("192.0.2.20", 443, "tcp")])
        self.assertEqual(services[0]["data"]["version"], "9.18")
        self.assertNotEqual(services[0]["id"], services[1]["id"])

    def test_hostile_xml_and_malformed_xml(self):
        for raw in ['<!DOCTYPE nmaprun [<!ENTITY x "boom">]><nmaprun/>',
                    '<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd"><nmaprun/>',
                    '<!DOCTYPE nmaprun PUBLIC "test" "https://example.test/dtd"><nmaprun/>']:
            with self.subTest(raw=raw):
                observations, warnings = self.parse("x.xml", raw)
                self.assertEqual(observations, [])
                self.assertEqual(warnings[0]["code"], "unsafe-xml")
        _, warnings = self.parse("x.xml", "<nmaprun><host>")
        self.assertEqual(warnings[0]["code"], "malformed-xml")

    def test_xml_repeated_port_evidence_points_to_each_host(self):
        raw = '''<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/></port>
</ports></host><host><address addr="192.0.2.20" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/></port>
</ports></host></nmaprun>'''
        observations, warnings = self.parse("services.xml", raw)
        self.assertEqual(warnings, [])
        services = [o for o in observations if o["kind"] == "service"]
        self.assertEqual([o["evidence"][0]["line"] for o in services], [2, 4])

    def test_xml_source_location_failures_become_warnings(self):
        with patch("scopelens.parsers._xml_locations", side_effect=expat.ExpatError("invalid encoding")):
            observations, warnings = self.parse("scan.xml", "<nmaprun/>")
        self.assertEqual(observations, [])
        self.assertEqual(warnings[0]["code"], "malformed-xml")

    def test_tls_wrapped_services_retain_tunnel(self):
        observations, warnings = parse_documents([
            doc("scan.xml", '<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="990"><state state="open"/><service name="ftp" tunnel="ssl"/></port></ports></host></nmaprun>'),
            doc("nmap.txt", 'Nmap scan report for 192.0.2.20\n990/tcp open ssl/ftp\n21/tcp open ftp\n')])
        self.assertEqual(warnings, [])
        services = [o["data"] for o in observations if o["kind"] == "service"]
        self.assertEqual([(s["service"], s["tunnel"]) for s in services], [("ftp", "ssl"), ("ssl/ftp", "ssl"), ("ftp", "")])

    def test_text_host_isolation_and_versions(self):
        observations, warnings = self.parse("tcp-services.txt", '''22/tcp open ssh
Nmap scan report for portal.example.test (192.0.2.10)
22/tcp open ssh OpenSSH 9.6p1 Ubuntu
53/udp open domain BIND 9.18
Nmap scan report for 192.0.2.20
443/tcp open ssl/http Apache httpd 2.4.62
Nmap scan report for !invalid!
80/tcp open http nginx 1.24
''')
        services = [o for o in observations if o["kind"] == "service"]
        self.assertEqual(len(services), 3)
        self.assertEqual([o["asset"] for o in services], ["192.0.2.10", "192.0.2.10", "192.0.2.20"])
        self.assertEqual(services[2]["data"]["product"], "Apache httpd")
        self.assertEqual(services[2]["data"]["version"], "2.4.62")
        self.assertEqual(len(warnings), 3)

    def test_env_is_data_and_never_supplies_global_fallback(self):
        observations, warnings = parse_documents([
            doc(".target.env", 'BOX="demo"\nIP="192.0.2.10"\nHOST=$(touch /tmp/nope)\n'),
            doc("ports.txt", "80/tcp open http\n")])
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["data"]["host"], "")
        self.assertEqual({w["code"] for w in warnings}, {"unsafe-target-value", "unattributed-service"})

    def test_httpx_jsonl_redacts_urls_and_cookie_values(self):
        raw = '\n'.join([json.dumps({"url": "https://alice:secret@portal.example.test:8443/admin?token=hidden#frag",
                                    "status_code": 200, "title": "Portal", "tech": ["nginx", "nginx"],
                                    "header": {"server": "nginx", "authorization": "private",
                                               "set-cookie": "sid=private; HttpOnly; Secure; SameSite=Lax"}}),
                         '{broken',
                         json.dumps({"url": "https://other.example.test", "status_code": 404})])
        observations, warnings = self.parse("httpx.jsonl", raw)
        self.assertEqual(len(observations), 2)
        web = observations[0]["data"]
        self.assertEqual(web["url"], "https://portal.example.test:8443/admin")
        self.assertEqual(web["headers"], {"server": "nginx"})
        self.assertEqual(web["cookies"], [{"name": "sid", "secure": True, "http_only": True, "same_site": "lax"}])
        self.assertFalse(web["headers_complete"])
        self.assertNotIn("private", json.dumps(web))
        self.assertEqual(warnings[0]["code"], "malformed-json")

    def test_invalid_json_schemas_do_not_crash(self):
        for raw in ['null', '42', '"str"', '[null, 1, "str"]', '{"url": []}', '{"results": {}}']:
            with self.subTest(raw=raw):
                observations, warnings = self.parse("httpx.json", raw)
                self.assertEqual(observations, [])
                self.assertTrue(warnings)

    def test_httpx_redirect_response_uses_final_url_and_host(self):
        observations, warnings = self.parse("httpx.jsonl", json.dumps({
            "url": "http://original.example.test/", "input": "http://original.example.test/",
            "final_url": "https://final.example.test/login?session=EXAMPLE", "status_code": 200}))
        self.assertEqual(warnings, [])
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["asset"], "final.example.test")
        self.assertEqual(observations[0]["data"]["url"], "https://final.example.test/login")
        # Import here to verify the boundary between response attribution and
        # transport/scope decisions without duplicating those decisions.
        from scopelens.engine import build_findings, in_scope, validate_scope
        self.assertFalse(any(f["rule_id"] == "SL003" for f in build_findings(observations)))
        self.assertFalse(in_scope(observations[0]["asset"], validate_scope({"include": ["original.example.test"]})))
        self.assertTrue(in_scope(observations[0]["asset"], validate_scope({"include": ["final.example.test"]})))

    def test_invalid_explicit_httpx_final_url_does_not_fall_back(self):
        for final in ("", None, [], "file:///example", "https://host.example.test:invalid/"):
            with self.subTest(final_url=final):
                observations, warnings = self.parse("httpx.jsonl", json.dumps({
                    "url": "http://original.example.test/", "final_url": final, "status_code": 200}))
                self.assertEqual(observations, [])
                self.assertEqual(warnings[0]["code"], "invalid-final-url")

    def test_httpx_plain_does_not_guess_column_meaning(self):
        observations, warnings = self.parse("httpx.txt", "https://portal.example.test [200] [42] [Admin] [nginx]\nhttps://other.example.test [404]\n")
        self.assertEqual(warnings, [])
        self.assertEqual(len(observations), 2)
        self.assertEqual(observations[0]["data"]["status"], 200)
        self.assertEqual(observations[0]["data"]["title"], "")

    def test_ffuf_content_and_vhost_attribution(self):
        observations, _ = self.parse("ffuf.json", json.dumps({"results": [
            {"url": "http://portal.example.test/admin?key=hidden", "status": 403}]}))
        self.assertEqual(observations[0]["data"]["url"], "http://portal.example.test/admin")
        observations, warnings = self.parse("ffuf-vhosts.json", json.dumps({"config": {"headers": {"Host": "FUZZ.example.test"}}, "results": [
            {"url": "http://192.0.2.10/", "host": "admin.example.test", "status": 200},
            {"url": "http://192.0.2.10/", "status": 200}]}))
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["asset"], "admin.example.test")
        self.assertEqual(warnings[0]["code"], "unattributed-vhost")

    def test_ffuf_literal_host_field_controls_attribution(self):
        observations, warnings = self.parse("ffuf.json", json.dumps({"results": [
            {"url": "http://192.0.2.10/admin", "host": "portal.example.test:8080", "status": 200},
            {"url": "http://192.0.2.10/", "host": "other.example.test/path", "status": 200}]}))
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["data"]["url"], "http://portal.example.test:8080/admin")
        self.assertEqual(warnings[0]["code"], "unattributed-vhost")
        observations, warnings = self.parse("ffuf.json", json.dumps({"results": [
            {"url": "http://192.0.2.10:8080/admin", "host": "portal.example.test", "status": 200}]}))
        self.assertEqual(warnings, [])
        self.assertEqual(observations[0]["data"]["url"], "http://portal.example.test:8080/admin")

    def test_raw_headers_explicit_url_and_cookie_flags(self):
        observations, warnings = self.parse("headers.txt", "URL: https://portal.example.test/\nHTTP/1.1 200 OK\nServer: nginx\nX-Content-Type-Options: nosniff\nSet-Cookie: sid=private; HttpOnly\nAuthorization: private\n\n")
        self.assertEqual(warnings, [])
        web = observations[0]["data"]
        self.assertTrue(web["headers_complete"])
        self.assertEqual(web["status"], 200)
        self.assertEqual(web["headers"]["x-content-type-options"], "nosniff")
        self.assertFalse(web["cookies"][0]["secure"])
        self.assertNotIn("private", json.dumps(web))

    def test_header_filename_and_ambiguous_host_override(self):
        observations, warnings = parse_documents([
            doc("enum/web/headers-http___192_0_2_10_8080.txt", "HTTP/1.1 200 OK\nServer: nginx\n"),
            doc("enum/web/headers-host-http___192_0_2_10_8080.txt", "HTTP/1.1 200 OK\nServer: Apache\n")])
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["data"]["url"], "http://192.0.2.10:8080/")
        self.assertEqual(warnings[0]["code"], "unattributed-headers")

    def test_headers_known_url_matching_and_redirect_rejection(self):
        observations, warnings = parse_documents([
            doc("live-web-urls.txt", "https://portal.example.test\n"),
            doc("headers-https___portal_example_test.txt", "HTTP/2 200\nServer: nginx\n"),
            doc("redirect-headers.txt", "URL: https://portal.example.test\nHTTP/1.1 301 Redirect\nLocation: https://other.example.test\n\nHTTP/2 200\nServer: nginx\n")])
        self.assertEqual(len(observations), 2)
        self.assertEqual(warnings[0]["code"], "ambiguous-headers")

    def test_ipv6_header_filename_matches_known_url_and_redacts_query(self):
        observations, warnings = parse_documents([
            doc("httpx.jsonl", json.dumps({"url": "https://alice:secret@[2001:db8::10]:8443/Admin?private=hidden#fragment", "status_code": 200})),
            doc("headers-https___[2001_db8__10]_8443_Admin.txt", "HTTP/2 200\nServer: nginx\n")])
        self.assertEqual(warnings, [])
        self.assertEqual(len(observations), 2)
        self.assertEqual({o["asset"] for o in observations}, {"2001:db8::10"})
        self.assertEqual({o["data"]["url"] for o in observations}, {"https://[2001:db8::10]:8443/Admin"})
        serialized = json.dumps(observations)
        for secret in ("alice", "secret", "hidden", "fragment"):
            self.assertNotIn(secret, serialized)

    def test_unknown_ipv6_filename_is_not_guessed(self):
        observations, warnings = self.parse("headers-https___[2001_db8__10]_8443.txt", "HTTP/2 200\nServer: nginx\n")
        self.assertEqual(observations, [])
        self.assertEqual(warnings[0]["code"], "unattributed-headers")

    def test_observation_limits_are_global_and_per_document(self):
        source = "\n".join(f"https://portal.example.test/{i}" for i in range(4))
        with patch("scopelens.parsers.MAX_OBSERVATIONS_PER_DOCUMENT", 2):
            observations, warnings = parse_documents([doc("httpx-a.txt", source), doc("httpx-b.txt", source)])
        self.assertEqual(len(observations), 4)
        self.assertEqual(len(warnings), 2)
        self.assertTrue(all(w["code"] == "observation-limit" and "incomplete" in w["message"] for w in warnings))
        with patch("scopelens.parsers.MAX_OBSERVATIONS", 3):
            observations, warnings = parse_documents([doc("httpx-a.txt", source), doc("httpx-b.txt", source)])
        self.assertEqual(len(observations), 3)
        self.assertEqual(len(warnings), 1)

    def test_malformed_record_warning_budget_stops_document(self):
        with patch("scopelens.parsers.MAX_WARNINGS_PER_DOCUMENT", 2):
            observations, warnings = parse_documents([doc("httpx.jsonl", "null\n" * 10), doc("httpx.txt", "https://portal.example.test/\n")])
        self.assertEqual(len(observations), 1)
        self.assertEqual(len(warnings), 3)
        self.assertEqual(warnings[-1]["code"], "warning-limit")

    def test_web_metadata_is_bounded(self):
        with patch("scopelens.parsers.MAX_WEB_METADATA_ITEMS", 2):
            observations, warnings = self.parse("httpx.json", json.dumps({"url": "https://portal.example.test", "tech": ["a", "b", "c"]}))
        self.assertEqual(observations, [])
        self.assertEqual(warnings[0]["code"], "web-metadata-limit")

    def test_packages_exact_pins_and_nested_npm(self):
        observations, warnings = parse_documents([
            doc("requirements.txt", "Requests==2.32.3\nFlask>=2\nDjango==5.1; python_version >= '3.10'\n-e git+https://example.test/repo\n"),
            doc("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/foo": {"version": "1.2.3"},
                "node_modules/foo/node_modules/@example/bar": {"version": "4.5.6"},
                "node_modules/local": {"version": "file:../local"}}}))])
        packages = [o["data"] for o in observations]
        self.assertEqual([(p["name"], p["version"]) for p in packages],
                         [("requests", "2.32.3"), ("django", "5.1"), ("foo", "1.2.3"), ("@example/bar", "4.5.6")])
        self.assertEqual(len(warnings), 2)


if __name__ == "__main__":
    unittest.main()
