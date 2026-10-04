import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scopelens.cli import main
from scopelens.inputs import load_input
from scopelens.workspace import review


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "Old workspace"
        self.workspace.mkdir()
        (self.workspace / ".target.env").write_text(
            'BOX="Example"\nIP=192.0.2.7\nHOST=portal.example.test\n', encoding="utf-8")
        (self.workspace / "notes.md").write_text("Existing notes\n", encoding="utf-8")
        (self.workspace / "scan.txt").write_text(
            "Nmap scan report for 192.0.2.7\n21/tcp open ftp Example 1.2\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = main([str(value) for value in args])
        return result, out.getvalue(), err.getvalue()

    def snapshot(self):
        return {path.relative_to(self.workspace).as_posix(): path.read_bytes()
                for path in self.workspace.rglob("*") if path.is_file()}

    def test_prepare_preserves_existing_scope_notes_and_custom_helpers(self):
        custom_scope = '{"include":["192.0.2.0/24"],"exclude":["192.0.2.8"]}\n'
        (self.workspace / "scope.json").write_text(custom_scope, encoding="utf-8")
        (self.workspace / "analyze.sh").write_text("#!/bin/sh\necho custom\n", encoding="utf-8")
        before = self.snapshot()
        code, out, err = self.run_cli("prepare", self.workspace, "--target", "192.0.2.9")
        self.assertEqual(code, 0, err)
        for filename, content in before.items():
            self.assertEqual((self.workspace / filename).read_bytes(), content)
        self.assertIn("Preserved customized helper: analyze.sh", out)
        self.assertIn("scope_preserved", out)
        self.assertTrue((self.workspace / "inspect.sh").exists())

    def test_prepare_infers_literal_metadata_and_is_idempotent_without_execution(self):
        marker = self.root / "should-not-exist"
        with (self.workspace / ".target.env").open("a", encoding="utf-8") as stream:
            stream.write(f'HOST=$(touch "{marker}")\nPASSWORD=private-value\n')
        with patch("socket.socket", side_effect=AssertionError("network")), patch("subprocess.Popen", side_effect=AssertionError("execution")):
            code, out, err = self.run_cli("prepare", self.workspace)
            self.assertEqual(code, 0, err)
            before = self.snapshot()
            self.assertEqual(self.run_cli("prepare", self.workspace)[0], 0)
            self.assertEqual(before, self.snapshot())
        self.assertFalse(marker.exists())
        self.assertNotIn("private-value", out)
        self.assertEqual(json.loads((self.workspace / "scope.json").read_text()),
                         {"include": ["192.0.2.7", "portal.example.test"], "exclude": []})
        helper = (self.workspace / "analyze.sh").read_text()
        self.assertIn('exec "${HTB_PYTHON:-python3}" -I -m scopelens review "$SCRIPT_DIR" "$@"', helper)
        self.assertNotIn("source ", helper)
        self.assertIn("BASH_SOURCE[0]", helper)

    def test_explicit_targets_override_inference_for_new_scope(self):
        code, _, err = self.run_cli("prepare", self.workspace, "--target", "192.0.2.99", "--target", "EXAMPLE.TEST")
        self.assertEqual(code, 0, err)
        scope = json.loads((self.workspace / "scope.json").read_text())
        self.assertEqual(scope["include"], ["192.0.2.99", "example.test"])

    def test_prepare_requires_usable_scope_and_validates_before_writes(self):
        (self.workspace / ".target.env").write_text("IP=$(not-executed)\n", encoding="utf-8")
        before = self.snapshot()
        code, _, err = self.run_cli("prepare", self.workspace)
        self.assertEqual(code, 2)
        self.assertIn("--target HOST", err)
        self.assertEqual(before, self.snapshot())
        (self.workspace / "scope.json").write_text('{"include": 3}', encoding="utf-8")
        before = self.snapshot()
        self.assertEqual(self.run_cli("prepare", self.workspace)[0], 2)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.run_cli("prepare", self.root / "absent", "--target", "192.0.2.7")[0], 2)
        self.assertFalse((self.root / "absent").exists())

    def test_review_requires_scope_before_creating_output(self):
        before = self.snapshot()
        code, _, err = self.run_cli("review", self.workspace)
        self.assertEqual(code, 2)
        self.assertIn("prepare", err)
        self.assertEqual(before, self.snapshot())

    def test_review_does_not_reenter_cli_or_parse_arguments(self):
        self.assertEqual(self.run_cli("prepare", self.workspace)[0], 0)
        with patch("scopelens.cli.main", side_effect=AssertionError("recursive CLI call")), \
                patch("argparse.ArgumentParser.parse_args", side_effect=AssertionError("recursive argument parsing")), \
                contextlib.redirect_stdout(io.StringIO()):
            code = review(self.workspace, format="json", fail_on="medium")
        self.assertEqual(code, 1)
        self.assertEqual(len(list((self.workspace / "reports").glob("*/report.json"))), 1)

    def test_analyze_and_review_share_severity_threshold_semantics(self):
        self.assertEqual(self.run_cli("prepare", self.workspace)[0], 0)
        for severity, expected in (("medium", 1), ("critical", 0)):
            with self.subTest(severity=severity):
                direct = self.run_cli("analyze", self.workspace, "--scope", self.workspace / "scope.json",
                                      "-o", self.root / severity, "--fail-on", severity, "--format", "json")
                reviewed = self.run_cli("review", self.workspace, "--fail-on", severity, "--format", "json")
                self.assertEqual(direct[0], expected, direct[2])
                self.assertEqual(reviewed[0], expected, reviewed[2])

    def test_review_unique_snapshots_baseline_and_threshold_exit(self):
        self.assertEqual(self.run_cli("prepare", self.workspace)[0], 0)
        with patch("socket.socket", side_effect=AssertionError("network")), patch("subprocess.Popen", side_effect=AssertionError("execution")):
            code, out, err = self.run_cli("review", self.workspace, "--fail-on", "medium")
            self.assertEqual(code, 1, err)
            snapshots = list((self.workspace / "reports").iterdir())
            self.assertEqual(len(snapshots), 1)
            first = snapshots[0]
            original = (first / "report.json").read_bytes()
            self.assertIn(str(first / "report.html"), out)
            (self.workspace / "scan.txt").write_text(
                "Nmap scan report for 192.0.2.7\n22/tcp open ssh Example 2.0\n", encoding="utf-8")
            code, out, err = self.run_cli("review", self.workspace, "--baseline", "latest")
            self.assertEqual(code, 0, err)
        self.assertIn(str(first / "report.json"), out)
        snapshots = list((self.workspace / "reports").iterdir())
        self.assertEqual(len(snapshots), 2)
        second = next(path for path in snapshots if path != first)
        report = json.loads((second / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(len(report["diff"]["added_services"]), 1)
        self.assertEqual(len(report["diff"]["removed_services"]), 1)
        self.assertEqual((first / "report.json").read_bytes(), original)
        self.assertEqual(report["scope"]["include"], ["192.0.2.7", "portal.example.test"])
        self.assertEqual(report["name"], "Example")
        self.assertFalse(any(item.get("path", "").lower() in {"scope.json", "assessment.json", "analysis.md"}
                             for item in report["warnings"]))

    def test_latest_requires_valid_prior_json_and_preserves_empty_exit(self):
        self.assertEqual(self.run_cli("prepare", self.workspace)[0], 0)
        code, _, err = self.run_cli("review", self.workspace, "--baseline", "latest")
        self.assertEqual(code, 2)
        self.assertIn("without --baseline", err)
        self.assertFalse((self.workspace / "reports").exists())
        (self.workspace / ".target.env").unlink()
        (self.workspace / "scan.txt").write_text("", encoding="utf-8")
        self.assertEqual(self.run_cli("review", self.workspace)[0], 2)
        self.assertEqual(len(list((self.workspace / "reports").glob("*/report.json"))), 1)

    def test_inspection_is_read_only_and_counts_match_loader(self):
        self.assertEqual(self.run_cli("prepare", self.workspace)[0], 0)
        self.assertEqual(self.run_cli("review", self.workspace)[0], 0)
        (self.workspace / "empty.txt").touch()
        before = self.snapshot()
        code, out, err = self.run_cli("inspect", self.workspace, "--json")
        self.assertEqual(code, 0, err)
        inventory = json.loads(out)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(inventory["scope"]["status"], "valid")
        self.assertEqual(inventory["targets"][0]["ip"], "192.0.2.7")
        _, coverage, _ = load_input(self.workspace)
        for status, count in inventory["artifact_counts"].items():
            self.assertEqual(count, sum(row["status"] == status for row in coverage))
        self.assertEqual(inventory["artifact_counts"]["empty"], 1)
        self.assertEqual(len(inventory["reports"]), 1)
        report = json.loads(Path(inventory["reports"][0]["paths"]["json"]).read_text(encoding="utf-8"))
        self.assertEqual(inventory["reports"][0]["summary"]["findings"], report["summary"]["findings"])
        self.assertIn("Loaded means readable artifact", self.run_cli("inspect", self.workspace)[1])

    def test_invalid_reports_are_diagnosed_and_never_latest(self):
        self.assertEqual(self.run_cli("prepare", self.workspace)[0], 0)
        self.assertEqual(self.run_cli("review", self.workspace, "--format", "json")[0], 0)
        valid = next((self.workspace / "reports").glob("*/report.json"))
        damaged = self.workspace / "reports" / "newer-invalid"
        damaged.mkdir()
        (damaged / "report.json").write_text('{"schema_version": 1}', encoding="utf-8")
        code, out, err = self.run_cli("inspect", self.workspace, "--json")
        self.assertEqual(code, 0, err)
        inventory = json.loads(out)
        self.assertEqual(len(inventory["reports"]), 1)
        self.assertIn("invalid_report", [item["code"] for item in inventory["diagnostics"]])
        code, out, err = self.run_cli("review", self.workspace, "--baseline", "latest", "--format", "html")
        self.assertEqual(code, 0, err)
        self.assertIn(str(valid), out)
        inventory = json.loads(self.run_cli("inspect", self.workspace, "--json")[1])
        self.assertEqual(len(inventory["reports"]), 2)
        self.assertIn("without_json", [item["status"] for item in inventory["reports"]])

    def test_malformed_scope_inspection_returns_diagnostic_and_error(self):
        (self.workspace / "scope.json").write_text("not json", encoding="utf-8")
        code, out, _ = self.run_cli("inspect", self.workspace, "--json")
        self.assertEqual(code, 2)
        inventory = json.loads(out)
        self.assertEqual(inventory["scope"]["status"], "invalid")
        self.assertIn("scope_invalid", [item["code"] for item in inventory["diagnostics"]])

    def test_latest_refuses_incomplete_report_inventory(self):
        self.assertEqual(self.run_cli("prepare", self.workspace)[0], 0)
        self.assertEqual(self.run_cli("review", self.workspace)[0], 0)
        before = self.snapshot()
        for setting, value in (("MAX_REPORT_ENTRIES", 0), ("MAX_REPORT_BYTES", 1)):
            with self.subTest(setting=setting), patch(f"scopelens.workspace.{setting}", value):
                code, _, err = self.run_cli("review", self.workspace, "--baseline", "latest")
                self.assertEqual(code, 2)
                self.assertIn("--baseline FILE", err)
                self.assertIn("incomplete", err)
        self.assertEqual(before, self.snapshot())

    def test_direct_reports_directory_is_an_eligible_existing_baseline(self):
        self.assertEqual(self.run_cli("prepare", self.workspace)[0], 0)
        prior = self.workspace / "reports"
        self.assertEqual(self.run_cli("analyze", self.workspace, "-o", prior,
                                      "--scope", self.workspace / "scope.json")[0], 0)
        code, out, err = self.run_cli("review", self.workspace, "--baseline", "latest")
        self.assertEqual(code, 0, err)
        self.assertIn(f"Baseline: {prior / 'report.json'}", out)

    def test_managed_links_are_rejected(self):
        external = self.root / "external.json"
        external.write_text('{"include":["192.0.2.7"],"exclude":[]}', encoding="utf-8")
        link = self.workspace / "scope.json"
        try:
            link.symlink_to(external)
        except OSError:
            self.skipTest("Creating symlinks is not permitted on this host")
        before = external.read_bytes()
        for command in ("prepare", "review"):
            code, _, err = self.run_cli(command, self.workspace)
            self.assertEqual(code, 2)
            self.assertIn("Links are not allowed", err)
        self.assertEqual(external.read_bytes(), before)
        self.assertFalse((self.workspace / "analyze.sh").exists())


if __name__ == "__main__":
    unittest.main()
