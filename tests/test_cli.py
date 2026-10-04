import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scopelens.cli import main


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "evidence"
        self.source.mkdir()
        (self.source / "scan.txt").write_text("Nmap scan report for 192.0.2.7\n21/tcp open ftp Example 1.2\n53/udp open domain\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def test_complete_offline_workflow_and_threshold(self):
        output = self.root / "report"
        with patch("socket.socket", side_effect=AssertionError("Network use is forbidden")), patch("subprocess.Popen", side_effect=AssertionError("Subprocess use is forbidden")):
            code, out, err = self.run_cli("analyze", self.source, "-o", output, "--fail-on", "medium")
        self.assertEqual(code, 1, err)
        self.assertIn("2 services", out)
        self.assertEqual({p.name for p in output.iterdir()}, {"report.json", "report.md", "report.html"})
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["services"], 2)
        self.assertTrue(any(f["rule_id"] == "SL001" for f in report["findings"]))

    def test_no_overwrite_and_selected_format(self):
        output = self.root / "report"
        self.assertEqual(self.run_cli("analyze", self.source, "-o", output, "--format", "json")[0], 0)
        snapshot = (output / "report.json").read_bytes()
        self.assertEqual(self.run_cli("analyze", self.source, "-o", output)[0], 2)
        self.assertEqual((output / "report.json").read_bytes(), snapshot)
        self.assertFalse((output / "report.html").exists())

    def test_baseline_and_diff_roundtrip(self):
        first, second = self.root / "first", self.root / "second"
        self.assertEqual(self.run_cli("analyze", self.source, "-o", first)[0], 0)
        (self.source / "scan.txt").write_text("Nmap scan report for 192.0.2.7\n22/tcp open ssh Example 2.0\n", encoding="utf-8")
        self.assertEqual(self.run_cli("analyze", self.source, "-o", second, "--baseline", first / "report.json")[0], 0)
        result = json.loads((second / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(len(result["diff"]["added_services"]), 1)
        self.assertEqual(len(result["diff"]["removed_services"]), 2)
        code, out, err = self.run_cli("diff", first / "report.json", second / "report.json")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), result["diff"])

    def test_zip_equals_directory_observations(self):
        archive = self.root / "evidence.zip"
        with zipfile.ZipFile(archive, "w") as stream:
            stream.write(self.source / "scan.txt", "scan.txt")
        first, second = self.root / "first", self.root / "second"
        self.assertEqual(self.run_cli("analyze", self.source, "-o", first)[0], 0)
        self.assertEqual(self.run_cli("analyze", archive, "-o", second)[0], 0)
        reports = [json.loads((p / "report.json").read_text(encoding="utf-8")) for p in (first, second)]
        self.assertEqual(reports[0]["observations"], reports[1]["observations"])

    def test_init_validates_scope_and_preserves_existing_work(self):
        output = self.root / "workspace"
        self.assertEqual(self.run_cli("init", output, "--name", "Example", "--target", "192.0.2.7")[0], 0)
        self.assertTrue((output / "evidence").is_dir())
        self.assertEqual(self.run_cli("init", output, "--name", "Changed")[0], 2)
        self.assertIn("Example", (output / "notes.md").read_text())
        self.assertEqual(self.run_cli("init", self.root / "invalid", "--name", "Bad", "--target", "https://example.test")[0], 2)

    def test_empty_input_fails_but_preserves_coverage_report(self):
        empty = self.root / "empty"
        empty.mkdir()
        output = self.root / "report"
        self.assertEqual(self.run_cli("analyze", empty, "-o", output)[0], 2)
        self.assertTrue((output / "report.json").is_file())

    def test_invalid_scope_baseline_and_missing_input(self):
        bad = self.root / "invalid.json"
        bad.write_text('{"include": 3}', encoding="utf-8")
        output = self.root / "report"
        self.assertEqual(self.run_cli("analyze", self.source, "-o", output, "--scope", bad)[0], 2)
        bad.write_text('{"schema_version": 9}', encoding="utf-8")
        self.assertEqual(self.run_cli("analyze", self.source, "-o", output, "--baseline", bad)[0], 2)
        self.assertFalse(output.exists())
        self.assertEqual(self.run_cli("analyze", self.root / "missing", "-o", output)[0], 2)

    def test_service_errors_and_interruptions_keep_public_exit_codes(self):
        for error, expected, message in ((OSError("write failed"), 2, "write failed"),
                                         (ValueError("invalid report"), 2, "invalid report"),
                                         (KeyboardInterrupt(), 130, "interrupted")):
            with self.subTest(expected=expected, message=message), \
                    patch("scopelens.cli.run_analysis", side_effect=error):
                code, _, err = self.run_cli("analyze", self.source, "-o", self.root / "report")
            self.assertEqual(code, expected)
            self.assertIn(message, err)


if __name__ == "__main__":
    unittest.main()
