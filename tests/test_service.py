import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scopelens.service import AnalysisRequest, analysis_exit_code, run_analysis


class AnalysisServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "scan.txt"
        self.source.write_text("Nmap scan report for 192.0.2.7\n21/tcp open ftp Example 1.2\n", encoding="utf-8")

    def test_api_publishes_without_parsing_arguments_or_console_output(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                patch("argparse.ArgumentParser.parse_args", side_effect=AssertionError("API must not parse arguments")):
            result = run_analysis(AnalysisRequest(self.source, self.root / "report", format="json", fail_on="medium"))
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.paths, (result.output / "report.json",))
        self.assertEqual(json.loads(result.paths[0].read_text(encoding="utf-8")), result.report)

    def test_invalid_options_fail_before_creating_any_output(self):
        for options in ({"format": "csv"}, {"fail_on": "urgent"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                run_analysis(AnalysisRequest(self.source, self.root / "new" / "report", **options))
            self.assertFalse((self.root / "new").exists())

    def test_thresholds_and_empty_evidence_keep_their_outcome_precedence(self):
        report = {"observations": [{}], "findings": [{"severity": "medium"}]}
        for threshold, expected in ((None, 0), ("info", 1), ("low", 1), ("medium", 1), ("high", 0), ("critical", 0)):
            with self.subTest(threshold=threshold):
                self.assertEqual(analysis_exit_code(report, threshold), expected)
        report["observations"] = []
        self.assertEqual(analysis_exit_code(report, "low"), 2)

    def test_empty_evidence_still_publishes_coverage(self):
        self.source.write_text("", encoding="utf-8")
        result = run_analysis(AnalysisRequest(self.source, self.root / "report", format="json"))
        self.assertEqual(result.exit_code, 2)
        self.assertTrue(result.paths[0].is_file())
        self.assertEqual(result.report["summary"]["files_parsed"], 0)

    def test_render_failure_does_not_create_destination(self):
        with patch("scopelens.service.render_json", side_effect=ValueError("render failed")), \
                self.assertRaisesRegex(ValueError, "render failed"):
            run_analysis(AnalysisRequest(self.source, self.root / "new" / "report"))
        self.assertFalse((self.root / "new").exists())


if __name__ == "__main__":
    unittest.main()
