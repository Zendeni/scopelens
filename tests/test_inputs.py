"""Regression coverage for importing untrusted local artifacts without side effects."""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

from scopelens.inputs import Limits, load_input


class InputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return path

    def archive(self, members, name="input.zip", compression=zipfile.ZIP_STORED):
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=compression) as archive:
            for member, contents in members:
                archive.writestr(member, contents)
        return path

    def test_hash_tracks_original_bytes_and_utf8_bom_is_decoded(self):
        raw = b"\xef\xbb\xbfhttps://portal.example.test/\n"
        path = self.write("httpx.txt", raw)
        docs, coverage, warnings = load_input(path)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0].text, "https://portal.example.test/\n")
        self.assertEqual(docs[0].sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(docs[0].size, len(raw))
        self.assertEqual(coverage[0]["status"], "loaded")
        self.assertFalse(warnings)
        self.assertEqual(path.read_bytes(), raw)

    def test_oversized_file_is_skipped_without_partial_content(self):
        path = self.write("large.txt", "123456789")
        docs, coverage, warnings = load_input(path, Limits(max_file_bytes=8))
        self.assertEqual(docs, [])
        self.assertEqual(coverage[0]["status"], "skipped")
        self.assertIn("no partial parsing", coverage[0]["reason"])
        self.assertTrue(warnings)

    def test_total_budget_does_not_load_a_partial_second_file(self):
        self.write("a.txt", "123456")
        self.write("b.txt", "abcdef")
        docs, coverage, warnings = load_input(self.root, Limits(max_total_bytes=10))
        self.assertEqual([doc.path for doc in docs], ["a.txt"])
        self.assertEqual(docs[0].text, "123456")
        self.assertIn("total input byte limit", coverage[1]["reason"])
        self.assertTrue(warnings)

    def test_directory_entry_limit_reports_incomplete_coverage(self):
        for name in ("a.txt", "b.txt", "c.txt"):
            self.write(name, name)
        docs, _, warnings = load_input(self.root, Limits(max_files=2))
        self.assertEqual(len(docs), 2)
        self.assertIn("entry_limit", {item["code"] for item in warnings})

    def test_empty_binary_and_non_utf8_are_distinguished(self):
        self.write("empty.txt", b"")
        self.write("binary.txt", b"abc\x00def")
        self.write("legacy.txt", b"caf\xe9")
        docs, coverage, warnings = load_input(self.root)
        by_name = {row["path"]: row for row in coverage}
        self.assertEqual(by_name["empty.txt"]["status"], "empty")
        self.assertIn("binary", by_name["binary.txt"]["reason"])
        self.assertEqual([doc.path for doc in docs], ["legacy.txt"])
        self.assertIn("\ufffd", docs[0].text)
        self.assertIn("encoding_replaced", {item["code"] for item in warnings})

    def test_generated_reports_and_notes_are_excluded(self):
        self.write("scans/services.txt", "usable scanner artifact")
        for name in ("report.json", "report.md", "recon-analysis.md", "notes.md",
                     "reports/scan.txt", "scopelens-report/copy.txt", "node_modules/pkg/data.json"):
            self.write(name, "generated or unrelated content")
        docs, coverage, _ = load_input(self.root)
        self.assertEqual([doc.path for doc in docs], ["scans/services.txt"])
        self.assertEqual(next(row for row in coverage if row["path"] == "report.json")["status"], "skipped")
        self.assertTrue(any(row["path"] == "reports/" for row in coverage))

    def test_custom_output_directory_is_pruned(self):
        self.write("scans/original.txt", "original evidence")
        output = self.root / "review-output"
        self.write("review-output/copied-evidence.txt", "generated evidence")
        docs, _, _ = load_input(self.root, exclude=output)
        self.assertEqual([doc.path for doc in docs], ["scans/original.txt"])

    def test_zip_is_read_without_extraction_or_filesystem_writes(self):
        path = self.archive([("wrapped/scans/services.txt", "recorded evidence"),
                             ("wrapped/.target.env", 'IP="192.0.2.10"\n')])
        before = {p.relative_to(self.root).as_posix() for p in self.root.rglob("*")}
        with mock.patch.object(zipfile.ZipFile, "extract", side_effect=AssertionError("extraction forbidden")), \
                mock.patch.object(zipfile.ZipFile, "extractall", side_effect=AssertionError("extraction forbidden")):
            docs, _, warnings = load_input(path)
        self.assertEqual({doc.path for doc in docs}, {"wrapped/scans/services.txt", "wrapped/.target.env"})
        self.assertFalse(warnings)
        self.assertEqual(before, {p.relative_to(self.root).as_posix() for p in self.root.rglob("*")})

    def test_zip_unsafe_member_paths_are_rejected(self):
        for index, name in enumerate(("../outside.txt", "/absolute.txt", "C:/drive.txt",
                                      "nested/../../outside.txt", "nested\\..\\..\\outside.txt", "bad\nname.txt")):
            with self.subTest(member=name):
                path = self.archive([(name, "synthetic content")], name=f"unsafe-{index}.zip")
                with self.assertRaisesRegex(ValueError, "unsafe member"):
                    load_input(path)
        self.assertFalse((self.root / "outside.txt").exists())

    def test_zip_case_ambiguous_members_are_rejected(self):
        path = self.archive([("scans/Result.txt", "first"), ("scans/result.txt", "second")])
        with self.assertRaisesRegex(ValueError, "duplicate or ambiguous"):
            load_input(path)

    def test_zip_links_and_special_files_are_skipped(self):
        symlink = zipfile.ZipInfo("link.txt")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        fifo = zipfile.ZipInfo("pipe.txt")
        fifo.create_system = 3
        fifo.external_attr = (stat.S_IFIFO | 0o600) << 16
        path = self.archive([(symlink, "elsewhere.txt"), (fifo, ""), ("regular.txt", "usable")])
        docs, coverage, warnings = load_input(path)
        self.assertEqual([doc.path for doc in docs], ["regular.txt"])
        self.assertEqual(sum(row["status"] == "skipped" for row in coverage), 2)
        self.assertEqual(len(warnings), 2)

    def test_zip_compression_ratio_is_checked_before_member_read(self):
        path = self.archive([("compressed.txt", "A" * 4096)], compression=zipfile.ZIP_DEFLATED)
        with mock.patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("member must not be opened")):
            docs, coverage, warnings = load_input(path, Limits(max_ratio=2))
        self.assertFalse(docs)
        self.assertIn("compression ratio", coverage[0]["reason"])
        self.assertTrue(warnings)

    def test_zip_entry_limit_applies_before_import(self):
        path = self.archive([("a.txt", "a"), ("b.txt", "b"), ("c.txt", "c")])
        with self.assertRaisesRegex(ValueError, "more than 2 entries"):
            load_input(path, Limits(max_files=2))

    def test_invalid_zip_fails_with_readable_error(self):
        path = self.write("broken.zip", b"this is not a zip")
        with self.assertRaisesRegex(ValueError, "Invalid or damaged ZIP"):
            load_input(path)

    def test_local_symlink_is_not_followed(self):
        target = self.write("real/evidence.txt", "private target content")
        directory = self.root / "workspace"
        directory.mkdir()
        link = directory / "linked.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Creating symlinks is unavailable for this user")
        docs, coverage, _ = load_input(directory)
        self.assertFalse(docs)
        self.assertIn("links", coverage[0]["reason"])
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            load_input(link)

    def test_missing_input_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "does not exist"):
            load_input(self.root / "missing")


if __name__ == "__main__":
    unittest.main()
