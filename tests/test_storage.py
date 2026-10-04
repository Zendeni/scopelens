from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scopelens.storage import publish_directory, read_json


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_json_reads_accept_bom_and_enforce_byte_bound(self):
        path = self.root / "scope.json"
        data = b'\xef\xbb\xbf{"include": []}'
        path.write_bytes(data)
        self.assertEqual(read_json(path, len(data)), {"include": []})
        with self.assertRaisesRegex(ValueError, "exceeds"):
            read_json(path, len(data) - 1)
        path.write_bytes(b"\xff")
        with self.assertRaisesRegex(ValueError, "Invalid JSON: scope.json"):
            read_json(path)

    def test_invalid_output_paths_fail_before_creating_parents(self):
        for name in ("../outside", "/absolute", "C:/absolute", "C:relative", "nested/../outside", "nested\\outside", "", "./report.json"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                publish_directory(self.root / "new" / "report", {name: "data"})
            self.assertFalse((self.root / "new").exists())

    def test_existing_directory_is_never_modified(self):
        output = self.root / "report"
        output.mkdir()
        sentinel = output / "notes.md"
        sentinel.write_text("original", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Output already exists"):
            publish_directory(output, {"notes.md": "replacement"})
        self.assertEqual(sentinel.read_text(), "original")
        self.assertEqual(list(self.root.glob(".scopelens-*")), [])

    def test_staging_failure_leaves_no_destination_or_temporary_directory(self):
        output = self.root / "report"
        with patch.object(Path, "write_text", side_effect=OSError("disk full")), \
                self.assertRaisesRegex(OSError, "disk full"):
            publish_directory(output, {"report.json": "{}"})
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".scopelens-*")), [])

    def test_racing_destination_creation_preserves_other_process_files(self):
        output = self.root / "report"
        original_mkdir = Path.mkdir

        def racing_mkdir(path, *args, **kwargs):
            if path == output:
                original_mkdir(path)
                (path / "notes.md").write_text("other process", encoding="utf-8")
            return original_mkdir(path, *args, **kwargs)

        with patch.object(Path, "mkdir", racing_mkdir), self.assertRaises(FileExistsError):
            publish_directory(output, {"report.json": "{}"})
        self.assertEqual((output / "notes.md").read_text(), "other process")
        self.assertFalse((output / "report.json").exists())
        self.assertEqual(list(self.root.glob(".scopelens-*")), [])

    def test_racing_file_creation_is_not_overwritten(self):
        output = self.root / "report"
        report = output / "report.json"
        original_open = Path.open

        def racing_open(path, mode="r", *args, **kwargs):
            if path == report and mode == "xb":
                with original_open(path, "w", encoding="utf-8") as stream:
                    stream.write("other process")
            return original_open(path, mode, *args, **kwargs)

        with patch.object(Path, "open", racing_open), self.assertRaises(FileExistsError):
            publish_directory(output, {"report.json": "{}"})
        self.assertEqual(report.read_text(), "other process")
        self.assertEqual(list(self.root.glob(".scopelens-*")), [])

    def test_cleanup_failure_does_not_mask_original_write_error(self):
        with patch.object(Path, "write_text", side_effect=OSError("original write error")), \
                patch("scopelens.storage.shutil.rmtree", side_effect=OSError("cleanup error")), \
                self.assertRaisesRegex(OSError, "original write error"):
            publish_directory(self.root / "report", {"report.json": "{}"})
        self.assertFalse((self.root / "report").exists())

    def test_parent_links_are_rejected_for_reads_and_publication(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "scope.json").write_text("{}", encoding="utf-8")
        linked = self.root / "linked"
        try:
            linked.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("Creating symlinks is not permitted on this host")
        with self.assertRaisesRegex(ValueError, "Links are not allowed"):
            read_json(linked / "scope.json")
        with self.assertRaisesRegex(ValueError, "Links are not allowed"):
            publish_directory(linked / "report", {"report.json": "{}"})
        self.assertFalse((outside / "report").exists())


if __name__ == "__main__":
    unittest.main()
