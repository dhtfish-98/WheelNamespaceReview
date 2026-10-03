"""OS capability regressions for the existing explicit local-file contract."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from wheel_namespace_review.review import snapshot
import wheel_namespace_review.review as reader
from wheel_namespace_review.review import StopReview
from wheel_namespace_review.review import Review, Limits
from wheel_namespace_review.cli import main


class ReaderCapabilities(unittest.TestCase):
    def invoke(self, path):
        return snapshot(path, Review(path.name, Limits()))

    def test_missing_none_zero_bool_and_noninteger_flags_fail_before_open(self):
        for flag in ('O_NOFOLLOW', 'O_NONBLOCK'):
            for value in (None, 0, True, False, -1, "flag"):
                with self.subTest(flag=flag, value=value):
                    with patch.object(reader.os, "open") as opened:
                        with patch.object(reader.os, "supports_dir_fd", {opened}):
                            with patch.object(reader.os, flag, value):
                                with self.assertRaises(StopReview):
                                    self.invoke(Path("synthetic-1.0-py3-none-any.whl"))
                        opened.assert_not_called()
            with patch.object(reader.os, flag, create=True):
                delattr(reader.os, flag)
                with self.assertRaises(StopReview):
                    self.invoke(Path("synthetic-1.0-py3-none-any.whl"))

    def test_directory_relative_capability_boundary(self):
        # This snapshot opens only the explicit leaf, with no dir_fd call.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "synthetic-1.0-py3-none-any.whl"
            path.write_bytes(b"synthetic")
            with patch.object(reader.os, "supports_dir_fd", None):
                self.assertEqual(self.invoke(path), b"synthetic")

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor contract")
    def test_valid_regular_symlink_and_fifo_nonblocking_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "synthetic-1.0-py3-none-any.whl"
            path.write_bytes(b"synthetic")
            self.assertEqual(self.invoke(path), b"synthetic")
            link = root / "leaf-1.0-py3-none-any.whl"
            link.symlink_to(path)
            pipe = root / "pipe-1.0-py3-none-any.whl"
            os.mkfifo(pipe)
            for target in (link, pipe):
                with self.assertRaises((StopReview, OSError)):
                    self.invoke(target)

    def test_cli_missing_capability_preserves_open_json(self):
        path = Path("synthetic-1.0-py3-none-any.whl")
        output = io.StringIO()
        with patch.object(reader.os, "O_NOFOLLOW", 0), contextlib.redirect_stdout(output):
            status = main([str(path)])
        self.assertEqual(status, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "OPEN")
        self.assertFalse(result.get("complete", False))
