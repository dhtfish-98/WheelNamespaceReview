"""Focused structure/policy/adversarial tests, with inert generated wheel bytes."""

import base64
import csv
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from wheel_namespace_review import Limits, review_wheel
from wheel_namespace_review.cli import main

DIST = "sample_pkg-1.0.dist-info"
WHEEL = b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
METADATA = b"Metadata-Version: 2.4\nName: sample-pkg\nVersion: 1.0\n\n"


def wheel_bytes(payload=None, *, omit=(), ghosts=(), duplicates=(), record_raw=None,
                wheel=WHEEL, metadata=METADATA, compression=zipfile.ZIP_STORED, extra_members=()):
    entries = dict({"sample_pkg/__init__.py": b"# inert sample\n"} if payload is None else payload)
    if wheel is not None:
        entries[f"{DIST}/WHEEL"] = wheel
    if metadata is not None:
        entries[f"{DIST}/METADATA"] = metadata
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    for name, data in entries.items():
        if name not in omit:
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            writer.writerow([name, "sha256=" + digest, str(len(data))])
    for name in ghosts:
        writer.writerow([name, "sha256=" + "A" * 43, "0"])
    for name in duplicates:
        data = entries[name]
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([name, "sha256=" + digest, str(len(data))])
    writer.writerow([f"{DIST}/RECORD", "", ""])
    entries[f"{DIST}/RECORD"] = out.getvalue().encode() if record_raw is None else record_raw
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=compression) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        for name, data in extra_members:
            zf.writestr(name, data)
    return target.getvalue()


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "sample_pkg-1.0-py3-none-any.whl"

    def check(self, data=None, **kwargs):
        self.path.write_bytes(wheel_bytes() if data is None else data)
        before = self.path.read_bytes()
        result = review_wheel(self.path, **kwargs)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertLessEqual(len(json.dumps(result).encode()), (kwargs.get("limits") or Limits()).report_bytes)
        return result

    def codes(self, result):
        return {f["code"] for f in result["findings"]}

    def expect(self, code, data, status="FAIL", **kwargs):
        result = self.check(data, **kwargs)
        self.assertEqual(result["status"], status, result)
        self.assertIn(code, self.codes(result), result)
        return result

    def test_valid_package_and_identity(self):
        result = self.check()
        self.assertEqual(result["status"], "PASS", result)
        self.assertTrue(result["complete"])
        self.assertEqual(result["input_sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertFalse(result["record_content_hashes_verified"])

    def test_valid_deflate(self):
        self.assertEqual(self.check(wheel_bytes(compression=zipfile.ZIP_DEFLATED))["status"], "PASS")

    def test_namespace_is_valid_without_init(self):
        result = self.check(wheel_bytes({"acme/component.py": b"# namespace\n"}))
        self.assertEqual(result["status"], "PASS", result)
        self.assertIn({"name": "acme", "root": ".", "kind": "implicit_namespace"}, result["namespaces"])

    def test_data_only_is_valid(self):
        self.assertEqual(self.check(wheel_bytes({"sample_pkg-1.0.data/data/readme.txt": b"data"}))["status"], "PASS")

    def test_record_omission(self):
        self.expect("record_omission", wheel_bytes(omit=["sample_pkg/__init__.py"]))

    def test_record_ghost(self):
        self.expect("record_ghost", wheel_bytes(ghosts=["ghost.py"]))

    def test_record_duplicate(self):
        self.expect("record_duplicate", wheel_bytes(duplicates=["sample_pkg/__init__.py"]))

    def test_zip_duplicate(self):
        with self.assertWarns(UserWarning):
            data = wheel_bytes(extra_members=[("sample_pkg/__init__.py", b"# other bytes\n")])
        self.expect("zip_duplicate", data)

    def test_multiple_dist_info(self):
        result = self.expect("dist_info_count", wheel_bytes({"other-1.0.dist-info/WHEEL": b"inert"}))
        self.assertFalse(result["complete"])

    def test_unsafe_paths(self):
        for path in ("../outside.py", "/outside.py", "C:/outside.py", "pkg\\outside.py", "a//x.py", "pkg/./x.py", "pkg/NUL.py", "pkg/name. /x.py", "pkg/a\x01.py"):
            with self.subTest(path=path):
                self.expect("unsafe_path", wheel_bytes({path: b"inert"}))

    def test_nul_member_is_rejected(self):
        data = bytearray(wheel_bytes({"sample_pkg/x.py": b"x"}))
        # Preserve filename lengths, inject NUL into both local and central names.
        needle = b"sample_pkg/x.py"
        data[:] = data.replace(needle, b"sample_pkg/\x00.py")
        self.expect("nul_member", bytes(data))

    def test_casefold_and_unicode_aliases(self):
        for payload in ({"pkg/X.py": b"a", "pkg/x.py": b"b"}, {"caf\u00e9/a.py": b"a", "cafe\u0301/a.py": b"b"}):
            self.expect("portable_collision", wheel_bytes(payload))

    def test_archive_parent_is_file(self):
        self.expect("archive_prefix_collision", wheel_bytes({"pkg": b"file", "pkg/a.py": b"a"}))

    def test_installation_mapping_collision(self):
        self.expect("installation_collision", wheel_bytes({"pkg/a.py": b"a", "sample_pkg-1.0.data/purelib/pkg/a.py": b"b"}))

    def test_installation_prefix_collision(self):
        self.expect("installation_prefix_collision", wheel_bytes({"pkg": b"file", "sample_pkg-1.0.data/platlib/pkg/a.py": b"a"}))

    def test_data_scheme_and_script_layout(self):
        self.expect("data_layout", wheel_bytes({"sample_pkg-1.0.data/unknown/a.py": b"a"}))
        self.expect("script_layout", wheel_bytes({"sample_pkg-1.0.data/scripts/nested/a": b"a"}))

    def test_purelib_and_platlib_are_both_mapped(self):
        result = self.check(wheel_bytes({"sample_pkg-1.0.data/purelib/acme/a.py": b"a", "sample_pkg-1.0.data/platlib/acme/b.py": b"b"}))
        self.assertEqual(result["status"], "PASS", result)

    def test_stdlib_overlap_at_root_and_mapped_root(self):
        for path in ("json.py", "json/__init__.py", "sample_pkg-1.0.data/platlib/json.py", "sitecustomize.py", "usercustomize.py"):
            self.expect("stdlib_overlap", wheel_bytes({path: b"# never executed\n"}))

    def test_pth_execution_exact_site_prefix(self):
        for content in (b"import os\n", b"import\tos\n", b"# comment\r\nimport os\r\n"):
            result = self.expect("pth_execution", wheel_bytes({"entry.pth": content}))
            self.assertTrue(any(":line" in f["location"] for f in result["findings"]))

    def test_pth_non_execution_lines(self):
        payload = {"entry.pth": b"# comment\n.\nvendor\n", "vendor/pkg.py": b"# text"}
        result = self.check(wheel_bytes(payload))
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["counts"]["pth_import_roots"], 1)
        # Leading whitespace is not executed by site; target is unknown instead.
        self.expect("pth_external_path", wheel_bytes({"entry.pth": b" import os\n"}), status="OPEN")

    def test_pth_promotes_nested_stdlib_name(self):
        self.expect("stdlib_overlap", wheel_bytes({"entry.pth": b"vendor\n", "vendor/json.py": b"# text"}))

    def test_pth_invalid_path_and_encoding(self):
        self.expect("unsafe_path", wheel_bytes({"entry.pth": b"../../other\n"}))
        self.expect("pth_encoding", wheel_bytes({"entry.pth": b"\xff\n"}), status="OPEN")

    def test_nested_pth_is_not_startup_processed(self):
        result = self.check(wheel_bytes({"pkg/data.pth": b"import os\n"}))
        self.assertEqual(result["status"], "PASS", result)
        self.assertNotIn("pth_execution", self.codes(result))

    def test_common_name_requires_decision(self):
        data = wheel_bytes({"tests/a.py": b"# test"})
        self.expect("common_top_level", data, status="OPEN")
        self.assertEqual(self.check(data, allow_common_names=["tests"])["status"], "PASS")
        self.expect("stdlib_overlap", wheel_bytes({"json.py": b"# text"}), allow_common_names=["json"])

    def test_module_package_conflict(self):
        self.expect("module_package_collision", wheel_bytes({"pkg.py": b"a", "pkg/__init__.py": b"b"}))

    def test_invalid_module_and_root_init(self):
        self.expect("module_path", wheel_bytes({"invalid-name/a.py": b"a"}))
        self.expect("root_init", wheel_bytes({"__init__.py": b"a"}))

    def test_bytecode_and_native_scope(self):
        self.expect("bytecode", wheel_bytes({"pkg/a.pyc": b"not compiled"}))
        self.expect("native_module", wheel_bytes({"module.abi3.so": b"not native"}), status="OPEN")

    def test_missing_metadata_and_bad_identity(self):
        self.expect("required_metadata", wheel_bytes(wheel=None))
        self.expect("metadata_identity", wheel_bytes(metadata=METADATA.replace(b"sample-pkg", b"other")))

    def test_duplicate_header_and_future_metadata(self):
        self.expect("metadata_field", wheel_bytes(wheel=WHEEL.replace(b"Root-Is-Purelib:", b"Root-Is-Purelib: true\nRoot-Is-Purelib:")))
        self.expect("wheel_version", wheel_bytes(wheel=WHEEL.replace(b"1.0", b"2.0")), status="OPEN")
        self.expect("metadata_version", wheel_bytes(metadata=METADATA.replace(b"2.4", b"9.9")), status="OPEN")

    def test_wheel_tag_and_build_binding(self):
        self.expect("wheel_tag", wheel_bytes(wheel=WHEEL.replace(b"py3-none-any", b"py2-none-any")))
        self.expect("wheel_tag", wheel_bytes(wheel=WHEEL.replace(b"py3-none-any", b"bad-tag")))
        self.expect("wheel_build", wheel_bytes(wheel=WHEEL.replace(b"\n\n", b"\nBuild: 1\n\n")))

    def test_record_malformed_csv_and_fields(self):
        self.expect("record_decode", wheel_bytes(record_raw=b'"unterminated'), status="OPEN")
        self.expect("record_fields", wheel_bytes(record_raw=b"x,one\n"))
        self.expect("record_hash_field", wheel_bytes(record_raw=b"sample_pkg/__init__.py,md5=bad,14\n"))
        self.expect("record_size", wheel_bytes(record_raw=b"sample_pkg/__init__.py,sha256=" + b"A" * 43 + b",999\n"))

    def test_record_payload_hash_is_explicitly_unverified(self):
        original = wheel_bytes()
        with zipfile.ZipFile(io.BytesIO(original)) as zf:
            record = zf.read(f"{DIST}/RECORD")
        lines = record.splitlines()
        fields = lines[0].split(b",")
        fields[1] = b"sha256=" + b"A" * 43
        lines[0] = b",".join(fields)
        result = self.check(wheel_bytes(record_raw=b"\n".join(lines) + b"\n"))
        self.assertEqual(result["status"], "PASS", result)
        self.assertFalse(result["record_content_hashes_verified"])

    def test_unknown_nested_archive(self):
        self.expect("nested_archive", wheel_bytes({"pkg/data.zip": b"PK\x05\x06"}), status="OPEN")

    def test_corrupt_member_crc(self):
        data = bytearray(wheel_bytes())
        payload_pos = data.find(b"# inert sample\n")
        data[payload_pos] = ord("!")
        self.expect("crc_mismatch", bytes(data))

    def test_truncated_and_nonzip_input(self):
        for data in (b"", b"not zip", wheel_bytes()[:-5]):
            self.expect("zip_structure", data, status="OPEN")

    def test_zip64_and_count_mismatch(self):
        data = bytearray(wheel_bytes())
        eocd = data.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", data, eocd + 8, 65535, 65535)
        self.expect("zip64", bytes(data), status="OPEN")
        data = bytearray(wheel_bytes())
        struct.pack_into("<HH", data, data.rfind(b"PK\x05\x06") + 8, 1, 1)
        self.expect("zip_structure", bytes(data), status="OPEN")

    def test_local_filename_mismatch(self):
        data = bytearray(wheel_bytes())
        data[30] = ord("z")
        self.expect("input_error", bytes(data), status="OPEN")

    def test_declared_size_does_not_truncate_decode(self):
        data = bytearray(wheel_bytes(compression=zipfile.ZIP_DEFLATED))
        # Forge first member's declared size in both headers. Raw bounded decode
        # detects real expansion even though ZipExtFile could truncate it.
        central = data.find(b"PK\x01\x02")
        struct.pack_into("<L", data, 22, 0)
        struct.pack_into("<L", data, central + 24, 0)
        self.expect("member_limit", bytes(data), status="OPEN")

    def test_symlink_mode(self):
        data = bytearray(wheel_bytes())
        central = data.find(b"PK\x01\x02")
        struct.pack_into("<L", data, central + 38, (stat.S_IFLNK | 0o777) << 16)
        self.expect("member_type", bytes(data))

    def test_budgets(self):
        samples = [
            ("archive_limit", replace(Limits(), archive_bytes=100), wheel_bytes()),
            ("central_limit", replace(Limits(), entries=1), wheel_bytes()),
            ("member_limit", replace(Limits(), member_bytes=10), wheel_bytes()),
            ("total_limit", replace(Limits(), total_bytes=50), wheel_bytes()),
            ("text_limit", replace(Limits(), text_bytes=10), wheel_bytes()),
            ("path_limit", replace(Limits(), path_depth=2), wheel_bytes({"a/b/c.py": b"a"})),
            ("member_limit", Limits(), wheel_bytes({"a.py": b"x" * 100000}, compression=zipfile.ZIP_DEFLATED)),
            ("namespace_limit", replace(Limits(), namespaces=1), wheel_bytes({"a.py": b"a", "b.py": b"b"})),
        ]
        for code, limits, data in samples:
            with self.subTest(code=code):
                self.expect(code, data, status="OPEN", limits=limits)

    def test_finding_limit_preserves_unknown(self):
        result = self.expect("finding_limit", wheel_bytes({"json.py": b"x", "os.py": b"x", "site.py": b"x"}), limits=replace(Limits(), findings=2))
        self.assertFalse(result["complete"])

    def test_report_limit_preserves_unknown(self):
        payload = {"a" * 190 + str(i) + ".py": b"x" for i in range(30)}
        result = self.check(wheel_bytes(payload), limits=replace(Limits(), report_bytes=4096))
        self.assertEqual(result["status"], "OPEN", result)
        self.assertIn("report_limit", self.codes(result))

    def test_directory_missing_file_and_invalid_filename(self):
        self.assertEqual(review_wheel(self.root / "missing-1.0-py3-none-any.whl")["status"], "OPEN")
        self.assertEqual(review_wheel(self.root)["status"], "OPEN")
        self.assertEqual(review_wheel(self.root / "file.zip")["status"], "OPEN")

    def test_invalid_limit_and_policy(self):
        for limits in (replace(Limits(), entries=0), replace(Limits(), entries=True), replace(Limits(), archive_bytes=Limits().archive_bytes + 1)):
            with self.assertRaises(ValueError):
                review_wheel(self.path, limits=limits)
        with self.assertRaises(ValueError):
            review_wheel(self.path, allow_common_names=["bad-name"])

    def test_no_network_execution_extract_or_import_of_inputs(self):
        sentinel = self.root / "executed"
        payload = {"sample_pkg/__init__.py": f"open({str(sentinel)!r}, 'w').write('executed')\n".encode(), "entry.pth": b"import sample_pkg\n"}
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")), \
             mock.patch.object(zipfile.ZipFile, "extract", side_effect=AssertionError("extract")), \
             mock.patch.object(zipfile.ZipFile, "extractall", side_effect=AssertionError("extractall")):
            self.expect("pth_execution", wheel_bytes(payload))
        self.assertFalse(sentinel.exists())
        self.assertNotIn("sample_pkg", sys.modules)

    def test_cli_exit_codes(self):
        for data, expected in [(wheel_bytes(), 0), (wheel_bytes({"json.py": b"# text"}), 1), (b"broken", 2)]:
            self.path.write_bytes(data)
            with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(main([str(self.path)]), expected)
                self.assertIn(json.loads(output.getvalue())["status"], {"PASS", "FAIL", "OPEN"})

    def test_data_descriptor_streaming_zip(self):
        class Unseekable(io.BytesIO):
            def seek(self, *args):
                raise io.UnsupportedOperation
        out = Unseekable()
        original = wheel_bytes(compression=zipfile.ZIP_DEFLATED)
        with zipfile.ZipFile(io.BytesIO(original)) as source, zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as dest:
            for name in source.namelist():
                dest.writestr(name, source.read(name))
        data = out.getvalue()
        self.assertEqual(self.check(data)["status"], "PASS")
        broken = bytearray(data)
        descriptor = broken.find(b"PK\x07\x08")
        broken[descriptor + 4] ^= 1
        self.expect("data_descriptor_mismatch", bytes(broken))

    def test_compression_encryption_and_unknown_flags(self):
        self.expect("compression", wheel_bytes(compression=zipfile.ZIP_BZIP2), status="OPEN")
        for flags, code in ((1, "encrypted_member"), (32, "zip_flags")):
            data = bytearray(wheel_bytes())
            struct.pack_into("<H", data, 6, flags)
            struct.pack_into("<H", data, data.find(b"PK\x01\x02") + 8, flags)
            self.expect(code, bytes(data), status="OPEN")

    def test_empty_explicit_data_directories(self):
        for name, code in (("sample_pkg-1.0.data/unknown/", "data_layout"), ("sample_pkg-1.0.data/scripts/nested/", "script_layout")):
            self.expect(code, wheel_bytes(extra_members=[(name, b"")]))

    def test_metadata_mime_body_is_not_recursively_parsed(self):
        unusual = WHEEL.replace(b"\n\n", b"\nContent-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: multipart/mixed; boundary=y\n\n--y--\n--x--\n")
        self.expect("wheel_body", wheel_bytes(wheel=unusual))

    def test_report_bound_with_unicode_and_large_policy(self):
        # A large policy is explicit input but must not escape the report limit.
        names = ["\u4e00" * 100 + str(i) for i in range(100)]
        result = self.check(limits=replace(Limits(), report_bytes=4096), allow_common_names=names)
        self.assertEqual(result["status"], "OPEN")
        self.assertEqual(result["allowed_common_name_summary"]["count"], 100)

    def test_filename_tag_cartesian_bound_before_parser(self):
        tags = ".".join("p" + str(i) for i in range(9))
        name = self.root / (f"sample_pkg-1.0-{tags}-{tags}-{tags}.whl")
        with mock.patch("wheel_namespace_review.review.parse_wheel_filename", side_effect=AssertionError("must preflight first")):
            result = review_wheel(name)
        self.assertEqual(result["status"], "OPEN")
        self.assertIn("tag_limit", self.codes(result))

    def test_symlink_and_fifo_inputs_are_not_read(self):
        if not hasattr(__import__("os"), "mkfifo"):
            self.skipTest("POSIX-specific input-type probes")
        import os
        target = self.root / "plain"
        target.write_bytes(wheel_bytes())
        self.path.symlink_to(target)
        if hasattr(os, "O_NOFOLLOW"):
            self.assertEqual(review_wheel(self.path)["status"], "OPEN")
        self.path.unlink()
        os.mkfifo(self.path)
        self.assertEqual(review_wheel(self.path)["status"], "OPEN")


if __name__ == "__main__":
    unittest.main()
