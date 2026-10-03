"""Independent inventory-first wheel review. Never import or extract members."""

from __future__ import annotations

import base64
import csv
from dataclasses import asdict, dataclass
from email import policy
from email.parser import BytesParser
import hashlib
import io
import itertools
import json
import keyword
import os
from pathlib import Path
import stat
import struct
import sys
import unicodedata
import zipfile
import zlib

from packaging.tags import parse_tag
from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

COMMON = frozenset({"app", "build", "data", "docs", "examples", "lib", "scripts", "src", "test", "tests"})
SCHEMES = frozenset({"purelib", "platlib", "scripts", "headers", "data"})
METADATA_VERSIONS = frozenset({"1.1", "1.2", "2.1", "2.2", "2.3", "2.4"})


@dataclass(frozen=True)
class Limits:
    archive_bytes: int = 32 * 1024 * 1024
    central_bytes: int = 4 * 1024 * 1024
    entries: int = 4000
    member_bytes: int = 16 * 1024 * 1024
    total_bytes: int = 128 * 1024 * 1024
    text_bytes: int = 1024 * 1024
    ratio: int = 100
    path_depth: int = 24
    path_chars: int = 1024
    findings: int = 200
    pth_roots: int = 128
    namespaces: int = 512
    report_bytes: int = 256 * 1024

    def validate(self) -> None:
        defaults = Limits()
        for key, value in asdict(self).items():
            if type(value) is not int or value < 1 or value > getattr(defaults, key):
                raise ValueError(f"limits must be positive integers no larger than default: {key}")
        if self.findings < 2 or self.report_bytes < 4096:
            raise ValueError("findings needs at least 2; report_bytes needs at least 4096")


class StopReview(Exception):
    pass


class Review:
    def __init__(self, name: str, limits: Limits):
        self.limits = limits
        self.result = {
            "schema": "wheel-namespace-review/1", "input_name": name[:200],
            "input_sha256": None, "status": "OPEN", "complete": True,
            "scope": "ZIP inventory, RECORD coverage, installation paths, namespace and .pth policy",
            "record_content_hashes_verified": False, "nested_archive_depth": 0,
            "failure_count": 0,
            "stdlib_policy": {"python": f"{sys.version_info.major}.{sys.version_info.minor}",
                              "platform": sys.platform, "source": "sys.stdlib_module_names plus startup hooks"},
            "limits": asdict(limits), "counts": {}, "namespaces": [], "findings": [],
        }

    def add(self, status: str, code: str, location: str, detail: str) -> None:
        if status == "OPEN":
            self.result["complete"] = False
        if status == "FAIL":
            self.result["failure_count"] += 1
        findings = self.result["findings"]
        finding = {"status": status, "code": code, "location": location[:300], "detail": detail[:500]}
        if len(findings) >= self.limits.findings - 1:
            # Reserve one slot for the incomplete-inventory marker without losing
            # the failure that triggered the cap. The counter survives omissions.
            if status == "FAIL":
                findings[-1] = finding
            findings.append({"status": "OPEN", "code": "finding_limit", "location": "report",
                             "detail": "Finding limit reached; remaining checks were not completed."})
            self.result["findings_truncated"] = True
            self.result["complete"] = False
            raise StopReview
        findings.append(finding)

    def stop(self, code: str, location: str, detail: str) -> None:
        self.add("OPEN", code, location, detail)
        raise StopReview

    def namespace(self, value: dict) -> None:
        if len(self.result["namespaces"]) >= self.limits.namespaces:
            self.stop("namespace_limit", "report/namespaces", "Namespace inventory limit reached; remaining checks were not completed.")
        self.result["namespaces"].append(value)

    def finish(self) -> dict:
        flags = {f["status"] for f in self.result["findings"]}
        self.result["status"] = "FAIL" if self.result["failure_count"] else ("OPEN" if "OPEN" in flags else "PASS")
        # Namespaces can be numerous even for a bounded archive. Never truncate silently.
        if len(json.dumps(self.result, ensure_ascii=True).encode()) > self.limits.report_bytes:
            self.result["namespaces"] = []
            first_failure = next((f for f in self.result["findings"] if f["status"] == "FAIL"), None)
            self.result["omitted_finding_count"] = len(self.result["findings"])
            self.result["findings"] = [{"status": "OPEN", "code": "report_limit", "location": "report",
                                       "detail": "Report exceeded byte limit; detailed inventory removed."}]
            if first_failure is not None:
                self.result["findings"].append({**first_failure, "location": first_failure["location"][:100],
                                                "detail": first_failure["detail"][:50]})
            names = self.result.pop("allowed_common_names", [])
            self.result["allowed_common_name_summary"] = {"count": len(names), "sha256": hashlib.sha256(json.dumps(names).encode()).hexdigest()}
            self.result["complete"] = False
            if self.result["status"] != "FAIL":
                self.result["status"] = "OPEN"
        return self.result


def path_ok(name: str, r: Review, location: str, directory: bool = False) -> bool:
    if len(name) > r.limits.path_chars or len(name.split("/")) > r.limits.path_depth:
        r.stop("path_limit", location, "Path exceeds length or nesting limit.")
    value = name[:-1] if directory and name.endswith("/") else name
    parts = value.split("/")
    bad = not value or any(p in {"", ".", ".."} for p in parts)
    bad |= any(ord(c) < 32 or ord(c) == 127 or c in '\\:<>"|?*' for c in value)
    # Portable policy rejects Windows devices and paths normalized differently by installers.
    devices = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10)),
               *(f"com{i}" for i in "¹²³"), *(f"lpt{i}" for i in "¹²³")}
    bad |= any(p.endswith((" ", ".")) or p.split(".")[0].casefold() in devices for p in parts)
    if bad:
        r.add("FAIL", "unsafe_path", location, "Path is absolute, traversing, ambiguous, control-bearing or unsafe on Windows.")
    return not bad


def key(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def snapshot(path: Path, r: Review) -> bytes:
    required = ('O_NOFOLLOW', 'O_NONBLOCK')
    if os.name != "posix" or any(type(getattr(os, flag, None)) is not int or getattr(os, flag) <= 0 for flag in required):
        r.stop("input_error", "input", "POSIX nonblocking/no-follow capabilities are unavailable.")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            r.stop("input_type", "input", "Input must be a regular file; directories, devices and pipes are unsupported.")
        if before.st_size > r.limits.archive_bytes:
            r.stop("archive_limit", "input", "Archive exceeds input byte limit.")
        data = stream.read(r.limits.archive_bytes + 1)
        after = os.fstat(stream.fileno())
        if len(data) > r.limits.archive_bytes:
            r.stop("archive_limit", "input", "Archive grew beyond input byte limit.")
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            r.stop("input_changed", "input", "Input changed during snapshot; no stable observation.")
    r.result["input_sha256"] = hashlib.sha256(data).hexdigest()
    return data


def central_preflight(data: bytes, r: Review) -> int:
    """Count actual central records before zipfile allocates its member list."""
    offset = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if offset < 0 or offset + 22 > len(data):
        r.stop("zip_structure", "ZIP/EOCD", "No complete ZIP end record.")
    _, disk, start_disk, disk_count, count, size, start, comment = struct.unpack_from("<4s4H2LH", data, offset)
    if offset + 22 + comment != len(data):
        r.stop("zip_structure", "ZIP/EOCD", "Trailing bytes or malformed end record comment.")
    if disk or start_disk or disk_count != count:
        r.stop("multidisk_zip", "ZIP/EOCD", "Multi-disk ZIP is unsupported.")
    if count == 65535 or size == 0xFFFFFFFF or start == 0xFFFFFFFF or data[max(0, offset - 20):offset].startswith(b"PK\x06\x07"):
        r.stop("zip64", "ZIP/EOCD", "ZIP64 is outside the supported archive profile.")
    if count > r.limits.entries or size > r.limits.central_bytes:
        r.stop("central_limit", "ZIP/EOCD", "Central-directory count or bytes exceed limit.")
    if start + size != offset or start > len(data):
        r.stop("zip_structure", "ZIP/central", "Central-directory offsets are inconsistent; prefixed ZIPs are unsupported.")
    pos, actual = start, 0
    while pos < offset:
        if pos + 46 > offset or data[pos:pos + 4] != b"PK\x01\x02":
            r.stop("zip_structure", f"ZIP/central@{pos}", "Malformed central-directory member.")
        fields = struct.unpack_from("<4s6H3L5H2L", data, pos)
        name_len, extra_len, comment_len, member_disk = fields[10:14]
        if member_disk or 0xFFFFFFFF in (fields[8], fields[9], fields[16]):
            r.stop("zip64", f"ZIP/central@{pos}", "ZIP64 or multi-disk member is unsupported.")
        end = pos + 46 + name_len + extra_len + comment_len
        if end > offset:
            r.stop("zip_structure", f"ZIP/central@{pos}", "Central record crosses its declared boundary.")
        actual += 1
        if actual > r.limits.entries:
            r.stop("central_limit", "ZIP/central", "Actual central record count exceeds limit.")
        pos = end
    if actual != count:
        r.stop("zip_structure", "ZIP/central", "Actual central record count differs from end record.")
    if actual == 0:
        r.stop("empty_zip", "ZIP/central", "Empty archive is not a wheel.")
    return start


def local_ranges(data: bytes, infos: list[zipfile.ZipInfo], central: int, r: Review) -> None:
    ranges = []
    for info in infos:
        off = info.header_offset
        if off < 0 or off + 30 > central or data[off:off + 4] != b"PK\x03\x04":
            r.stop("zip_structure", info.filename, "Local file header is missing or crosses central directory.")
        f = struct.unpack_from("<4s5H3L2H", data, off)
        end = off + 30 + f[9] + f[10] + info.compress_size
        if f[2] != info.flag_bits or f[3] != info.compress_type:
            r.add("FAIL", "local_header_mismatch", info.filename, "Local and central compression/flags differ.")
        if end > central:
            r.stop("zip_structure", info.filename, "Compressed member crosses central-directory boundary.")
        if f[2] & 8:
            pos = end + (4 if data[end:end + 4] == b"PK\x07\x08" else 0)
            if pos + 12 > central:
                r.stop("zip_structure", info.filename, "Truncated ZIP data descriptor.")
            if struct.unpack_from("<3L", data, pos) != (info.CRC, info.compress_size, info.file_size):
                r.add("FAIL", "data_descriptor_mismatch", info.filename, "Data descriptor differs from central CRC or sizes.")
            end = pos + 12
        elif (f[6], f[7], f[8]) != (info.CRC, info.compress_size, info.file_size):
            r.add("FAIL", "local_header_mismatch", info.filename, "Local and central CRC or sizes differ.")
        ranges.append((off, end, info.filename))
    cursor = 0
    for start, end, name in sorted(ranges):
        if start != cursor:
            r.add("FAIL", "unindexed_or_overlapping_bytes", name, "Local ranges overlap or leave bytes not described by central records.")
        cursor = max(cursor, end)
    if cursor != central:
        r.add("FAIL", "unindexed_bytes", "ZIP/local", "Local records do not end at central directory.")


def identity(root: str, suffix: str, distribution: str, version: Version, r: Review) -> None:
    try:
        name, ver = root[:-len(suffix)].rsplit("-", 1)
        same = canonicalize_name(name) == distribution and Version(ver.replace("_", "-")) == version
    except (ValueError, InvalidVersion):
        same = False
    if not same:
        r.add("FAIL", "distribution_identity", root, "Directory distribution/version do not match wheel filename.")


def read_members(zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo], r: Review) -> dict[str, bytes]:
    texts, total = {}, 0
    for info in infos:
        location = info.orig_filename
        if info.flag_bits & 1:
            r.stop("encrypted_member", location, "Encrypted ZIP members are unsupported.")
        if info.flag_bits & ~0x080E:
            r.stop("zip_flags", location, "ZIP flags outside UTF-8, data descriptor and deflate level hints are unsupported.")
        if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            r.stop("compression", location, "Only stored and deflated members are supported.")
        if info.file_size > r.limits.member_bytes or info.file_size > max(1, info.compress_size) * r.limits.ratio:
            r.stop("member_limit", location, "Member exceeds size or compression-ratio limit.")
        total += info.file_size
        if total > r.limits.total_bytes:
            r.stop("total_limit", location, "Declared total expansion exceeds limit.")
        save = info.filename.endswith(("/WHEEL", "/METADATA", "/RECORD", ".pth"))
        if save and info.file_size > r.limits.text_bytes:
            r.stop("text_limit", location, "Metadata or .pth text exceeds limit.")
        chunks, read, prefix, crc = [], 0, b"", 0
        # zipfile validates local name/extra fields and overlapping ranges on open.
        # Its read method trusts declared size and can truncate expansion, so decode
        # raw data independently with a bounded decompressor to detect understated sizes.
        with zf.open(info):
            pass
        archive = zf.fp.getbuffer()
        fields = struct.unpack_from("<4s5H3L2H", archive, info.header_offset)
        start = info.header_offset + 30 + fields[9] + fields[10]
        decoder = zlib.decompressobj(-15) if info.compress_type == zipfile.ZIP_DEFLATED else None

        def consume(chunk: bytes) -> None:
            nonlocal read, prefix, crc
            read += len(chunk)
            if read > info.file_size or read > r.limits.member_bytes:
                r.stop("member_limit", location, "Actual expansion exceeds declared size or limit.")
            crc = zlib.crc32(chunk, crc)
            if len(prefix) < 4:
                prefix += chunk[:4 - len(prefix)]
            if save:
                chunks.append(chunk)

        for pos in range(start, start + info.compress_size, 65536):
            compressed = bytes(archive[pos:min(pos + 65536, start + info.compress_size)])
            if decoder is None:
                consume(compressed)
            else:
                while compressed:
                    consume(decoder.decompress(compressed, 65536))
                    compressed = decoder.unconsumed_tail
                if decoder.unused_data:
                    r.add("FAIL", "deflate_trailing_data", location, "Compressed stream contains trailing data.")
        archive.release()
        if decoder is not None and not decoder.eof:
            r.add("FAIL", "deflate_truncated", location, "Deflate stream does not reach its end marker.")
        if read != info.file_size:
            r.add("FAIL", "member_size", location, "Actual expansion differs from central size.")
        if crc != info.CRC:
            r.add("FAIL", "crc_mismatch", location, "Actual expanded member CRC differs from ZIP CRC.")
        if not info.is_dir() and (prefix in {b"PK\x03\x04", b"PK\x05\x06"} or info.filename.lower().endswith((".zip", ".whl", ".tar", ".tar.gz", ".tgz"))):
            r.add("OPEN", "nested_archive", location, "Nested archive contents are not reviewed; recursion depth is zero.")
        if save:
            texts[info.filename] = b"".join(chunks)
    r.result["counts"]["expanded_bytes"] = total
    return texts


def headers(raw: bytes, location: str, required: tuple[str, ...], r: Review):
    try:
        raw.decode("utf-8")
        # Wheel headers are not MIME messages. Header-only mode avoids interpreting
        # attacker-controlled multipart bodies or recursively parsing MIME structures.
        message = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    except (UnicodeError, ValueError) as exc:
        r.stop("metadata_decode", location, f"Metadata is not supported UTF-8 header text: {type(exc).__name__}.")
    if message.defects or any(getattr(value, "defects", ()) for value in message.values()):
        r.add("FAIL", "metadata_syntax", location, "Metadata parser reported malformed headers.")
    for field in required:
        values = message.get_all(field, [])
        if len(values) != 1 or not str(values[0]).strip():
            r.add("FAIL", "metadata_field", f"{location}/{field}", "Required singleton header is missing, empty or duplicated.")
    return message


def check_metadata(texts: dict, files: dict, dist: str, distribution: str, version: Version, tags: frozenset, build: tuple, r: Review) -> None:
    for leaf in ("WHEEL", "METADATA", "RECORD"):
        if f"{dist}/{leaf}" not in files:
            r.add("FAIL", "required_metadata", f"{dist}/{leaf}", "Required wheel metadata file is missing.")
    wheel_path = f"{dist}/WHEEL"
    if wheel_path in texts:
        msg = headers(texts[wheel_path], wheel_path, ("Wheel-Version", "Root-Is-Purelib"), r)
        if msg.get("Wheel-Version") != "1.0":
            r.add("OPEN", "wheel_version", wheel_path, "Only Wheel-Version 1.0 is supported.")
        if str(msg.get("Root-Is-Purelib", "")).lower() not in {"true", "false"}:
            r.add("FAIL", "root_is_purelib", wheel_path, "Root-Is-Purelib must be true or false.")
        if msg.get_payload().strip():
            r.add("FAIL", "wheel_body", wheel_path, "Unexpected WHEEL message body.")
        declared = set()
        try:
            for value in msg.get_all("Tag", []):
                value = str(value)
                if len(value) > 512 or len(value.split("-")) != 3:
                    raise ValueError
                components = value.split("-")
                if any(not c or any(not part or not all(ch.isascii() and (ch.isalnum() or ch == "_") for ch in part) for part in c.split(".")) for c in components):
                    raise ValueError
                if len(list(itertools.islice(itertools.product(*(c.split(".") for c in components)), 501))) > 500:
                    raise ValueError
                declared.update(parse_tag(value))
                if len(declared) > 500:
                    raise ValueError
        except ValueError:
            r.add("FAIL", "wheel_tag", wheel_path, "Malformed or excessive compatibility tags.")
        if declared != set(tags):
            r.add("FAIL", "wheel_tag", wheel_path, "Expanded WHEEL tags differ from filename tags.")
        builds = msg.get_all("Build", [])
        expected_build = str(build[0]) + build[1] if build else None
        if builds != ([] if expected_build is None else [expected_build]):
            r.add("FAIL", "wheel_build", wheel_path, "Build header differs from filename build tag.")
    metadata_path = f"{dist}/METADATA"
    if metadata_path in texts:
        msg = headers(texts[metadata_path], metadata_path, ("Metadata-Version", "Name", "Version"), r)
        if msg.get("Metadata-Version") not in METADATA_VERSIONS:
            r.add("OPEN", "metadata_version", metadata_path, "Metadata version is outside supported versions (1.1, 1.2, 2.1-2.4).")
        try:
            matching = canonicalize_name(str(msg.get("Name", "")), validate=True) == distribution and Version(str(msg.get("Version", ""))) == version
        except (ValueError, InvalidVersion):
            matching = False
        if not matching:
            r.add("FAIL", "metadata_identity", metadata_path, "METADATA Name/Version differ from wheel filename.")


def check_record(raw: bytes, files: dict, dist: str, r: Review) -> None:
    location = f"{dist}/RECORD"
    try:
        stream = io.StringIO(raw.decode("utf-8"), newline="")
        reader = csv.reader(stream, strict=True)
        rows = {}
        for number, row in enumerate(reader, 1):
            where = f"{location}:row{number}"
            if number > r.limits.entries:
                r.stop("record_limit", where, "RECORD row limit exceeded.")
            if len(row) != 3:
                r.add("FAIL", "record_fields", where, "RECORD rows require exactly path, hash and size fields.")
                continue
            path, digest, size = row
            if not path_ok(path, r, where):
                continue
            if path in rows:
                r.add("FAIL", "record_duplicate", where, "Duplicate RECORD path.")
            rows[path] = number
            if path not in files:
                r.add("FAIL", "record_ghost", where, "RECORD path is not a real central-directory file.")
            if path == location:
                if digest or size:
                    r.add("FAIL", "record_self_fields", where, "RECORD's own hash and size must be empty.")
                continue
            if not size.isascii() or not size.isdecimal() or len(size) > 12:
                r.add("FAIL", "record_size", where, "RECORD size must be a bounded nonnegative decimal.")
            elif path in files and int(size) != files[path].file_size:
                r.add("FAIL", "record_size", where, "RECORD size differs from actual ZIP member size.")
            try:
                algorithm, encoded = digest.split("=", 1)
                expected = {"sha256": 32, "sha384": 48, "sha512": 64}[algorithm]
                if len(encoded) > 86 or not encoded or "=" in encoded or not all(c.isascii() and (c.isalnum() or c in "-_") for c in encoded):
                    raise ValueError
                binary = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
                if len(binary) != expected or base64.urlsafe_b64encode(binary).rstrip(b"=").decode() != encoded:
                    raise ValueError
            except (ValueError, KeyError):
                r.add("FAIL", "record_hash_field", where, "RECORD hash requires canonical unpadded SHA-256/384/512 base64 text; payload hashes are not verified.")
        exempt = {f"{dist}/RECORD.jws", f"{dist}/RECORD.p7s"}
        for path in sorted(files.keys() - rows.keys() - exempt):
            r.add("FAIL", "record_omission", path, "Real ZIP file is omitted from RECORD.")
        for path in sorted(files.keys() & exempt):
            r.add("OPEN", "legacy_signature", path, "Deprecated signature file is present; signature authenticity is not verified.")
            if path in rows:
                r.add("FAIL", "signature_record", path, "Legacy signature files must be absent from RECORD.")
        r.result["counts"]["record_rows"] = len(rows)
    except (UnicodeError, csv.Error):
        r.add("OPEN", "record_decode", location, "RECORD cannot be completely decoded as UTF-8 strict CSV.")


def mapped_path(name: str, dist: str, r: Review) -> tuple[str, str] | None:
    parts = name.split("/")
    if parts[0] == dist:
        return None
    if parts[0].endswith(".dist-info"):
        return None
    if parts[0].endswith(".data"):
        if parts[0] != dist[:-10] + ".data" or len(parts) < 3 or parts[1] not in SCHEMES:
            r.add("FAIL", "data_layout", name, ".data root or installation scheme is invalid.")
            return None
        scheme, relative = parts[1], "/".join(parts[2:])
        if scheme == "scripts" and len(parts) != 3:
            r.add("FAIL", "script_layout", name, ".data/scripts supports regular files immediately below scripts only.")
        return ("site-packages" if scheme in {"purelib", "platlib"} else scheme, relative)
    return "site-packages", name


def namespaces(installed: dict[str, str], root: str, allowed_common: frozenset[str], r: Review) -> None:
    modules, dirs = {}, set()
    prefix = root + "/" if root else ""
    native_init_dirs = {name.rsplit("/", 1)[0] for name in installed if "/" in name and name.rsplit("/", 1)[1].startswith("__init__.") and name.endswith((".so", ".pyd"))}
    for installed_name, original in installed.items():
        if not installed_name.startswith(prefix):
            continue
        relative = installed_name[len(prefix):]
        parts = relative.split("/")
        leaf = parts[-1]
        if leaf.endswith((".pyc", ".pyo")):
            r.add("FAIL", "bytecode", original, "Precompiled bytecode is outside source namespace review policy.")
            continue
        native = leaf.endswith((".so", ".pyd"))
        if not leaf.endswith(".py") and not native:
            continue
        stem = leaf.split(".")[0] if native else leaf[:-3]
        if native:
            r.add("OPEN", "native_module", original, "Native extension identified by filename; ABI, loader behavior and binary contents are not reviewed.")
        names = parts[:-1] + [stem]
        if any(not p.isidentifier() or keyword.iskeyword(p) for p in names):
            r.add("FAIL", "module_path", original, "Python module filename is not a valid import path.")
            continue
        if names == ["__init__"]:
            r.add("FAIL", "root_init", original, "__init__.py is at an import root.")
            continue
        logical = names[:-1] if stem == "__init__" else names
        if not logical:
            continue
        top = logical[0]
        kind = "package" if len(logical) > 1 or stem == "__init__" else "module"
        modules.setdefault(top, []).append((original, kind))
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))
    stdlib = sys.stdlib_module_names | {"sitecustomize", "usercustomize"}
    for top, evidence in sorted(modules.items()):
        if top in stdlib:
            r.add("FAIL", "stdlib_overlap", evidence[0][0], f"Potential standard-library/startup-name overlap: {top}. Actual shadowing depends on interpreter and sys.path.")
        if top in COMMON and top not in allowed_common:
            r.add("OPEN", "common_top_level", evidence[0][0], f"Generic import name {top} needs an explicit ownership decision (--allow-common-name).")
        kinds = {kind for _, kind in evidence}
        if kinds == {"package", "module"}:
            r.add("FAIL", "module_package_collision", evidence[0][0], f"Both module and package use top-level name {top}.")
        r.namespace({"name": top, "root": root or ".", "kind": "module" if kinds == {"module"} else "package_or_namespace"})
    for directory in sorted(dirs):
        init = prefix + directory + "/__init__.py"
        native_init = prefix + directory in native_init_dirs
        if init not in installed and not native_init:
            r.namespace({"name": directory.replace("/", "."), "root": root or ".", "kind": "implicit_namespace"})


def check_installation(files: dict, texts: dict, dist: str, allowed_common: frozenset[str], r: Review) -> None:
    destinations, installed = {}, {}
    for name in files:
        target = mapped_path(name, dist, r)
        if target is None:
            continue
        scheme, relative = target
        canonical = scheme + "/" + key(relative)
        if canonical in destinations:
            r.add("FAIL", "installation_collision", name, f"Installed destination collides with {destinations[canonical][:200]}.")
        destinations[canonical] = name
        if scheme == "site-packages":
            installed[relative] = name
    # File-versus-directory collisions after spreading .data into install paths.
    for canonical, name in destinations.items():
        pieces = canonical.split("/")
        for i in range(2, len(pieces)):
            if "/".join(pieces[:i]) in destinations:
                r.add("FAIL", "installation_prefix_collision", name, "A file occupies a parent installation directory.")
    roots = {""}
    for relative, original in installed.items():
        if not relative.endswith(".pth"):
            continue
        if "/" in relative:
            continue  # Only site-packages root .pth files are processed by site startup.
        try:
            text = texts[original].decode("utf-8")
        except UnicodeError:
            r.add("OPEN", "pth_encoding", original, "Non-UTF-8 .pth needs interpreter/locale-specific analysis; no fallback guessing.")
            continue
        for number, line in enumerate(io.StringIO(text, newline=None), 1):
            if number > r.limits.entries:
                r.stop("pth_line_limit", original, ".pth line count exceeds limit.")
            value = line.rstrip()
            if not value or value.startswith("#"):
                continue
            if value.startswith(("import ", "import\t")):
                r.add("FAIL", "pth_execution", f"{original}:line{number}", "CPython site treats this exact import-space/tab prefix as an executable startup line; text is never executed here.")
                continue
            if value == ".":
                continue
            if not path_ok(value, r, f"{original}:line{number}"):
                continue
            if not any(p.startswith(value + "/") for p in installed):
                r.add("OPEN", "pth_external_path", f"{original}:line{number}", "Path addition is not an archive-contained installed directory; target state is unknown.")
                continue
            roots.add(value)
            if len(roots) > r.limits.pth_roots:
                r.stop("pth_root_limit", original, "Too many .pth import roots.")
    for root in sorted(roots):
        namespaces(installed, root, allowed_common, r)
    r.result["counts"]["installation_files"] = len(destinations)
    r.result["counts"]["pth_import_roots"] = len(roots) - 1


def review_wheel(path: str | os.PathLike, *, limits: Limits | None = None, allow_common_names=()) -> dict:
    limits = limits or Limits()
    limits.validate()
    allowed_common = frozenset(allow_common_names)
    if len(allowed_common) > 100 or any(type(n) is not str or len(n) > 128 or not n.isidentifier() for n in allowed_common):
        raise ValueError("allow_common_names requires at most 100 short identifiers")
    path = Path(path)
    r = Review(path.name, limits)
    r.result["allowed_common_names"] = sorted(allowed_common)
    try:
        if len(path.name) > 512:
            r.stop("filename_limit", "input", "Wheel filename is too long.")
        tag_components = path.name[:-4].rsplit("-", 3)[-3:]
        if len(tag_components) == 3 and (tag_components[0].count(".") + 1) * (tag_components[1].count(".") + 1) * (tag_components[2].count(".") + 1) > 500:
            r.stop("tag_limit", "input", "Filename expands to too many compatibility tags.")
        try:
            distribution, version, build, tags = parse_wheel_filename(path.name)
        except (InvalidWheelFilename, InvalidVersion):
            r.stop("wheel_filename", "input", "Filename is not a supported wheel filename.")
        if len(tags) > 500:
            r.stop("tag_limit", "input", "Filename expands to too many compatibility tags.")
        data = snapshot(path, r)
        central = central_preflight(data, r)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            r.result["counts"]["central_entries"] = len(infos)
            local_ranges(data, infos, central, r)
            files, roots, seen, canonical_paths = {}, set(), set(), {}
            for info in infos:
                name = info.orig_filename
                if name != info.filename:
                    r.add("FAIL", "nul_member", name, "ZIP filename contains a NUL and was truncated by the ZIP decoder.")
                if not path_ok(name, r, name, info.is_dir()):
                    continue
                roots.add(name.split("/")[0])
                if name in seen:
                    r.add("FAIL", "zip_duplicate", name, "Duplicate central-directory member.")
                seen.add(name)
                canonical = key(name.rstrip("/"))
                if canonical in canonical_paths and canonical_paths[canonical] != name:
                    r.add("FAIL", "portable_collision", name, "Case-folding or Unicode normalization yields a colliding archive path.")
                canonical_paths[canonical] = name
                kind = stat.S_IFMT(info.external_attr >> 16)
                if kind not in {0, stat.S_IFREG, stat.S_IFDIR} or (kind == stat.S_IFDIR and not info.is_dir()) or (kind == stat.S_IFREG and info.is_dir()):
                    r.add("FAIL", "member_type", name, "Symlink, special file or conflicting directory mode is forbidden.")
                if not info.is_dir():
                    files[name] = info
                elif info.file_size:
                    r.add("FAIL", "directory_payload", name, "Directory member has a payload.")
            for name in files:
                parts = key(name).split("/")
                for i in range(1, len(parts)):
                    parent = canonical_paths.get("/".join(parts[:i]))
                    if parent is not None and not parent.endswith("/"):
                        r.add("FAIL", "archive_prefix_collision", name, "A central-directory file occupies a parent directory.")
            dists = sorted(root for root in roots if root.endswith(".dist-info"))
            if len(dists) != 1:
                r.add("FAIL", "dist_info_count", "ZIP/central", "Wheel requires exactly one top-level .dist-info directory.")
                r.stop("metadata_unresolved", "ZIP/central", "Unique metadata root is unavailable; later checks cannot complete.")
            dist = dists[0]
            identity(dist, ".dist-info", distribution, version, r)
            data_roots = sorted(root for root in roots if root.endswith(".data"))
            if len(data_roots) > 1:
                r.add("FAIL", "data_count", "ZIP/central", "Multiple .data roots.")
            for root in data_roots:
                identity(root, ".data", distribution, version, r)
            for info in infos:
                if info.is_dir() and info.filename.split("/")[0].endswith(".data"):
                    parts = info.filename.rstrip("/").split("/")
                    if len(parts) > 1 and parts[1] not in SCHEMES:
                        r.add("FAIL", "data_layout", info.filename, "Explicit .data directory uses an unknown installation scheme.")
                    if len(parts) > 2 and parts[1] == "scripts":
                        r.add("FAIL", "script_layout", info.filename, ".data/scripts must not contain subdirectories.")
            texts = read_members(zf, infos, r)
            check_metadata(texts, files, dist, distribution, version, tags, build, r)
            if f"{dist}/RECORD" in texts:
                check_record(texts[f"{dist}/RECORD"], files, dist, r)
            check_installation(files, texts, dist, allowed_common, r)
    except StopReview:
        pass
    except (OSError, zipfile.BadZipFile, UnicodeError, ValueError, RuntimeError, EOFError, zlib.error, NotImplementedError) as exc:
        try:
            r.add("OPEN", "input_error", "input/ZIP", f"Review stopped on {type(exc).__name__}; remaining checks were not completed.")
        except StopReview:
            pass
    return r.finish()
