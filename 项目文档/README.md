> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# WheelNamespaceReview


New implementation author: **dhtfish98**. Current project version: **0.1.4**.

A small defensive tool for reviewing an existing Python wheel before it enters
an installation pipeline. It reads bytes, compares the actual ZIP inventory with
RECORD, maps installation paths and identifies namespace/startup policy risks.
It never installs, imports, extracts or executes the input package.

The implementation is independent and automated. Its semantic reference is
[check-wheel-contents](https://github.com/jwodder/check-wheel-contents) at
`4f490a11a156ad4215fb87458aa942daefd3fb2e`. This is a narrower new project,
with different architecture and checks; it does not claim full upstream
compatibility or applicant authorship of upstream work. See [ORIGIN](<ORIGIN.md>).

## Use

Requires Python 3.11 or newer and `packaging>=24.2,<27`.

```sh
python -m pip install .
wheel-namespace-review /path/to/sample_pkg-1.0-py3-none-any.whl
wheel-namespace-review --allow-common-name tests /path/to/wheel.whl
python -m wheel_namespace_review /path/to/wheel.whl
```

The command emits one JSON report. Exit `0` means PASS for the declared checks,
`1` means a demonstrated policy failure, and `2` means unresolved/unsupported
input. FAIL takes precedence when the same report also has OPEN findings.
`complete: false` preserves incomplete observations even in a FAIL report.
`failure_count` counts observed failures even when report details are omitted.
A findings cap retains the failure that triggers the cap and a separate OPEN
marker; `findings_truncated: true` makes omitted detail explicit.
An invalid CLI option exits `2` through argparse and prints a usage error.

The report includes input SHA-256, interpreter-specific standard-library policy,
real member/RECORD counts, namespace evidence, fixed resource limits, and finding
locations such as `sample_pkg-1.0.dist-info/RECORD:row3` or `entry.pth:line2`.
The input remains unchanged. Reports go to stdout; file writing requires the
caller's explicit shell redirection.

## Implemented checks

- Count actual central records before allocating ZIP entries. Check local headers,
  data descriptors and contiguous non-overlapping member ranges. Expand stored/
  deflated bytes with a bounded independent decoder and verify ZIP CRC and sizes.
- Compare central files with strict UTF-8 CSV RECORD: omissions, ghosts, duplicate
  rows, declared sizes, mandatory self-entry and canonical hash field syntax.
- Require one `.dist-info` root, WHEEL/METADATA/RECORD, matching filename identity,
  supported metadata version and singleton required headers, filename/WHEEL tags
  and Build agreement. Header parsing uses the standard email parser without MIME
  body recursion; filename/version/tag parsing uses `packaging`.
- Reject traversal, ambiguous portable paths, links/special entries, file-parent
  conflicts, duplicate members, case/NFC collisions, and `.data` installation
  collisions. Purelib and platlib are conservatively treated as one site-packages
  destination. Map scripts/data/headers separately.
- Reject Windows-reserved filename punctuation, ASCII controls, trailing dots/
  spaces and reserved device components, including COM/LPT superscript 1–3
  aliases. This applies to data files and directories as well as Python source.
  The portable policy follows [Microsoft filename rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file);
  it does not claim to simulate every installer or Windows filesystem.
- Identify Python source module/package/implicit namespace structures. Flag
  standard-library/startup-name overlaps, generic names requiring ownership
  decisions, module/package conflicts, bytecode and native-extension uncertainty.
- Inspect root site-packages `.pth` lines as text using the CPython admission rule.
  Reject executable startup prefixes and unsafe path additions; unknown external
  paths remain OPEN. Archive-contained path additions receive a second namespace
  review, so `vendor/json.py` exposed by `vendor` is detected.

Legal implicit namespace packages without `__init__.py` and data-only wheels can
PASS. Nested package data `.pth` files are not site-startup configuration and are
not treated as startup execution. `--allow-common-name` accepts a generic import
ownership decision; it cannot waive standard-library overlaps.

## Scope and limits

PASS means no finding within this tool's explicit checks. It does not establish
package safety, signature authenticity, correct business behavior or installability.
RECORD payload digest verification is deliberately excluded: the JSON always
states `record_content_hashes_verified: false`. CRC is corruption evidence only.
For cryptographic digest verification use an independent artifact verifier.

ZIP64, multi-disk archives, encryption, unsupported ZIP flags/compression,
unknown metadata versions, non-UTF-8 `.pth`, native contents and nested archives
produce OPEN. Supported WHEEL version is 1.0; supported METADATA versions are
1.1, 1.2 and 2.1 through 2.4. This is a required-header/identity review, not a
complete validator of every Core Metadata field, license declaration or SBOM.
Metadata body content and package source behavior are outside scope.

Defaults: 32 MiB input, 4 MiB central directory, 4,000 entries/RECORD rows/`.pth`
lines per file, 16 MiB per member, 128 MiB total expansion, 1 MiB saved text,
100:1 expansion ratio, 24 path components, 1,024 path characters, 200 findings,
128 `.pth` roots, 512 namespace records and 256 KiB JSON. Archive recursion is
zero. Limits can only be tightened through the Python `Limits` API; they cannot
be increased. Findings/report truncation is explicit OPEN, never a clean result.

Potential overlap with `sys.stdlib_module_names` is a conservative policy finding,
not proof that an installed package can override built-in/frozen modules. The
report identifies the interpreter version and platform used for this policy.
Portable case/NFC and shared purelib/platlib policies may reject layouts accepted
by a specific case-sensitive installer. Symlink rejection uses `O_NOFOLLOW` where
available; only regular input files are accepted.

## Verification and provenance

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python -m build
```

[VALIDATION](<VALIDATION.md>) records actual local results and limitations.
[DEFENSIVE_SCOPE](<DEFENSIVE_SCOPE.md>) describes authorized use and attribution.
The fixed upstream is a design reference only; no original source or fixtures are packaged.
The new implementation's MIT license, provenance/scope documents and runtime source are packaged.

Specifications consulted: [PyPA wheel format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/)
and [CPython site configuration](https://docs.python.org/3/library/site.html).

Local-file capability boundary: required OS flags must be exact positive integers. This wheel reader checks the explicit leaf with POSIX no-follow/nonblocking flags; it does not promise symlink-free parent ancestry. Missing, null, zero, boolean or otherwise invalid required capabilities return a controlled OPEN result before file access. Native Windows local-file reading is outside this POSIX profile.
