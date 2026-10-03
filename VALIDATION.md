# Current delivery validation — 0.1.2

New implementation author and maintainer: dhtfish98. Current source inventory: `SOURCE_REVIEW_MANIFEST.json` (this manifest excludes its own digest). The 2026-10-03 delivery preserves original upstream license and notice bytes; current runtime additionally validates the required OS capability flags and directory-relative support before local file reads.

The existing suite has 61 passing test cases in the current source and in a fresh consumer of this version. Package verification checks version/author, artifact RECORD or archive inventories, runtime bytes against the formal source, and retained third-party licenses. Consumer installation uses local frozen dependencies and does not run target inputs. Detailed current artifact hashes and execution receipts are kept in the separate delivery evidence.

New-commit hosted CI and publication remain pending until the repository owner publishes this version.

These engineering checks do not establish upstream authorship, independent human review, actual safeguards impact or CVP eligibility.

## Historical delivery evidence

The following sections describe the earlier delivery and retain its original versions and checks. They do not validate a later artifact.

# Validation record

## Version 0.1.1, 2026-10-03

All 57 source tests pass on local CPython 3.14.6 / macOS arm64. The new
regressions cover a first failure arriving at tightened and default finding
caps, counters and retained failure evidence after finding/report omission,
Windows-reserved punctuation in data files and directories, ASCII controls,
COM/LPT superscript device names, and safe ordinary Unicode data controls.
Independent real wheel probes preserve input bytes and confirm the corrected
FAIL results alongside normal data PASS controls. The path policy follows
[Microsoft's documented filename rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file);
no Windows runtime or installer execution is claimed.

`SOURCE_REVIEW_MANIFEST.json` binds the current complete formal source set.
The 2026-10-02 `evidence/source-review.json` and `evidence/validation.json`
remain historical version 0.1.0 records; their hashes and test counts do not
validate this revision. Fresh installed consumers, built wheel/sdist contents,
source identity and artifact hashes are recorded in the separate dated
engineering evidence. Checks bind those exact bytes rather than later builds.
Matching hosted CI for this new revision, unobserved platforms, full upstream
compatibility, authenticity and CVP approval remain OPEN.

## Historical version 0.1.0

Local results are recorded for 2026-10-02 (Asia/Tokyo). This record describes the
implemented bounded scope; it does not validate CVP eligibility or approval.

See `evidence/validation.json` for the final test count, interpreter/dependency
versions, independently installed consumer checks and package contents checks.
`evidence/source-review.json` records every new runtime/test/package/CI source
file reviewed and its SHA-256. Distribution hashes are recorded separately in the
engineering handoff, because placing a package's own hash inside that package
would create a circular identity claim.

The suite uses generated valid package/namespace/data-only wheels, true ZIP/RECORD
cross-view failures, malformed CSV/header/filename/ZIP inputs, CRC corruption,
forged sizes, unsafe paths, duplicate/colliding names, installation spreading,
native/bytecode/nested-archive uncertainty and exact `.pth` admission semantics.
It checks read-only input identity, no network/process/extraction calls, no imported
input module and an execution sentinel that must remain absent.

Counterexamples preserve limits: a syntactically valid but wrong RECORD payload
digest can PASS because digest verification is explicitly outside this tool's
scope; non-UTF-8 `.pth` stays OPEN; generic names require a policy decision;
valid implicit namespace and data-only wheels can PASS. The CLI checks 0/1/2
status exits in an independent environment and examines both wheel/sdist license,
source and provenance contents.

The CI workflow runs tests and builds packages on Python 3.11 and 3.14. This
workflow was source-reviewed locally; no GitHub-hosted execution is claimed.
Only the local interpreter/operating system listed in the evidence was actually
executed. No upstream package was run, and no reviewed input package was installed.
