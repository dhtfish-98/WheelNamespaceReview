# Validation record

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
