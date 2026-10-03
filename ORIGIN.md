# Origin and attributable contribution

Semantic reference: John Thorvald Wodder II and contributors,
[`jwodder/check-wheel-contents`](https://github.com/jwodder/check-wheel-contents),
fixed commit `4f490a11a156ad4215fb87458aa942daefd3fb2e` (MIT).
The frozen archive SHA-256 recorded during source collection is
`31b61504cac44ae1b5a1a60468d76a5fd39101d74f3438b057443d5079ee72bf`.
The archive digest is source-collection provenance, not a signature or authorship
proof. The full copyright/permission/disclaimer notice is retained verbatim in
`licenses/check-wheel-contents-MIT.txt`.

Upstream runtime review covered all nine source files: `__init__.py`,
`__main__.py`, `checker.py`, `checks.py`, `config.py`, `contents.py`, `errors.py`,
`filetree.py`, `util.py`; upstream package/CI review covered `pyproject.toml`,
`tox.ini`, `.github/workflows/test.yml`, and `LICENSE`. Test inspection covered
`test/test_wheelcontents.py:1-110` only. Other upstream tests, binary fixtures,
dependencies, README details and renovation config were not fully audited or run.
Therefore this is a complete review of the frozen upstream's own runtime files,
not a claim of full upstream repository/dependency audit. Exact inspected-file
hashes and notes are in `evidence/upstream-review.json`.

Upstream builds its principal tree from RECORD rows and checks wheel contents,
expected local source trees, bytecode, generic names and duplicate signatures.
It optionally walks local trees/configuration parents and recursively discovers
wheel filenames; top-level `.pth` is excluded from several content checks.

This implementation was newly written under repository-owner direction. It does not
copy, rename, vendor or invoke upstream runtime code. Its architecture starts
with an immutable bounded snapshot and an independently counted ZIP directory,
cross-checks real files against RECORD, spreads installation paths, and evaluates
namespace and site startup policy. Raw expansion verifies CRC and detects false
declared uncompressed sizes. It interprets `.pth` path additions rather than
simply searching arbitrary Python source text. It uses the Python standard
library and the separate mature `packaging` library for version/name/tag grammar.

Deliberately excluded upstream behavior: config discovery, local source-tree
comparison, directory recursion, complete W00x/W10x/W20x compatibility, signature
duplicate-content rules, and upstream formatting. Added checks do not constitute
a complete rewrite of all upstream behavior. The new project is fully implemented
within its declared defensive scope.

The applicant may truthfully identify this new implementation,
review, tests and subsequent independently attributable maintenance, once they
have verified it. They must not claim original authorship of upstream software,
independent human authorship of generated output, or CVP approval based on this repository.

New implementation author: dhtfish98. This attribution applies to the new project implementation; original sources, licenses and third-party notices retain their authors. Automated checks do not establish independent human review or CVP eligibility.
