# Defensive use and boundaries

Use this tool to review wheels that you own or are authorized to assess before
installation, distribution or internal acceptance. The tool has no target network,
credential access, remote scanning, payload delivery or package execution path.
Input contents remain bytes/text. Generated negative fixtures are inert records
and source text; they are never installed or executed.

The useful output is evidence for a release reviewer: unexpected installed paths,
RECORD omissions/ghosts, ambiguous archive layouts, standard-library name overlap,
and `.pth` interpreter-startup entry points. Reviewers can fix their packaging
configuration or reject the artifact without running it.

PASS/FAIL/OPEN are bounded policy observations. Unknown or partial inputs remain
OPEN; demonstrated failures can coexist with incomplete observations. PASS does
not prove code harmlessness, provenance, signature authenticity, digest correctness,
runtime compatibility or behavior on an unobserved device. Source names alone
do not establish that a package is malicious or that actual shadowing will occur.

This project fits a lawful defensive supply-chain review use case. CVP eligibility
and approval also require truthful applicant identity/organization, attributable
work, actual use and any safeguards impact evidence. Neither the upstream project
nor an AI-assisted local rewrite establishes those requirements on its own.
No application approval, production incident or real-world safeguards limitation
has been observed in this implementation task.
