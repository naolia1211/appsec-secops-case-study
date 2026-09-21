# Security exceptions

The default exception list is empty. Findings with fixes block. Container HIGH,
CRITICAL and UNKNOWN findings also block without a fix; pip-audit advisories all
block because that report does not supply severity. Low/medium unfixed container
findings remain visible. IaC HIGH/CRITICAL findings block in required targets.

An exception must match scanner, advisory ID, package and installed version
exactly. Required fields are scope (`lab`), reason, mitigation, owner,
review_reference and expires (ISO date; expires at the start of that date).
Wildcards, duplicates and expired records fail the gate. No approval is fabricated:
this repository starts with no accepted exceptions. A blocked scan is valid evidence.

Request changes to security/exceptions.json through a pull request using the
security-exception template. Review must examine exploit prerequisites, package
use, exposure and compensating controls, and set a short reassessment deadline.
The file records a decision; it cannot authenticate its own approver.

For production, configure branch protection/rulesets, required CI, independent
reviewers, dismissal of stale approvals and protection of workflow/policy changes.
These account-level controls have NOT been configured by this lab. A sole author
cannot demonstrate separation of duties. Deployment approval is separate and
must never bypass scan gates. CODEOWNERS should name a real security reviewer
only after that reviewer has agreed; no placeholder identity is installed.
