# Validation

## GitHub Actions

See [CI runs](ci-evidence.md) for commit hashes and links.

- Docker image built on the GitHub runner.
- 24 API and gate tests passed.
- Semgrep ran 155 rules on the clean source: zero findings, gate PASS.
- Deploy mock loaded the approved image and checked /health and /api/greeting over HTTP.
- Deployment response files and container logs uploaded as deploy-results.
- Demo branch produced one ERROR: gate exit 1, Deploy mock skipped.
- The intentional eval fixture is isolated to the demo branch.

## Local checks

- Docker build and Compose configuration checked.
- API responses and non-root UID 10001 checked in a running container.
- Gate tested with missing/malformed reports, scanner errors, unknown severities and empty scan scope.
- ERROR and WARNING behavior also checked with real Semgrep scans using temporary source fixtures.
- Workflow YAML and job dependency chain checked before pushing.

## Scope

Build, Test, Security and Deploy mock are implemented. The pipeline generates JSON and
uses a separate parser for its pass/fail decision. PDF analysis is pending.
Kubernetes, dependency/container/IaC scanning and persistent deployment are outside Task 1.
Registry rules and transitive dependencies are not fully locked. Branch protection is not configured.
