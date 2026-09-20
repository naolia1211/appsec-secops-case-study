# Local validation — 2026-09-20

- Python 3.12: 24 pytest tests passed (API behavior, gate policy, malformed/missing reports).
- Docker Compose config validated and `docker build -t concung-demo:local .` succeeded.
- Built container: HTTP /health and greeting verified; runtime UID 10001 verified.
- Semgrep 1.136.0: 4 local rules scanned 4 source files; actual JSON report produced; clean gate PASS.
- Temporary eval fixture: actual Semgrep ERROR finding, gate exit 1 confirmed.
- Temporary MD5 fixture: actual WARNING finding, gate exit 0 confirmed.
- Temporary fixture removed and clean scan rerun. Demo JSON remains locally in reports/sast/.
- Workflow YAML parsed and Build → Test → Security dependencies checked.
- GitHub-hosted Actions verified: Build, Test and Security PASS on main; intentional demo blocked at Security. See ci-evidence.md for run links.
- Requirements pin direct dependencies; transitive packages and base image tag are not fully locked.
- Four local rules plus the Semgrep p/python registry ruleset provide demonstration coverage, not comprehensive security assurance.
- PDF, Kubernetes and container/IaC scanning are deferred.

## Expanded SAST coverage

- Added Semgrep Registry p/python alongside local rules: 155 rules scanned 4 source files, zero findings, gate PASS.
- Removed unnecessary CLI-controlled scan targets/report path; scanner now uses fixed project paths.
- Re-ran pytest: 24 passed.
- Added GitHub Actions summary table and evidence guide.
- User approved publication; main and codex/demo-sast-block have been pushed and both hosted outcomes verified.
