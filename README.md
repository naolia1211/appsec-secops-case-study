# AppSec / SecOps Case Study

[![CI](https://github.com/naolia1211/appsec-secops-case-study/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/naolia1211/appsec-secops-case-study/actions/workflows/ci.yml?query=branch%3Amain)

A Flask API demonstrating a security-gated delivery pipeline with GitHub Actions,
Docker, pytest and Semgrep. The same image moves from build to mock deployment;
a blocking SAST finding prevents deployment.

```text
Build image → Unit tests → SAST + policy gate → Deploy mock
```

## Quick start

Requires Docker with Linux container support. Run from the repository root:

```bash
docker compose up --build -d
curl --fail http://localhost:18080/health
# {"status":"ok"}
```

The API listens on host port `18080`, mapped to container port `8080`.
Stop it with `docker compose down`.

| Endpoint | Response |
| --- | --- |
| `/` | Service name and version |
| `/health` | `{"status":"ok"}` |
| `/api/greeting?name=Linh` | `{"message":"Hello, Linh!"}` |

## Development

Requires Python 3.12. The commands below use Git Bash on Windows:

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -r requirements-dev.txt -r requirements-security.txt
python -m pytest -q
python scripts/run_sast.py
```

On Linux, activate with `source .venv/bin/activate`. In PowerShell, use
`.\.venv\Scripts\Activate.ps1`; use `curl.exe` for the HTTP example above.

## Pipeline

The [workflow](.github/workflows/ci.yml) runs on pushes, pull requests and manual dispatch.
Each job requires the previous job to succeed.

| Job | Check or output |
| --- | --- |
| Build | Build `concung-demo:<commit SHA>` and upload the image archive |
| Test | Run API and security-gate unit tests |
| Security | Scan Python source, evaluate JSON, publish the approved image artifact |
| Deploy mock | Load the approved image, start a container, verify HTTP responses and collect logs |

Deploy mock verifies `/health` and `/api/greeting`, including their JSON contents.
Readiness checks have bounded retries, and the container is removed after the check.
This is an ephemeral deployment on the CI runner, not a persistent public service.

## Security gate

[`scripts/run_sast.py`](scripts/run_sast.py) scans `app/` and `scripts/` with
the local [rules](.semgrep.yml) and Semgrep's `p/python` ruleset. The local rules
cover dynamic evaluation, shell execution, debug mode and weak hashes.

[`scripts/security_gate.py`](scripts/security_gate.py) parses
`reports/sast/semgrep.json` and applies this policy:

| Condition | Decision | Exit code |
| --- | --- | --- |
| One or more ERROR findings | Block | 1 |
| WARNING / INFO only, or no findings | Pass; retain findings in report | 0 |
| Invalid report, scan errors, unknown severity or no scanned files | Block | 2 |

The scanner runs without `--error` so finding policy stays in the gate. The wrapper
also blocks on a scanner process failure and removes any old report before scanning.
Severity is supplied by the rule; it is not a CVSS score.

## Verified runs

| Case | Expected result | GitHub Actions |
| --- | --- | --- |
| Clean source | All four jobs pass | [PASS run](https://github.com/naolia1211/appsec-secops-case-study/actions/runs/35487648462) |
| Intentional eval fixture | Security fails; Deploy mock is skipped | [BLOCK run](https://github.com/naolia1211/appsec-secops-case-study/actions/runs/35487650775) |

The fixture exists only on the demo branch and must not be merged. Both reports
come from actual scans. See [CI evidence](docs/ci-evidence.md) for commit hashes
and [validation](docs/validation.md) for checks performed.

| Artifact | Retention |
| --- | --- |
| `built-image` — intermediate image | 1 day |
| `sast-report` — Semgrep JSON, also uploaded on gate failure | 30 days |
| `approved-image-<SHA>` — image released after gate PASS | 7 days |
| `deploy-results` — HTTP responses and container logs | 30 days |

## Scope and limitations

Task 1 implements Build, Test, Security and Deploy mock. Kubernetes and container/IaC
scanning are reserved for Tasks 2 and 3; `k8s/` currently contains placeholders.

- SAST covers the selected source files and rules, not dependency or container vulnerabilities.
- Registry rules require network access and may change; transitive dependencies and the base image tag are not fully locked.
- Branch protection is not configured. A failed gate stops deployment but does not itself prevent merging.
