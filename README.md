# AppSec / SecOps Case Study

[![CI](https://github.com/naolia1211/appsec-secops-case-study/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/naolia1211/appsec-secops-case-study/actions/workflows/ci.yml?query=branch%3Amain)

A Flask API demonstrating a security-gated delivery pipeline with GitHub Actions,
Docker, pytest and Semgrep. The same image moves from build to mock deployment;
a blocking SAST finding prevents deployment.

```text
Build image â†’ Unit tests â†’ SAST + policy gate â†’ Deploy mock
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

## Full local pipeline with Docker

From Git Bash or a Linux shell, run `bash scripts/demo.sh`. Docker Compose v2
builds the application and check images, runs tests and SAST, then starts the
application only if the gate passes. Python is installed inside the check image;
no host Python is required. The initial run downloads packages and registry rules.

The JSON report is written to `reports/sast/semgrep.json`. The local app stays
available on port 18080 until `docker compose down`. GitHub's mock deployment
instead removes its container when the job ends.

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
| Build | Build `appsec-demo:<commit SHA>` and upload the image archive |
| Test | Run API and security-gate unit tests |
| Security | Scan Python source, evaluate JSON, publish the approved image artifact |
| Task 3 | SCA, image and IaC scans; risk policy must pass before deployment |
| Kubernetes | Verify hardening after Deploy mock |
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
| Clean source | Historical Task 1 jobs pass | [PASS run](https://github.com/naolia1211/appsec-secops-case-study/actions/runs/35487648462) |
| Intentional eval fixture | Security fails; Deploy mock is skipped | [BLOCK run](https://github.com/naolia1211/appsec-secops-case-study/actions/runs/35487650775) |

The fixture exists only on the demo branch and must not be merged. Both reports
come from actual scans. See [CI evidence](docs/ci-evidence.md) for commit hashes
and [validation](docs/validation.md) for checks performed.

| Artifact | Retention |
| --- | --- |
| `built-image` â€” intermediate image | 1 day |
| `sast-report` â€” Semgrep JSON, also uploaded on gate failure | 30 days |
| `approved-image-<SHA>` â€” image released after gate PASS | 7 days |
| `deploy-results` â€” HTTP responses and container logs | 30 days |

## Kubernetes hardening

Task 2 uses k3d to run K3s inside Docker. It deploys the approved Task 1 image to
separate insecure and hardened namespaces and verifies runtime controls.

```bash
bash scripts/demo.sh
docker compose -f docker-compose.k8s.yml build lab
docker compose -f docker-compose.k8s.yml run --rm lab all
```

The CI job `Kubernetes hardening` runs after Deploy mock and downloads the same
approved image artifact. See [Task 2](docs/task2.md) for risks, remediation,
NetworkPolicy rollout, evidence and cleanup commands.

## SCA, container, and IaC scanning

Task 3 adds [pip-audit](https://pypi.org/project/pip-audit/) for dependency
scanning and [Trivy](https://aquasecurity.github.io/trivy/) for both the built
image and the Dockerfile/Kubernetes manifests, covering all three optional areas
against the same image Task 1 approves and the same manifests Task 2 hardens.

```bash
bash scripts/demo.sh
bash scripts/demo_task3.sh
```

Each of the three gates (`scripts/sca_gate.py`, `scripts/container_gate.py`,
`scripts/iac_gate.py`) blocks on a different, independently justified condition —
see [Task 3](docs/task3.md) for the policy table, the findings before and after
the fix, and how to reproduce a BLOCK on the `codex/demo-dependency-block` fixture
branch.

## Scope and limitations

Task 1 implements Build, Test, Security and Deploy mock. Task 2 adds local
Kubernetes deployment and hardening. Task 3 adds SCA, container image, and IaC
scanning.

- SAST covers the selected source files and rules, not dependency or container vulnerabilities; those are Task 3's job.
- Registry rules require network access and may change; transitive dependencies and the base image tag are not fully locked.
- Historical image reports contain 44 HIGH and 2 UNKNOWN unfixed OS findings. These block deployment under the current policy until remediated or explicitly excepted.
- Branch protection is not configured. A failed gate stops deployment but does not itself prevent merging.

Task 3 now blocks deployment on fixable or HIGH/CRITICAL/UNKNOWN image findings.
See [exception review](docs/security-exceptions.md). Historical green runs predate
this policy. No risk exceptions are accepted by default.

Current policy verification: [run 35607540442](https://github.com/naolia1211/appsec-secops-case-study/actions/runs/35607540442)
(Build/Test/SAST/SCA pass, image gate blocks 46 findings, IaC passes, deployment and Kubernetes skip).
