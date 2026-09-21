# Task 3 — SCA, container image, and IaC scanning

Three of the three optional areas are covered, not the required minimum of two:
[pip-audit](https://pypi.org/project/pip-audit/) for dependency scanning (SCA),
[Trivy](https://aquasecurity.github.io/trivy/) for the built container image, and
Trivy's config scanner for IaC — reusing the Task 1 image and the Task 2 manifests,
as the case study explicitly allows.

## Run

Requirements: the same Docker Engine with Linux containers and Compose v2 used by
Tasks 1 and 2. Task 3 scans the image Task 1 approved, so run Task 1 first if that
record is stale or missing (a build with a different image ID makes the container
scan fall back to `appsec-demo:local` rather than silently trusting old evidence).

```bash
bash scripts/demo.sh
bash scripts/demo_task3.sh
```

Trivy runs as the pinned upstream image `aquasec/trivy@sha256:62b1e65...` (see
`docker-compose.security.yml`), not a custom build, since Aqua already publishes
one. pip-audit needed its own image (`Dockerfile.sca`): pinning it alongside
Semgrep in `Dockerfile.checks` failed to resolve — `semgrep==1.136.0` requires
`tomli~=2.0.1`, `pip-audit==2.10.1` requires `tomli>=2.2.1` — so SCA gets a
separate, smaller toolbox instead of loosening either pin.

## Why these tools, and why three

Semgrep (Task 1) only sees code the team wrote. It cannot see a vulnerable pinned
package, a vulnerable OS package baked into the base image, or a Kubernetes
manifest that grants more than it should — three different origins the case study
asks to be told apart. pip-audit resolves the actual dependency tree from
`requirements.txt` against the PyPA advisory database. Trivy covers both remaining
gaps with one binary: `trivy image` for the built artifact (OS packages and
installed Python packages together) and `trivy config` for Dockerfile and
Kubernetes manifests, which doubles as a second, independent check on the Task 2
hardening claims.

## Scan order and gate policy

Build, Test and SAST run first. Task 3 scans the approved image, and Deploy mock
waits for Task 3; Kubernetes follows deployment. Local demo uses the same order.
A changed/missing local approval or mismatched scanned image blocks the demo.

See [exception policy](security-exceptions.md) for exact decisions and PR review.
Empty scan scopes, missing required IaC targets and malformed reports block.
All pip-audit advisories require disposition. Container findings block if fixable
or HIGH/CRITICAL/UNKNOWN. IaC HIGH/CRITICAL findings in required targets block.
No exceptions are accepted by default. Historical reports contain 44 HIGH and
2 UNKNOWN OS findings; these now block, rather than silently passing without fixes.

## Findings and remediation

| Area | Before | After | Fix |
| --- | --- | --- | --- |
| Container, Python packages | 7 findings (1 Flask, 6 pip) | 0 | Multi-stage `Dockerfile`; final stage never installs pip, and the base image's own pip/setuptools are removed |
| Container, OS packages (Debian 13 "trixie") | 152 findings, 44 HIGH, none with a published fix | Unchanged | Blocked under current policy; requires risk assessment |
| SCA (`requirements.txt`) | 1 actionable (Flask) | 0 | Same Flask bump |
| IaC, `Dockerfile` | 0 | 0 | Already clean |
| IaC, `k8s/hardened/*` | 0 | 0 | Already clean — Trivy independently confirms the Task 2 hardening |
| IaC, `k8s/insecure/app.yml` (reference only, not gated) | 19 findings, 2 CRITICAL, 3 HIGH | Unchanged (fixture, not remediated) | Task 2's hardened manifest already addresses each one |

### Root cause: the Flask dependency finding

`CVE-2026-27205` (`PYSEC-2026-2151`): Flask omits `Vary: Cookie` on some code paths
that only read session keys, so a caching proxy in front of the app could serve one
user's cached response to another. Root cause is a stale pin, not application code.
Fix: `Flask==3.1.2` to `Flask==3.1.3` in `requirements.txt`. Verified by both
pip-audit and Trivy showing zero Flask findings after the bump.

### Root cause: pip shipping in the runtime image

Six of the seven container findings were `pip` itself, not the application.
`python:3.12-slim` installs pip so `pip install` works during the build, but the
running Flask process never imports or executes it. Root cause is a single-stage
Dockerfile that copies the entire base install, build tooling included, into the
image that ships. Fix: build dependencies into `/build/deps` in a `builder` stage,
copy only that directory into the final stage, and remove the base image's own
`pip`/`setuptools` from the final stage explicitly — this removes the CVE surface
outright rather than chasing each patch version. `run.py` calls `waitress.serve()` directly because dependencies are installed into a target directory; the generated console script is not on the runtime PATH.

### Code vs. dependency vs. misconfiguration vs. base image

The case study asks these to be told apart, and the four categories map onto four
different fixes:

- **Code** (Task 1, Semgrep): a flaw in logic the team wrote — `eval`, `shell=True`,
  `debug=True`. Fixed in `app/` or `scripts/`.
- **Dependency** (pip-audit, and Trivy's `lang-pkgs` results): a known CVE in a
  pinned third-party package. Fixed in `requirements.txt`.
- **Base image** (Trivy's `os-pkgs` results): a known CVE in an OS package that
  arrived with `FROM python:3.12-slim`, not through anything the project pinned.
  Fixed by changing the base image tag or waiting for the distro to publish a
  patched package — not by editing application code or `requirements.txt`.
- **Misconfiguration** (Trivy `config`): the code and dependencies could be
  flawless and the deployment would still be wrong — a root container, a wildcard
  RBAC role. Fixed in the manifest, not the application.

The 152 unfixed OS-package findings sit in the base-image category: real, but nothing
in this repository put them there, and nothing in this repository can patch them
directly.

## Demo: reproducing a BLOCK

```bash
git switch codex/demo-dependency-block
bash scripts/demo.sh
bash scripts/demo_task3.sh; echo $?
git switch main
```

The fixture branch reverts `Flask==3.1.2` in `requirements.txt` only — the exact
version this task found and fixed on `main`. `sca_gate.py` and `container_gate.py`
both fail closed with exit 1 (`git status` before switching back if uncommitted
changes to `reports/` exist). It must never be merged.

## Evidence

Each area follows the same `evidence/` (committed) vs. `last-run/` (gitignored,
regenerated by `demo_task3.sh` and CI) split Task 2 already uses for
`reports/k8s/`. `reports/sca/evidence/local-2026-09-21/pip-audit-before.json` and
`reports/container/evidence/local-2026-09-21/trivy-image-before.json` are real
pip-audit and Trivy output from a clean worktree checked out at the pre-Task-3
commit (`273cfb8`); the `-after.json` files are the same tools against the current
tree, after the Flask/Dockerfile fix — neither is synthesized.
`reports/iac/evidence/local-2026-09-21/trivy-config.json` covers the whole
repository in one run; `iac_gate.py`'s scope filter, not a second scan, is what
separates the gated result from the `k8s/insecure` and toolbox-image reference
findings.

## Limitations

Historical PASS decisions used a weaker policy and are not current approvals.
An unavailable patch is not sufficient risk acceptance: assess package use,
exploit prerequisites, alternate base images, package removal and isolation.
A PR-reviewed exception must be specific and expire. No production approver or
branch protection is claimed by this single-maintainer lab.

The local script stops on its first failed gate. CI preserves IaC evidence even
if container scanning fails. Reports are time-specific; advisory databases change.
