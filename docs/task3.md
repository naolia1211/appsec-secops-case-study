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

## Where each scan runs, and why

SCA runs first, against `requirements.txt`, before the image is even built — the
earliest point a dependency fix is possible, and the cheapest to fail fast on.
Container and IaC scanning run after Task 1's gate and Task 2's cluster
verification, against the same approved image and the same manifests already
proven to deploy correctly; scanning code that has not passed its own tests or
SAST gate yet would waste a slower scan on an artifact likely to change anyway.

## Block/warn policy per gate

| Gate | Blocks on | Reasoning |
| --- | --- | --- |
| SCA (`sca_gate.py`) | Any dependency vulnerability with a published fix version | A fix that exists and is not applied is a choice, not a limitation; severity ratings are inconsistent across advisory sources, so fixability is the more reliable trigger |
| Container (`container_gate.py`) | Any image vulnerability (OS or Python package) with a fixed version available | Same reasoning, applied to the built artifact; vulnerabilities without a published fix are recorded but cannot be acted on by blocking |
| IaC (`iac_gate.py`) | A CRITICAL or HIGH misconfiguration in a gated target only | Manifest fixes are always actionable immediately, so severity alone is enough; the gated scope excludes `k8s/insecure/*`, the CI toolbox Dockerfiles, and Task 2's rendered probe pods, since those are documented lab fixtures and test harnesses, not what ships |

This blocks on a fixable LOW-severity dependency finding, which a larger dependency
tree might turn into pipeline noise; a severity floor (e.g. only HIGH/CRITICAL with
a fix) is a reasonable tuning knob for that case. It was not added here because our
dependency tree is small enough that it has not caused noise, and the point of the
policy is to keep an unresolved-but-fixable finding visible rather than let it age.
As with Semgrep's severities, none of these are CVSS scores; they are the tool's
own classification, read as-is.

Gated target list (production-facing files only):
`Dockerfile`, `k8s/cluster.yml`, `k8s/hardened/app.yml`, `k8s/hardened/network-policy.yml`.

## Findings and remediation

| Area | Before | After | Fix |
| --- | --- | --- | --- |
| Container, Python packages | 7 findings (1 Flask, 6 pip) | 0 | Multi-stage `Dockerfile`; final stage never installs pip, and the base image's own pip/setuptools are removed |
| Container, OS packages (Debian 13 "trixie") | 152 findings, 44 HIGH, none with a published fix | Unchanged | No action available yet; accepted and monitored (see Limitations) |
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
outright rather than chasing each patch version. `run.py` replaces the
`waitress-serve` console-script entry point (which needs pip's script shims on
`PATH`) with a three-line script that calls `waitress.serve()` directly.

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

pip-audit reports whether a fix exists, not a CVSS score, so the gate above uses
fixability rather than severity. Trivy's built-in misconfiguration scanners cover
Dockerfiles and Kubernetes manifests but not Compose files, so `docker-compose*.yml`
is not scanned. The 152 OS-level findings come from Debian 13 ("trixie"), a very
recent release; most currently lack a published fixed version in Trivy's database,
so blocking on them would create pipeline noise with no remediation path. Task 2's
non-root, read-only-filesystem, no-privileged, and seccomp hardening already narrow
what a compromised OS package could do at runtime, independent of whether or when a
patch lands. Both the Trivy vulnerability database and the PyPA advisory data are
point-in-time snapshots; a clean scan today is not a permanent guarantee, hence a
re-scan on every pipeline run rather than a one-time check.

References: [pip-audit](https://pypi.org/project/pip-audit/),
[Trivy](https://aquasecurity.github.io/trivy/latest/docs/),
[Trivy Kubernetes checks](https://aquasecurity.github.io/trivy/latest/docs/target/kubernetes/).
