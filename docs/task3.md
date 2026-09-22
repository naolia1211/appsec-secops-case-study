# Task 3 — SCA, Container and IaC Security

Task 3 covers all three optional security areas in the case study:

- **SCA:** `pip-audit` for Python dependencies.
- **Container scanning:** Trivy for the approved application image.
- **IaC scanning:** Trivy config scanning for the Dockerfile and Kubernetes manifests.

The scans reuse the application artifact and deployment configuration from
Tasks 1 and 2.

## Run

Requires Docker Engine with Linux container support and Docker Compose v2.

The full local pipeline already includes Task 3:

```bash
bash scripts/demo.sh
```

To rerun only Task 3 after Task 1 has successfully produced an approved image:

```bash
bash scripts/demo_task3.sh
```

Task 3 does not select or rebuild a different application image when approval
is missing. A missing, changed or mismatched approved artifact causes the
corresponding gate to fail.

## Tools

### SCA

`pip-audit` checks the Python dependencies resolved from `requirements.txt`
against the PyPA advisory database.

It runs from the dedicated `Dockerfile.sca` image. SCA is separated from the
Semgrep toolbox because the pinned versions of the two tools require
incompatible `tomli` versions.

### Container scanning

Trivy scans the approved application image for both OS packages and installed
Python packages.

The Trivy image is pinned in `docker-compose.security.yml`.

The container gate also validates image identity. The image represented by the
scan report must match the artifact previously approved by the pipeline.

### IaC scanning

Trivy config scanning checks the Dockerfile and Kubernetes manifests.

This provides an independent static check on the Kubernetes hardening performed
in Task 2.

## Scan order and release policy

The release path is:

```text
Build
  -> Test
  -> SAST
  -> SCA / Container / IaC gates
  -> Deploy Mock
  -> Kubernetes Verification
```

The three Task 3 gates are implemented in:

```text
scripts/sca_gate.py
scripts/container_gate.py
scripts/iac_gate.py
```

The gates use fail-closed behavior for missing, malformed or incomplete
security evidence.

Current policy includes:

- all `pip-audit` advisories require disposition;
- fixable or HIGH/CRITICAL/UNKNOWN container findings block release;
- required IaC targets must be present in the report;
- HIGH/CRITICAL IaC findings in required targets block release;
- no risk exception is accepted by default.

The detailed exception model is documented in
[`security-exceptions.md`](security-exceptions.md).

## Finding 1 — Flask dependency

`pip-audit` identified one actionable application dependency finding:

```text
Flask 3.1.2
PYSEC-2026-2151 / CVE-2026-27205
```

The root cause was the pinned Flask version in `requirements.txt`, not
application logic or the container base image.

Remediation:

```text
Flask 3.1.2 -> Flask 3.1.3
```

After the version update, `pip-audit` no longer reports the Flask finding.

This finding is also visible in the historical Trivy language-package result.

## Finding 2 — Python packages in the runtime image

The historical container scan contained seven Python-package findings:

```text
1 Flask finding
6 pip findings
```

The Flask finding was addressed by the dependency update above.

The other six findings were associated with `pip` shipped in the runtime
image. The running Flask application does not require `pip` or `setuptools`.

The Dockerfile was changed to a multi-stage build. Dependencies are prepared in
the builder stage and only the required runtime content is copied into the
final image. Unnecessary `pip` and `setuptools` packages are removed from the
runtime image.

The subsequent scan contains zero Python-package findings.

## Finding 3 — OS packages in the base image

A later container scan of the Debian-based runtime image reported:

```text
152 OS-package findings
44 HIGH
2 UNKNOWN
```

The findings came from OS packages inherited from the Debian-based Python
runtime image rather than from Flask application code.

Under the current policy, the 44 HIGH and 2 UNKNOWN findings block release.
They were not suppressed and no risk exception was added.

The runtime image was changed to the official Python 3.12 Alpine image and
pinned by digest in both build stages. The scanned runtime OS is Alpine 3.24.2.

After rebuilding and rescanning, the previous Debian OS-package findings are no
longer present. The current evidence set contains zero OS and Python-package
findings.

Changing the base image also required compatibility verification. The
application API, UID 10001 and all 33 Kubernetes runtime checks pass on the
remediated image.

## IaC result

Trivy config scanning is also used against the Dockerfile and Kubernetes
manifests.

Current results:

| Target | Result |
| --- | --- |
| Dockerfile | 0 findings |
| `k8s/hardened/` | 0 findings |
| `k8s/insecure/app.yml` | 19 findings, including 2 CRITICAL and 3 HIGH |

`k8s/insecure/` is an intentional Task 2 baseline and is not the deployment
configuration approved for release. The hardened manifests address the
misconfigurations and are independently checked by Trivy.

## BLOCK and PASS evidence

### Historical BLOCK

GitHub Actions run:

https://github.com/naolia1211/appsec-secops-case-study/actions/runs/35607540442

In this run:

- Build, Test and SAST pass.
- SCA passes.
- IaC passes.
- the container gate blocks the image because 44 HIGH and 2 UNKNOWN OS
  findings exceed the release policy;
- Deploy Mock and Kubernetes Verification do not run.

### Remediated PASS

GitHub Actions run:

https://github.com/naolia1211/appsec-secops-case-study/actions/runs/35608731394

Commit:

```text
b62e3aa1e33a7d2be0b984aeec8ff7e4319ff117
```

In this run:

- SCA passes;
- container scanning passes;
- IaC scanning passes;
- no risk exception is used;
- Deploy Mock continues;
- all 33 Kubernetes runtime checks pass.

Raw CI evidence for the PASS run is stored under:

```text
reports/task3/evidence/ci-35608731394/
```

Historical BLOCK evidence is retained under:

```text
reports/task3/evidence/ci-35607540442/
```

## Reproduce a dependency BLOCK

A separate fixture branch retains the vulnerable Flask version for negative
testing:

```bash
git switch codex/demo-dependency-block
bash scripts/demo.sh; echo $?
git switch main
```

The fixture changes the Flask dependency back to version 3.1.2. The SCA gate
is expected to return a non-zero exit code and prevent the release path from
continuing.

The fixture branch exists only to reproduce the negative test and must not be
merged into `main`.

## Evidence layout

Committed evidence is kept separately from regenerated local output.

Historical pre-remediation evidence includes:

```text
reports/sca/evidence/local-2026-09-21/pip-audit-before.json
reports/container/evidence/local-2026-09-21/trivy-image-before.json
```

These files represent the earlier Task 3 state and are retained as historical
scan evidence.

Current CI evidence should be used to determine the final remediated state,
including the Alpine base-image remediation.

Generated local results are stored under the corresponding `last-run/`
directories and may be regenerated by the demo scripts.

## Limitations

Security scan results are point-in-time evidence. Advisory databases and
scanner rules can change after an image has passed.

A zero-finding result does not guarantee that the image will remain free of
known vulnerabilities. The pinned base image therefore still requires regular
rescanning and controlled updates.

An unavailable vendor patch is not treated automatically as risk acceptance.
Production handling should consider exploitability, package use, compensating
controls, alternate base images and formal exception approval.

This case study does not claim production branch protection or independent
risk approval. Those controls would be required around the release policy in a
production environment.