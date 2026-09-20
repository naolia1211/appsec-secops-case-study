# AppSec / SecOps case study

A small Flask API with a GitHub Actions pipeline:

```text
Build → Test → Security → Deploy mock
```

The image is built once and passed between jobs as an artifact. Security scans
the Python source with Semgrep and evaluates the JSON report. Deploy mock loads
the approved image, starts it on the runner, checks two HTTP endpoints, and removes
the container. It does not create a persistent hosting environment.

## Local setup

Requires Python 3.12. Docker Desktop must use Linux containers.
From Git Bash on Windows:

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -r requirements-dev.txt -r requirements-security.txt
python -m pytest -q
python scripts/run_sast.py
docker compose up --build -d
curl --fail http://localhost:18080/health
docker compose down
```

On Linux, activate with `source .venv/bin/activate`. In PowerShell use
`.\.venv\Scripts\Activate.ps1` and `curl.exe`.

Endpoints: `/health`, `/api/greeting?name=Linh`, and `/` for service metadata.
The host port is 18080 because port 8080 was already occupied on the development machine.

## Pipeline

| Job | Work |
| --- | --- |
| Build | Build and save `concung-demo:<commit SHA>` |
| Test | Run API and gate unit tests |
| Security | Run Semgrep, parse JSON, publish image only on PASS |
| Deploy mock | Start approved image; check health and greeting; collect logs; stop container |

Each job depends on the previous one. A failed security gate skips Deploy mock.
SAST and deployment evidence are uploaded even if their checks fail.

## Gate policy

`scripts/run_sast.py` scans `app/` and `scripts/` using `.semgrep.yml` and
Semgrep's `p/python` ruleset. The registry rules require network access and may
change over time. The local rules cover dynamic evaluation, shell execution,
debug mode, and weak hashes.

`scripts/security_gate.py` reads `reports/sast/semgrep.json`:

- ERROR: block (exit 1).
- WARNING / INFO: report, but allow if there are no ERROR findings.
- Scanner failure, invalid report, unknown severity, or no scanned files: block (exit 2).

Semgrep runs without `--error`; the separate gate owns the finding policy.
Reports are real scanner output. A clean result only applies to the scanned files
and enabled rules, not dependencies or container contents.

## CI evidence

Run details and artifact names are in [docs/ci-evidence.md](docs/ci-evidence.md).
The `codex/demo-sast-block` branch contains an intentional eval fixture. Do not
merge or deploy that branch. Its pipeline should stop at Security.

SAST and deployment artifacts expire after 30 days; approved images after 7 days.
Branch protection is not configured, so a failing job does not itself prevent a merge.

Kubernetes and container/IaC scanning are reserved for Tasks 2 and 3.
