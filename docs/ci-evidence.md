# CI runs

Verified on 2026-09-20.

| Case | Commit | Run |
| --- | --- | --- |
| Clean main | `a20608cd4c79d5e09ecccd6edc688748e7853135` | [35487648462](https://github.com/naolia1211/appsec-secops-case-study/actions/runs/35487648462) |
| Intentional SAST failure | `0f9b4eb10c927671d9bc963176bdbc7293c5f987` | [35487650775](https://github.com/naolia1211/appsec-secops-case-study/actions/runs/35487650775) |

| Job | Main | Demo branch |
| --- | --- | --- |
| Build | Success | Success |
| Test | Success | Success |
| Security | Success | Failed: one ERROR, gate exit 1 |
| Deploy mock | Success | Skipped |

Open a run and select a job to inspect its logs. Artifacts appear on the run summary.

- `sast-report`: actual Semgrep JSON, including on a blocked run.
- `approved-image-<SHA>`: the image released by Security on PASS.
- `deploy-results`: health response, greeting response and container logs from Deploy mock.
- `built-image`: intermediate image passed between jobs; it is not a release approval.

The demo branch adds `app/demo_block.py`, an uncalled function containing eval.
Semgrep detects it; no JSON findings are fabricated. That branch must not be merged.

Deploy mock runs on an ephemeral GitHub runner. It loads the approved image without
rebuilding, checks both response status and JSON contents, and removes the container.
No application remains hosted after the job finishes.

The initial smoke test hit a startup race. Bounded HTTP retries fixed it; the check
now belongs to Deploy mock, after Security.

Download SAST/deployment artifacts within 30 days, and the approved image within 7 days.
Documentation-only commits after these runs do not change the verified application or workflow.
