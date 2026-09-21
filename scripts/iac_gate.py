"""Exit 0: pass; 1: a CRITICAL/HIGH misconfiguration exists in a gated target; 2: invalid/incomplete scan.

Only files that ship to production are gated. Lab fixtures (k8s/insecure, the
probe manifests rendered for Task 2, the CI toolbox Dockerfiles) are scanned and
reported for reference but never block, the same way Task 2 treats its insecure
namespace as a documented comparison rather than something to remediate.
"""
import argparse
import json
from pathlib import Path
try:
    from .scan_policy import require, text, SEVERITIES, apply_exceptions
except ImportError:
    from scan_policy import require, text, SEVERITIES, apply_exceptions

GATED_TARGETS = {"Dockerfile", "k8s/cluster.yml", "k8s/hardened/app.yml", "k8s/hardened/network-policy.yml"}
BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}


def evaluate(report):
    if not isinstance(report, dict) or not isinstance(report.get("Results"), list):
        raise ValueError("report must contain a Results array")
    require(report.get("SchemaVersion") == 2, "unsupported Trivy schema")
    seen = set()
    blocking, reference = [], []
    for result in report["Results"]:
        if not isinstance(result, dict) or not isinstance(result.get("Target"), str):
            raise ValueError("malformed result entry")
        target = result["Target"].replace("\\", "/")
        if target.startswith("/workspace/"):
            target = target[len("/workspace/"):]
        while target.startswith("./"):
            target = target[2:]
        require(".." not in target.split("/"), "ambiguous target path")
        seen.add(target)
        gated = target in GATED_TARGETS
        require(result.get("Class") == "config" and isinstance(result.get("MisconfSummary"), dict), "missing config scan summary")
        require(result.get("Misconfigurations") is None or isinstance(result["Misconfigurations"], list), "invalid findings")
        for finding in result.get("Misconfigurations") or []:
            if not isinstance(finding, dict) or not isinstance(finding.get("Severity"), str):
                raise ValueError("malformed misconfiguration entry")
            require(finding.get("Severity") in SEVERITIES and finding.get("Status") in {"FAIL", "PASS", "EXCEPTION"} and text(finding.get("ID")), "invalid finding")
            entry = {"target": result["Target"], "id": finding.get("ID"), "severity": finding["Severity"], "status": finding.get("Status"), "title": finding.get("Title")}
            if entry["status"] != "FAIL":
                continue
            if gated and entry["severity"] in BLOCKING_SEVERITIES:
                blocking.append(entry)
            else:
                reference.append(entry)
    require(GATED_TARGETS <= seen, "missing required IaC targets: " + str(sorted(GATED_TARGETS - seen)))
    return (1 if blocking else 0), blocking, reference


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--exceptions", type=Path, default=Path("security/exceptions.json"))
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        code, blocking, reference = evaluate(report)
        apply_exceptions("iac", [], args.exceptions)  # Validate policy; IaC findings are not waived.
        code = 1 if blocking else 0
    except (OSError, ValueError) as error:
        print(f"BLOCK: {error}")
        return 2
    for entry in blocking:
        print(f"BLOCK-CANDIDATE: {entry['severity']} {entry['id']} - {entry['title']} [{entry['target']}]")
    print(f"Reference findings outside the gated scope: {len(reference)} (not evaluated for pass/fail)")
    print(f"{'BLOCK' if code else 'PASS'}: {len(blocking)} in gated scope {sorted(GATED_TARGETS)}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
